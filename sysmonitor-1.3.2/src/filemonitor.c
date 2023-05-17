/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2016-2019. All rights reserved.
 * sysmonitor licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Description: file monitor
 * Author: xuchunmei
 * Create: 2016-1-1
 */
#include "filemonitor.h"

#include <time.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/limits.h>

#include <securec.h>

#define FILE_WATCH_SELECT_TIMEOUT 60
#define FILE_WATCH_MAX_FAIL_NUM 3
#define INOTIFY_IOC_SET_SYSMONITOR_FM 0xABAB
static int g_watched_items;
static struct list_head g_conf_head;
static struct list_head g_event_head;
static bool g_watch_flag = true;
static bool g_save_process = false;
static int g_select_timeout = FILE_WATCH_SELECT_TIMEOUT;

void set_file_monitor_select_timeout(int timeout)
{
    if (timeout <= 0) {
        return;
    }
    g_select_timeout = timeout;
}

static fqueue_entry *find_queue(int wd)
{
    fqueue_entry *entry = NULL;

    list_for_each_entry(entry, &g_conf_head, list) {
        if (entry->wd == wd) {
            return entry;
        }
    }
    return NULL;
}

static fqueue_entry *find_queue_byname(const char *name)
{
    fqueue_entry *entry = NULL;

    list_for_each_entry(entry, &g_conf_head, list) {
        if (!strcmp(entry->file_path, name)) {
            return entry;
        }
    }
    return NULL;
}

static void free_fqueue(void)
{
    fqueue_entry *entry = NULL;
    fqueue_entry *next = NULL;

    list_for_each_entry_safe(entry, next, &g_conf_head, list) {
        list_del(&entry->list);
        free(entry);
    }
}

static bool check_before_add(const char *file_path, const char *tmp_path, const char *real_path)
{
    struct stat info = {0};

    if (access(file_path, F_OK) != 0) {
        return true;
    }

    if (stat(file_path, &info) != 0) {
        log_printf(LOG_ERR, "stat %s error [%d]", file_path, errno);
        return false;
    }
    /* distinguish between files and directories */
    if (S_ISDIR(info.st_mode)) {
        if (find_queue_byname(tmp_path) || find_queue_byname(real_path)) {
            log_printf(LOG_INFO, "File path %s is already configed, ignore this conf item.", file_path);
            return false;
        }
    } else if (S_ISREG(info.st_mode)) {
        if (find_queue_byname(real_path)) {
            log_printf(LOG_INFO, "File path %s is already configed, ignore this conf item.", file_path);
            return false;
        }
    } else {
        log_printf(LOG_INFO, "%s is not a directory or regular file, can not watch it.", file_path);
        return false;
    }

    return true;
}

static bool add_file_monitor(const char *file_path, char *tmp_path, const char *real_path, unsigned long wt_mask)
{
    fqueue_entry *wt_file = NULL;
    int ret;

    if (check_before_add(file_path, tmp_path, real_path) == false) {
        return false;
    }

    wt_file = malloc(sizeof(struct _fqueue_entry));
    if (wt_file == NULL) {
        log_printf(LOG_ERR, "wt_file malloc error!\n");
        return false;
    }

    ret = memset_s(wt_file, sizeof(struct _fqueue_entry), 0, sizeof(struct _fqueue_entry));
    if (ret) {
        log_printf(LOG_ERR, "filemonitor parse_line: memset_s wt_file failed, ret: %d", ret);
        free(wt_file);
        return false;
    }
    /* remove last / if the last of file_path is not / */
    if (file_path[strlen(file_path) - 1] != '/') {
        tmp_path[strlen(tmp_path) - 1] = '\0';
    }

    ret = strcpy_s(wt_file->file_path, MAX_PATH_LEN, tmp_path);
    if (ret) {
        log_printf(LOG_ERR, "filemonitor parse_line: strcpy_s wt_file file_path failed, ret: %d", ret);
        free(wt_file);
        return false;
    }
    wt_file->flag = false;
    wt_file->wt_mask = wt_mask;
    wt_file->count = 0;
    list_add(&wt_file->list, &g_conf_head);
    return true;
}

static int get_file_and_mask_from_config(const char *line, char *file_path, int size, unsigned long *mask)
{
    int ret;
    char str_mask[MAX_MASK_LEN] = {0};
    char *tmp = NULL;
    unsigned long wt_mask;

    ret = sscanf_s(line, "%s %s", file_path, size, str_mask, sizeof(str_mask));
    if (ret == -1) {
        log_printf(LOG_ERR, "Get path and mask failed [%d]", errno);
        return -1;
    }

    if (!strlen(file_path) || strlen(file_path) >= MAX_PATH_LEN - 1) {
        log_printf(LOG_INFO,
            "The path can't be recognised. The path length should be less than 4096 characters. error.");
        return -1;
    }

    if (strlen(str_mask) > 0) {
        /* use hex conversion */
        wt_mask = (unsigned long)strtol(str_mask, &tmp, STRTOL_HEX_NUMBER_BASE);
        if (wt_mask & 0xFFFFFCFF) {
            log_printf(LOG_INFO, "Mask is %s, it is more than add and delete, error.", str_mask);
            return -1;
        }
    } else {
        wt_mask = 0x200;
    }

    *mask = wt_mask;
    return 0;
}

static int parse_from_file_path(const char *file_path, unsigned int file_size, char *tmp_path, unsigned int size)
{
    int ret;
    unsigned int i;
    int j = 0;
    size_t len;

    ret = memcpy_s(tmp_path, size, file_path, file_size);
    if (ret) {
        log_printf(LOG_ERR, "filemonitor parse_line: memcpy_s tmp_path failed, ret: %d", ret);
        return -1;
    }
    if (strstr(file_path, "//") != NULL) {
        ret = memset_s(tmp_path, size, 0, size);
        if (ret) {
            log_printf(LOG_ERR, "filemonitor parse_line: memset_s tmp_path failed, ret: %d", ret);
            return -1;
        }
        len = strlen(file_path);
        for (i = 0; i < len; i++) {
            if (file_path[i] == '/' && file_path[i + 1] == '/') {
                continue;
            } else {
                tmp_path[j++] = file_path[i];
            }
        }
    }

    /* remove last /, realpath results do not include last / */
    if (strlen(tmp_path) > 0 && strcmp(tmp_path, "/") != 0 && tmp_path[strlen(tmp_path) - 1] == '/') {
        tmp_path[strlen(tmp_path) - 1] = '\0';
    }
    return 0;
}

static int check_tmpfs_dir(const char *tmp_path, const char *file_path, unsigned long *mask)
{
    /* check /proc/ /sys/ /dev/ */
    if (!memcmp(tmp_path, "/proc/", strlen("/proc/")) ||
        !memcmp(tmp_path, "/sys/", strlen("/sys/")) || !memcmp(tmp_path, "/dev/", strlen("/dev/"))) {
        log_printf(LOG_INFO, "(/proc /sys /dev)file %s no need to monitor.", file_path);
        return -1;
    }

    /* check /var/log/ only monitor delete event */
    if (!memcmp(tmp_path, "/var/log/", strlen("/var/log/"))) {
        log_printf(LOG_INFO, "Watch path is in /var/log, watch %s for only delete event", file_path);
        *mask = 0x200;
    }
    return 0;
}

static int parse_line(const char *line)
{
    char file_path[MAX_PATH_LEN] = {0};
    char real_path[PATH_MAX] = {0};
    char tmp_path[MAX_PATH_LEN] = {0};
    unsigned long wt_mask;
    int ret;

    while (*line == ' ' || *line == '\t') {
        line++;
        continue;
    }

    if (*line == '#') {
        return 0;
    }

    if (*line == '\0') {
        return 0;
    }

    ret = get_file_and_mask_from_config(line, file_path, MAX_PATH_LEN, &wt_mask);
    if (ret != 0) {
        return -1;
    }

    ret = parse_from_file_path(file_path, MAX_PATH_LEN, tmp_path, MAX_PATH_LEN);
    if (ret != 0) {
        return -1;
    }

    if (!access(file_path, F_OK)) {
        if (realpath(file_path, real_path) == NULL) {
            log_printf(LOG_ERR, "realpath error [%d]", errno);
            return -1;
        }
        if (!strlen(tmp_path) || (strcmp(real_path, tmp_path) && strcmp(real_path, file_path))) {
            log_printf(LOG_ERR, "%s should be absolute path.", file_path);
            return -1;
        }
    }

    /* add / to last to check /proc/ /sys/ /dev/ and /var/log/ */
    if (tmp_path[strlen(tmp_path) - 1] != '/') {
        tmp_path[strlen(tmp_path)] = '/';
    }

    ret = check_tmpfs_dir(tmp_path, file_path, &wt_mask);
    if (ret == -1) {
        return 0;
    }

    if (add_file_monitor(file_path, tmp_path, real_path, wt_mask) == false) {
        return -1;
    }

    return 0;
}

static void parse_conf(FILE *fp)
{
    char conf_line[MAX_LINE_LEN] = {0};

    for (;;) {
        if (!fgets(conf_line, MAX_LINE_LEN, fp)) {
            break;
        }
        if (strlen(conf_line) == 1 || strlen(conf_line) == 0) {
            continue;
        }
        if (conf_line[strlen(conf_line) - 1] == '\n') {
            conf_line[strlen(conf_line) - 1] = '\0';
        }
        if (strlen(conf_line) >= (MAX_LINE_LEN - 1)) {
            log_printf(LOG_INFO, "Config file line len is invalid. [%s]", conf_line);
            continue;
        }
        if (parse_line(conf_line)) {
            log_printf(LOG_ERR, "Parse line error. [%s]", conf_line);
        }
    }
    return;
}

static int fm_load_config(void)
{
    FILE *fp = NULL;
    struct dirent *entry_dirent = NULL;
    int config_fd = 0;
    DIR *dirp = NULL;
    int ret = -1;
    char cfg_full_name[FM_MAX_CFG_NAME_LEN + sizeof(FM_MONITOR_CONFIG_DIR)] = {0};

    fp = fopen(FM_MONITOR_CONF, "r");
    if (fp != NULL) {
        parse_conf(fp);
        (void)fclose(fp);
        ret = 0;
    }

    dirp = opendir(FM_MONITOR_CONFIG_DIR);
    if (dirp == NULL) {
        log_printf(LOG_INFO, "%s not exist", FM_MONITOR_CONFIG_DIR);
        return ret;
    }

    for (;;) {
        entry_dirent = readdir(dirp);
        if (entry_dirent == NULL) {
            break;
        }

        if (strlen(entry_dirent->d_name) >= FM_MAX_CFG_NAME_LEN) {
            log_printf(LOG_ERR, "file monitor:config file name is too long. file: %s", entry_dirent->d_name);
            continue;
        }
        ret = memset_s(cfg_full_name, sizeof(cfg_full_name), 0, sizeof(cfg_full_name));
        if (ret != 0) {
            log_printf(LOG_ERR, "fm_load_config memset_s cfg_full_name error [%d]", ret);
            continue;
        }
        ret = snprintf_s(cfg_full_name, sizeof(cfg_full_name), sizeof(cfg_full_name) - 1,
            "%s%s", FM_MONITOR_CONFIG_DIR, entry_dirent->d_name);
        if (ret < 0) {
            log_printf(LOG_ERR, "fm_load_config snprintf_s cfg_full_name error [%d]", ret);
            continue;
        }

        fp = open_cfgfile(cfg_full_name, &config_fd);
        if (fp == NULL) {
            continue;
        }

        parse_conf(fp);
        (void)fclose(fp);
    }
    (void)closedir(dirp);

    return 0;
}

static int open_inotify_fd(void)
{
    int fd = -1;
    int ret;

    g_watched_items = 0;
    g_save_process = false;
    fd = inotify_init1(IN_CLOEXEC);
    if (fd < 0) {
        log_printf(LOG_ERR, "Init file monitor thread error [%d]", errno);
        return fd;
    }

    ret = ioctl(fd, INOTIFY_IOC_SET_SYSMONITOR_FM);
    if (ret == 0) {
        log_printf(LOG_INFO, "ioctl set inotify save process info success.");
        g_save_process = true;
    }
    return fd;
}

/* Close the open file descriptor that was opened with inotify_init() */
static void close_inotify_fd(int fd)
{
    if (fd < 0) {
        return;
    }
    if (close(fd) < 0) {
        log_printf(LOG_ERR, "Close file monitor thread error [%d]", errno);
    }

    g_watched_items = 0;
}

struct event_msg {
    unsigned int flag;
    const char *name;
};

static const struct event_msg g_event_msg[] = {
    { IN_DELETE, "deleted" },
    { IN_CREATE, "added" },
};

static int set_event_msg(const queue_entry *event, char *msg, size_t size, const char *file_path)
{
    int ret;
    unsigned int i;
    unsigned int flag = event->inot_ev.mask & (IN_ALL_EVENTS | IN_UNMOUNT | IN_Q_OVERFLOW | IN_IGNORED);
    bool b_dir = (event->inot_ev.mask & IN_ISDIR) ? true : false;

    for (i = 0; i < array_size(g_event_msg); i++) {
        if (g_event_msg[i].flag == flag) {
            if (!g_save_process) {
                ret = snprintf_s(msg, size, size - 1, "%s \"%s\" under \"%s\" was %s.",
                    b_dir ? "Subdir" : "Subfile", event->inot_ev.name, file_path, g_event_msg[i].name);
            } else {
                ret = snprintf_s(msg, size, size - 1,
                    "%s \"%s\" under \"%s\" was %s, comm: %s[%d], parent comm: %s[%d]",
                    b_dir ? "Subdir" : "Subfile", event->inot_ev.name, file_path, g_event_msg[i].name,
                    event->info.comm, event->info.pid, event->info.parent_comm, event->info.parent_pid);
            }
            if (ret == -1) {
                log_printf(LOG_ERR, "snprintf_s event[%u] msg failed.", flag);
            }
            return ret;
        }
    }
    return -1;
}

static int handle_del_self_and_ignore(const queue_entry *event, fqueue_entry *conf,
                                      char *alarm_msg, size_t size)
{
    int ret;

    if (!access(conf->file_path, F_OK)) {
        /* file exist, log info and add watch again */
        if (!g_save_process) {
            ret = snprintf_s(alarm_msg, size, size - 1,
                "File \"%s\" was deleted. It's maybe changed", conf->file_path);
	} else {
            ret = snprintf_s(alarm_msg, size, size - 1,
                "File \"%s\" was deleted. It's maybe changed. comm: %s[%d], parent comm: %s[%d]",
                conf->file_path, event->info.comm, event->info.pid, event->info.parent_comm, event->info.parent_pid);
        }
        conf->flag = false;
        g_watch_flag = false;
    } else {
        if (!g_save_process) {
            ret = snprintf_s(alarm_msg, size, size - 1,
                "File \"%s\" was deleted", conf->file_path);
        } else {
            ret = snprintf_s(alarm_msg, size, size - 1,
                "File \"%s\" was deleted. comm: %s[%d], parent comm: %s[%d]", conf->file_path,
                event->info.comm, event->info.pid, event->info.parent_comm, event->info.parent_pid);
        }
    }
    return ret;
}

static void handle_event(const queue_entry *event)
{
    char alarm_msg[PARAS_LEN] = {0};
    int cur_event_wd = event->inot_ev.wd;
    fqueue_entry *conf = find_queue(cur_event_wd);

    if (conf == NULL) {
        log_printf(LOG_ERR, "Monitor a event not in conf file, the wd is %d", cur_event_wd);
        return;
    }

    switch (event->inot_ev.mask & (IN_ALL_EVENTS | IN_UNMOUNT | IN_Q_OVERFLOW | IN_IGNORED)) {
        case IN_DELETE:
        case IN_CREATE:
            set_event_msg(event, alarm_msg, sizeof(alarm_msg), conf->file_path);
            break;

        case IN_DELETE_SELF:
        case IN_IGNORED:
            handle_del_self_and_ignore(event, conf, alarm_msg, sizeof(alarm_msg));
            break;

        default:
            snprintf_s((char *)alarm_msg, sizeof(alarm_msg),
                sizeof(alarm_msg) - 1, "UNKNOWN EVENT on \"%s\".", conf->file_path);
            break;
    }
    log_printf(LOG_INFO, "%s", alarm_msg);
}

static void handle_events(void)
{
    queue_entry *f_event = NULL;
    queue_entry *next = NULL;
    int count = 0;

    list_for_each_entry_safe(f_event, next, &g_event_head, list) {
        log_printf(LOG_INFO, "%dth event handled", ++count);
        handle_event(f_event);
        list_del(&f_event->list);
        free(f_event);
    }
}
static int check_size(size_t event_size, size_t q_event_size, size_t buffer_i)
{
    if (event_size == 0 || q_event_size == 0) {
        log_printf(LOG_INFO, "read_events: event_size or q_event_size is not right.");
        return RET_BREAK;
    }
    if (event_size > EVENT_BUF - 1 - buffer_i) {
        log_printf(LOG_INFO, "read_events: not enough buffer for event.");
        return RET_BREAK;
    }

    return RET_SUCCESS;
}

static int add_event_list(const char *buffer, ssize_t r)
{
    size_t buffer_i = 0;
    struct inotify_event *pevent = NULL;
    queue_entry *event = NULL;
    size_t event_size, q_event_size;
    size_t info_size = sizeof(inotify_event_process_info);
    int count = 0;
    int ret;

    while (buffer_i < (size_t)r) {
        pevent = (struct inotify_event *)&buffer[buffer_i];
        event_size = offsetof(struct inotify_event, name) + pevent->len;
        q_event_size = offsetof(struct _queue_entry, inot_ev.name) + pevent->len;
        ret = check_size(event_size, q_event_size, buffer_i);
        if (ret == RET_BREAK) {
            break;
        }
        event = malloc(q_event_size);
        if (event == NULL) {
            log_printf(LOG_ERR, "event malloc error!\n");
            break;
        }
        ret = memset_s(event, q_event_size, 0, q_event_size);
        if (ret) {
            log_printf(LOG_ERR, "read_events: memset_s event failed, ret: %d", ret);
            free(event);
            break;
        }
        ret = memcpy_s(&(event->inot_ev), event_size, pevent, event_size);
        if (ret) {
            log_printf(LOG_ERR, "read_events: memcpy_s event inot_ev failed, ret: %d", ret);
            free(event);
            break;
        }
        buffer_i += event_size;
        if (!g_save_process) {
            list_add(&event->list, &g_event_head);
            count++;
            continue;
        }
        if (info_size > EVENT_BUF - 1 - buffer_i) {
            log_printf(LOG_INFO, "read_events: not enough buffer for event process info.");
            free(event);
            break;
        }
        ret = memcpy_s(&(event->info), info_size, (inotify_event_process_info *)&buffer[buffer_i], info_size);
        if (ret) {
            log_printf(LOG_ERR, "read_events: memcpy_s event info failed, ret: %d", ret);
            free(event);
            break;
        }
        buffer_i += info_size;
        list_add(&event->list, &g_event_head);
        count++;
    }

    if (count > 0) {
        log_printf(LOG_INFO, "%d events queued", count);
    }

    return count;
}

static int read_events(int fd)
{
    char *buffer = NULL;
    ssize_t r;
    int ret;

    buffer = malloc(EVENT_BUF);
    if (buffer == NULL) {
        log_printf(LOG_ERR, "buffer malloc error!\n");
        return -1;
    }
    ret = memset_s(buffer, EVENT_BUF, 0, EVENT_BUF);
    if (ret) {
        log_printf(LOG_ERR, "read_events: memset_s buffer failed, ret: %d", ret);
        free(buffer);
        return -1;
    }
    r = read(fd, buffer, EVENT_BUF);
    if (r <= 0) {
        free(buffer);
        return (int)r;
    }

    ret = add_event_list(buffer, r);
    free(buffer);
    buffer = NULL;
    return ret;
}

static int event_check(int fd)
{
    fd_set rfds;

    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    struct timeval timeout;

    timeout.tv_sec = g_select_timeout;
    timeout.tv_usec = 0;
    return select(FD_SETSIZE, &rfds, NULL, NULL, &timeout);
}

static int watch_dir(int fd, const char *dirname, unsigned long mask)
{
    int wd;

    wd = inotify_add_watch(fd, dirname, (unsigned int)mask);
    if (wd <= 0) {
        if (fflush(stdout) == EOF) {
            log_printf(LOG_INFO, "fflush failed, check filesystem");
        }
    } else {
        g_watched_items++;
    }

    return wd;
}

static void fm_add_watch(int fd)
{
    int wd;
    int i_fd = fd;
    fqueue_entry *entry = NULL;

    g_watch_flag = true;
    list_for_each_entry(entry, &g_conf_head, list) {
        if (entry->flag) {
            continue;
        }
        wd = watch_dir(i_fd, entry->file_path, entry->wt_mask);
        if (wd > 0) {
            entry->wd = wd;
            entry->flag = true;
            log_printf(LOG_INFO, "file name is \"%s\", watch event is 0x%lX", entry->file_path, entry->wt_mask);
            entry->count = 0;
        } else {
            if (entry->count < FILE_WATCH_MAX_FAIL_NUM) {
                log_printf(LOG_INFO, "Cannot add watch for \"%s\" with event mask 0x%lX",
                    entry->file_path, entry->wt_mask);
            }
            g_watch_flag = false;
            entry->count++;
        }
    }
}

static int handle_filemonitor_reload(int *inotify_fd)
{
    int fd = *inotify_fd;

    if (!get_thread_item_reload_flag(FILE_ITEM)) {
        return 0;
    }

    set_thread_item_reload_flag(FILE_ITEM, false);
    log_printf(LOG_INFO, "Conf file is modified, reload conf and watch again.");
    close_inotify_fd(fd);
    fd = open_inotify_fd();
    if (fd <= 0) {
        *inotify_fd = -1;
        return -1;
    }

    free_fqueue();

    if (fm_load_config()) {
        log_printf(LOG_INFO, "Reload file monitor configuration failed.");
    }

    fm_add_watch(fd);
    if (g_watched_items == 0) {
        log_printf(LOG_INFO, "No watcher add to FD.");
    }

    *inotify_fd = fd;
    return 0;
}

static void *file_monitor_start(void *arg)
{
    int inotify_fd = -1;

    /* prctl does not return false if arg2 is right when arg1 is PR_SET_NAME */
    (void)prctl(PR_SET_NAME, "monitor-file");
    log_printf(LOG_INFO, "file monitor starting up");

    set_thread_item_reload_flag(FILE_ITEM, false);
    inotify_fd = open_inotify_fd();
    if (inotify_fd <= 0) {
        return NULL;
    }
    init_list_head(&g_conf_head);
    init_list_head(&g_event_head);

    if (fm_load_config()) {
        log_printf(LOG_INFO, "load file monitor configuration failed");
    }
    fm_add_watch(inotify_fd);
    if (g_watched_items == 0) {
        log_printf(LOG_INFO, "No watcher add to FD");
    }
    for (;;) {
        if (handle_filemonitor_reload(&inotify_fd) == -1) {
            break;
        }

        if (g_watch_flag == false) {
            fm_add_watch(inotify_fd);
        }

        if (event_check(inotify_fd) > 0) {
            int r;

            r = read_events(inotify_fd);
            if (r < 0) {
                break;
            } else {
                handle_events();
            }
        } else {
            continue;
        }
    }

    close_inotify_fd(inotify_fd);
    free_fqueue();
    return NULL;
}

void file_monitor_init(void)
{
    pthread_t tid;

    if (pthread_create(&tid, NULL, file_monitor_start, NULL)) {
        log_printf(LOG_ERR, "create file monitor thread error [%d]", errno);
        return;
    }
    set_thread_item_tid(FILE_ITEM, tid);
}
