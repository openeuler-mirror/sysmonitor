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
 * Description: disk, inode, io_delay monitor
 * Author: xuchunmei
 * Create: 2016-1-1
 */
#include "disk.h"

#include <unistd.h>

#include <securec.h>
#include "common.h"
#include "monitor_thread.h"

#define DISK_CFG_PATH "/etc/sysmonitor/disk"
#define DISK_INODE_CFG_PATH "/etc/sysmonitor/inode"
#define MAX_DISK_CONFIG 200
#define MAX_DISK_NAME 64
#define DISK_RETRY_TIMES 3
#define MAX_DISK_ID 32
#define DISK_STATS_COUNT 2
#define MAX_COUNT 60
#define DISK_ALARM_DEFAULT 90
#define DISK_RESUME_DEFAULT 80
#define DISK_BUFFER_LEN 1024
#define DISK_USAGE_LEN 4
#define MAX_DELAY_ABNORMAL 30
#define MAX_DISK_ALARM 100
#define MAX_DISK_RESUME 100

#define DELAY_INFO_BUF_LEN  500
#define DELAY_DATA_BUF_LEN  10

#define DISK_STATS_DATA_COUNT 4
typedef enum _disk_status {
    NORMAL,
    ALARM
} disk_status;

typedef struct _mdisk {
    struct _mdisk *next;
    char disk[MAX_DISK_NAME + 1];  /* monitor disk name */
    char mount[MAX_DISK_NAME + 1]; /* mount dir name */
    int alarm;                     /* block or inode alarm value */
    int resume;                    /* block or inode resume value */
    disk_status last_status;       /* last status, alarm or normal */
    int times;                     /* alarm times */
} mdisk;

typedef struct _disk_states_info {
    unsigned long rio;             /* read request sum */
    unsigned long wio;             /* write request sum */
    unsigned long r_use;           /* read spend time */
    unsigned long w_use;           /* write spend time */
} disk_states_info;

typedef struct _disk_io_info {
    bool alarm;                                     /* alarm status */
    char disk_id[MAX_DISK_ID];                      /* disk id */
    disk_states_info disk_stats[DISK_STATS_COUNT];  /* disk io status */
    unsigned long delay[MAX_COUNT];                 /* disk io delay */
} disk_io_info;

typedef struct _local_disk {
    struct _local_disk *next;
    disk_io_info disk_io_info;
} local_disk;

static mdisk *g_mdisk_head;
static mdisk *g_mdisk_inode_head;

static int g_disk_thread_start = 1;
static int g_inode_thread_start = 1;
static int g_disk_io_delay;
static int g_disk_io_thread_start = 1;

#define custom_list_for_each(list_head, list_node) \
    for ((list_node) = (list_head)->next;       \
         (list_node) != NULL;                 \
         (list_node) = (list_node)->next)

static void free_disk_list(mdisk **disklist)
{
    mdisk *t = NULL;
    mdisk *disk = NULL;

    if (*disklist == NULL) {
        return;
    }

    disk = *disklist;
    t = disk;
    while (t->next != NULL) {
        disk = t->next;
        free(t);
        t = disk;
    }
    free(disk);
    *disklist = NULL;
    return;
}

static bool mdisk_add(const mdisk *add_disk, mdisk **disk_list)
{
    mdisk *disk = NULL;
    int ret;

    if (add_disk == NULL) {
        return false;
    }

    disk = malloc(sizeof(mdisk));
    if (disk == NULL) {
        log_printf(LOG_ERR, "malloc mdisk error [%d]", errno);
        return false;
    }

    ret = memcpy_s(disk, sizeof(mdisk), add_disk, sizeof(mdisk));
    if (ret != 0) {
        log_printf(LOG_ERR, "mdisk_add: memcpy_s disk failed, ret: %d", ret);
        free(disk);
        return false;
    }

    disk->next = NULL;

    if (*disk_list == NULL) {
        *disk_list = disk;
    } else {
        disk->next = *disk_list;
        *disk_list = disk;
    }
    return true;
}

static void free_local_disk(local_disk *disklist)
{
    local_disk *tmp_disk = NULL;

    if (disklist == NULL) {
        return;
    }

    while (disklist != NULL) {
        tmp_disk = disklist->next;
        free(disklist);
        disklist = tmp_disk;
    }
    return;
}

static bool local_disk_add(local_disk *disk_head, const local_disk *add_local_disk)
{
    local_disk *local_disk_node = NULL;
    int ret;

    if (add_local_disk == NULL) {
        return false;
    }

    local_disk_node = malloc(sizeof(local_disk));
    if (local_disk_node == NULL) {
        log_printf(LOG_ERR, "malloc local disk error [%d]", errno);
        return false;
    }
    ret = memset_s(local_disk_node, sizeof(local_disk), 0, sizeof(local_disk));
    if (ret != 0) {
        log_printf(LOG_ERR, "local_disk_add: memset_s local_disk_node failed, ret: %d", ret);
        free(local_disk_node);
        return false;
    }
    ret = strcpy_s(local_disk_node->disk_io_info.disk_id, MAX_DISK_ID, add_local_disk->disk_io_info.disk_id);
    if (ret != 0) {
        log_printf(LOG_ERR, "local_disk_add: strcpy_s disk_io_info failed, ret: %d", ret);
        free(local_disk_node);
        return false;
    }
    local_disk_node->next = disk_head->next;
    disk_head->next = local_disk_node;
    return true;
}

static int get_mount(mdisk *disk)
{
    int ret;
    char buffer[DISK_BUFFER_LEN] = {0};
    char tmp_cmd[MAX_TEMPSTR] = {0};

    ret = snprintf_s(tmp_cmd, sizeof(tmp_cmd), MAX_TEMPSTR - 1,
        "df %s | awk \'{print $6 }\'| tail -1", disk->disk);
    if (ret == -1) {
        log_printf(LOG_ERR, "get_mount: snprintf_s tmp_cmd failed, ret: %d", ret);
        return -1;
    }
    ret = monitor_popen(tmp_cmd, buffer, sizeof(buffer) - 1, POPEN_TIMEOUT, NULL);
    if (strchr(buffer, '/') && (ret >= 0)) {
        ret = memset_s(disk->mount, sizeof(disk->mount), 0, sizeof(disk->mount));
        if (ret != 0) {
            log_printf(LOG_ERR, "get_mount: memset_s tmp_cmd failed, ret: %d", ret);
            return -1;
        }
        ret = memcpy_s(disk->mount, sizeof(disk->mount), buffer, strlen(buffer) - 1);
        if (ret != 0) {
            log_printf(LOG_ERR, "get_mount: memcpy_s mount failed, ret: %d", ret);
            return -1;
        }
        return 0;
    }
    return -1;
}

static int get_diskname_from_config(const char *config, mdisk *disk)
{
    char key[MAX_DISK_NAME + 1] = {0};
    int ret;

    if (get_string(config, "DISK=\"", key, sizeof(key), "DISK") != 0) {
        log_printf(LOG_INFO, "get_string DISK failed");
        return -1;
    }

    if (check_conf_file_valid(key) == -1) {
        return -1;
    }

    ret = strncpy_s(disk->disk, sizeof(disk->disk), key, sizeof(disk->disk) - 1);
    if (ret != 0) {
        log_printf(LOG_ERR, "parse_diskline: strncpy_s disk failed, ret: %d", ret);
        return -1;
    }

    return 0;
}

static int get_alarm_from_config(const char *config, mdisk *disk)
{
    char key[MAX_DISK_NAME + 1] = {0};

    if (get_string(config, "ALARM=\"", key, sizeof(key), "ALARM") != 0) {
        disk->alarm = DISK_ALARM_DEFAULT;
    } else {
        if (check_int(key)) {
            disk->alarm = (int)strtol(key, NULL, STRTOL_NUMBER_BASE);
        } else {
            return -1;
        }
    }
    return 0;
}

static int get_resume_from_config(const char *config, mdisk *disk)
{
    char key[MAX_DISK_NAME + 1] = {0};

    if (get_string(config, "RESUME=\"", key, sizeof(key), "RESUME") != 0) {
        disk->resume = DISK_RESUME_DEFAULT;
    } else {
        if (check_int(key)) {
            disk->resume = (int)strtol(key, NULL, STRTOL_NUMBER_BASE);
        } else {
            return -1;
        }
    }
    return 0;
}

static int check_alarm_and_resume(const mdisk *disk)
{
    if ((disk->alarm <= disk->resume) || (disk->alarm < 0) || (disk->alarm > MAX_DISK_ALARM) ||
        (disk->resume < 0) || (disk->resume > MAX_DISK_RESUME)) {
        log_printf(LOG_ERR, "alarm:%d or resume:%d invalided", disk->alarm, disk->resume);
        return -1;
    }
    return 0;
}

static int parse_and_check_config(const char *config, mdisk *disk)
{
    if (get_diskname_from_config(config, disk) == -1) {
        return -1;
    }

    if (get_alarm_from_config(config, disk) == -1) {
        return -1;
    }

    if (get_resume_from_config(config, disk) == -1) {
        return -1;
    }

    if (check_alarm_and_resume(disk) == -1) {
        return -1;
    }

    return 0;
}

/*
 * parse one line in the config file
 * parse item word DISK=
 * verify mount points
 * verify alarm and resume value
 */
static int parse_diskline(mdisk *disk, const char *config, mdisk **head)
{
    /* skip space and tab */
    while (*config == ' ' || *config == '\t') {
        config++;
        continue;
    }

    /* comment start with '#' */
    if ((*config == '#') || (*config == '\n')) {
        return 1;
    }

    if (parse_and_check_config(config, disk) == -1) {
        return -1;
    }

    /* get mount point */
    if (get_mount(disk) == -1) {
        log_printf(LOG_ERR, "get_mount:%s failed", disk->disk);
        return -1;
    }

    /* keep status and times before reload */
    mdisk *t = *head;

    while (t != NULL) {
        if (strcmp(disk->disk, t->disk) == 0) {
            disk->last_status = t->last_status;
            disk->times = t->times;
            break;
        }
        t = t->next;
    }

    return 0;
}

static bool check_list(mdisk **disk_list, int type)
{
    mdisk *disk = *disk_list;
    mdisk *new_list = NULL;
    mdisk *t = NULL;
    bool useful = false;

    while (disk != NULL) {
        t = *disk_list;
        useful = true;
        while (t != disk) {
            if (!strcmp(disk->mount, t->mount)) {
                useful = false;
                log_printf(LOG_INFO, "[%s]disk:%s mount:%s alarm:%d resume:%d has monitored",
                    type == INODE_ITEM ? "disk inode" : "disk space",
                    disk->disk, disk->mount, disk->alarm, disk->resume);
                break;
            }
            t = t->next;
        }

        if (useful) {
            if (mdisk_add(disk, &new_list) == false) {
                free_disk_list(disk_list);
                *disk_list = new_list;
                return false;
            }
        }

        disk = disk->next;
    }

    free_disk_list(disk_list);
    *disk_list = new_list;
    return true;
}

static void parse_diskline_failed(char *config, unsigned int len, int ret)
{
    if (ret != -1) {
        return;
    }

    if (len > 0 && config[len - 1] == '\n') {
        config[len - 1] = '\0';
    }
    log_printf(LOG_INFO, "parse_diskline error:%s", config);
}

static int reload_file(const char *cfg_path, mdisk **head)
{
    int ret;
    FILE *fp = NULL;
    int config_fd = -1;
    char config[MAX_DISK_CONFIG];
    mdisk disk_tmp;
    mdisk *new_disk = NULL;
    int type;

    fp = open_cfgfile(cfg_path, &config_fd);
    if (fp == NULL) {
        return 1;
    }

    for (;;) {
        if (!fgets(config, sizeof(config), fp)) {
            break;
        }

        ret = memset_s(&disk_tmp, sizeof(disk_tmp), 0, sizeof(disk_tmp));
        if (ret != 0) {
            log_printf(LOG_ERR, "reload_file: memset_s disk_tmp failed, ret: %d", ret);
            goto err;
        }
        /* compare with old config, if exists keep old status and times */
        ret = parse_diskline(&disk_tmp, config, head);
        if (ret != 0) {
            parse_diskline_failed(config, (unsigned int)strlen(config), ret);
            continue;
        }

        /* add disk to new list */
        if (mdisk_add(&disk_tmp, &new_disk) == false) {
            free_disk_list(head);
            *head = new_disk;
            goto err;
        }
    }

    /* free old list and set new list */
    free_disk_list(head);
    *head = new_disk;

    if (!strcmp(DISK_CFG_PATH, cfg_path)) {
        type = DISK_ITEM;
        set_thread_item_reload_flag(DISK_ITEM, false);
    } else {
        type = INODE_ITEM;
        set_thread_item_reload_flag(INODE_ITEM, false);
    }

    /* check and merge same root mount point, the first config works */
    if (check_list(head, type) == false) {
        goto err;
    }

    (void)fclose(fp);
    return 0;
err:
    free_disk_list(head);
    (void)fclose(fp);
    return -1;
}

static int get_disk(const mdisk *disk)
{
    char *str = NULL;
    char tmp[DISK_USAGE_LEN] = {0};
    int used = -1;
    char buffer[DISK_BUFFER_LEN] = {0};
    char tmp_cmd[MAX_TEMPSTR] = {0};
    int ret;

    ret = snprintf_s(tmp_cmd, sizeof(tmp_cmd), MAX_TEMPSTR - 1,
        "df %s | awk \'{print $5 }\'| tail -1", disk->disk);
    if (ret == -1) {
        log_printf(LOG_ERR, "get_disk: snprintf_s tmp_cmd failed, ret: %d", ret);
        return -1;
    }
    (void)monitor_popen(tmp_cmd, buffer, sizeof(buffer) - 1, POPEN_TIMEOUT, NULL);
    str = strchr(buffer, '%');
    if (str != NULL) {
        ret = memcpy_s(tmp, sizeof(tmp), buffer, (size_t)(str - buffer));
        if (ret != 0) {
            log_printf(LOG_ERR, "get_disk: memcpy_s tmp failed, ret: %d", ret);
            return -1;
        }
        used = (int)strtol(tmp, NULL, STRTOL_NUMBER_BASE);
        return used;
    }

    return used;
}

static int get_disk_inode(const mdisk *disk)
{
    char *str = NULL;
    char tmp[DISK_USAGE_LEN] = {0};
    int used = -1;
    char buffer[DISK_BUFFER_LEN] = {0};
    char tmp_cmd[MAX_TEMPSTR] = {0};
    int ret;
    ret = snprintf_s(tmp_cmd, sizeof(tmp_cmd), MAX_TEMPSTR - 1,
        "df -i %s | awk \'{print $5 }\'| tail -1", disk->disk);
    if (ret == -1) {
        log_printf(LOG_ERR, "get_disk_inode: snprintf_s tmp_cmd failed, ret: %d", ret);
        return -1;
    }
    (void)monitor_popen(tmp_cmd, buffer, sizeof(buffer) - 1, POPEN_TIMEOUT, NULL);
    str = strchr(buffer, '%');
    if (str != NULL) {
        ret = memcpy_s(tmp, sizeof(tmp), buffer, (size_t)(str - buffer));
        if (ret != 0) {
            log_printf(LOG_ERR, "get_disk_inode: memcpy_s tmp_cmd failed, ret: %d", ret);
            return -1;
        }

        used = (int)strtol(tmp, NULL, STRTOL_NUMBER_BASE);
        return used;
    }

    return used;
}

/* return value 0 means not alarm, 1 means alarm */
static int check_disk(int used, mdisk *disk, int thread_start, unsigned char *alarm_type)
{
    if ((used >= disk->alarm) && (disk->last_status == NORMAL)) {
        disk->times++;
        if (disk->times >= DISK_RETRY_TIMES) {
            disk->last_status = ALARM;
            disk->times = 0;
            *alarm_type = COMMON_ALARM_TYPE_OCCUR;
            return 1;
        }
    }

    if (((used < disk->resume) && (disk->last_status == ALARM)) ||
        ((used < disk->resume) && thread_start)) {
        disk->times = 0;
        disk->last_status = NORMAL;
        *alarm_type = COMMON_ALARM_TYPE_RESUME;
        return 1;
    }

    return 0;
}

/* run the queue to check all the disk cfg in the list */
static void disk_runqueue(void)
{
    mdisk *t = NULL;
    int used;
    unsigned char alarm_type;

    for (t = g_mdisk_head; t;) {
        /* get usage of disk */
        used = get_disk(t);
        if (used < 0) {
            log_printf(LOG_INFO, "get_disk_used %s failed", t->disk);
            t = t->next;
            continue;
        }

        /* check alarm or not */
        if (check_disk(used, t, g_disk_thread_start, &alarm_type)) {
            if (alarm_type == COMMON_ALARM_TYPE_OCCUR) {
                log_printf(LOG_WARNING, "report disk alarm, %s used:%d%% alarm:%d%%", t->disk, used, t->alarm);
            } else {
                log_printf(LOG_INFO, "report disk recovered, %s used:%d%% resume:%d%%", t->disk, used, t->resume);
            }
        }

        t = t->next;
    }

    g_disk_thread_start = 0;
}

/* run the queue to check all the disk cfg in the list */
static void inode_runqueue(void)
{
    mdisk *t = NULL;
    int used;
    unsigned char alarm_type;

    for (t = g_mdisk_inode_head; t;) {
        /* get inode usage */
        used = get_disk_inode(t);
        if (used < 0) {
            log_printf(LOG_WARNING, "get_disk_inode used %s failed", t->disk);
            t = t->next;
            continue;
        }

        /* check alarm or not */
        if (check_disk(used, t, g_inode_thread_start, &alarm_type)) {
            if (alarm_type == COMMON_ALARM_TYPE_OCCUR) {
                log_printf(LOG_WARNING, "report disk inode alarm, %s used:%d%% alarm:%d%%", t->disk, used, t->alarm);
            } else {
                log_printf(LOG_INFO, "report disk inode recovered, %s used:%d%% resume:%d%%", t->disk, used, t->resume);
            }
        }

        t = t->next;
    }

    g_inode_thread_start = 0;
}

static int disk_reload_file(void)
{
    int ret;

    ret = reload_file(DISK_CFG_PATH, &g_mdisk_head);
    if (ret != 0) {
        log_printf(LOG_INFO, "reload disk monitor configuration failed");
        ret = set_thread_status_check_flag(THREAD_DISK_ITEM, false);
        if (ret == -1) {
            log_printf(LOG_ERR, "reload disk monitor set check flag error");
        }
        return RET_BREAK;
    }
    return RET_SUCCESS;
}

static void *disk_monitor_start(void *arg)
{
    unsigned int period;
    int ret;
    /* prctl does not return false if arg2 is right when arg1 is PR_SET_NAME */
    (void)prctl(PR_SET_NAME, "monitor-disk");
    log_printf(LOG_INFO, "disk monitor starting up");
    period = (unsigned int)get_thread_item_period(DISK_ITEM);
    log_printf(LOG_INFO, "disk monitor period:[%u]\n", period);
    ret = set_thread_check_value(THREAD_DISK_ITEM, true, period);
    if (ret == -1) {
        log_printf(LOG_ERR, "disk monitor set check flag or period error");
        return NULL;
    }

    for (;;) {
        if (get_thread_item_reload_flag(DISK_ITEM)) {
            ret = disk_reload_file();
            if (ret == RET_BREAK) {
                break;
            }
        }
        disk_runqueue();
        ret = feed_thread_status_count(THREAD_DISK_ITEM);
        if (ret == -1) {
            log_printf(LOG_ERR, "disk monitor feed error");
            break;
        }
        (void)sleep(period);
    }
    return NULL;
}

void disk_monitor_init(void)
{
    pthread_t tid;

    if (pthread_create(&tid, NULL, disk_monitor_start, NULL)) {
        log_printf(LOG_ERR, "create disk monitor thread error [%d]", errno);
        return;
    }
    set_thread_item_tid(DISK_ITEM, tid);
}

static int inode_reload_file(void)
{
    int ret;

    ret = reload_file(DISK_INODE_CFG_PATH, &g_mdisk_inode_head);
    if (ret != 0) {
        log_printf(LOG_INFO, "reload disk inode monitor configuration failed");
        ret = set_thread_status_check_flag(THREAD_INODE_ITEM, false);
        if (ret == -1) {
            log_printf(LOG_ERR, "reload disk inode monitor set check flag error");
        }
        return RET_BREAK;
    }
    return RET_SUCCESS;
}

static void *inode_monitor_start(void *arg)
{
    int ret;
    unsigned int period;
    /* prctl does not return false if arg2 is right when arg1 is PR_SET_NAME */
    (void)prctl(PR_SET_NAME, "monitor-inode");
    log_printf(LOG_INFO, "disk inode monitor starting up");
    period = (unsigned int)get_thread_item_period(INODE_ITEM);
    log_printf(LOG_INFO, "disk inode monitor period:%u\n", period);
    ret = set_thread_check_value(THREAD_INODE_ITEM, true, period);
    if (ret == -1) {
        log_printf(LOG_ERR, "disk inode monitor set check flag or period error");
        return NULL;
    }

    for (;;) {
        if (get_thread_item_reload_flag(INODE_ITEM)) {
            ret = inode_reload_file();
            if (ret == RET_BREAK) {
                break;
            }
        }
        inode_runqueue();
        ret = feed_thread_status_count(THREAD_INODE_ITEM);
        if (ret == -1) {
            log_printf(LOG_ERR, "disk inode monitor feed error");
            break;
        }
        (void)sleep(period);
    }
    return NULL;
}

void inode_monitor_init(void)
{
    pthread_t tid;

    if (pthread_create(&tid, NULL, inode_monitor_start, NULL)) {
        log_printf(LOG_ERR, "create disk inode monitor thread error [%d]", errno);
        return;
    }
    set_thread_item_tid(INODE_ITEM, tid);
}

static bool parse_line(const char *config)
{
    char item[ITEM_LEN] = {0};
    char value[VALUE_LEN] = {0};
    char *ptr = NULL;
    unsigned int size;
    int ret;

    while (*config == ' ' || *config == '\t') {
        config++;
    }

    if (*config == '#') {
        return true;
    }

    ptr = strstr(config, "=\"");
    if (ptr != NULL) {
        size = (unsigned int)(ptr - config);
        if (size >= sizeof(item)) {
            log_printf(LOG_ERR, "disk parse_line: item length(%u) too long(>%lu).", size, sizeof(item));
            return false;
        }
        ret = strncpy_s(item, sizeof(item), config, size);
        if (ret != 0) {
            log_printf(LOG_ERR, "disk parse_line: strncpy_s item failed, ret: %d", ret);
            return false;
        }
        get_value(config, size, value, sizeof(value));
        if (!strlen(value)) {
            return true;
        }

        if (!strcmp(item, "DELAY_VALUE")) {
            if (check_int(value) == false) {
                return false;
            }
            g_disk_io_delay = (int)strtol(value, NULL, STRTOL_NUMBER_BASE);
        }
    }
    return true;
}

static void get_io_delay(local_disk *local_disk, unsigned int delay_id)
{
    unsigned long temp = 0;
    unsigned long io_req;

    /* second value is equal or larger than first value */
    io_req = (local_disk->disk_io_info.disk_stats[1].rio - local_disk->disk_io_info.disk_stats[0].rio) +
             (local_disk->disk_io_info.disk_stats[1].wio - local_disk->disk_io_info.disk_stats[0].wio);

    if (io_req != 0) {
        temp = ((local_disk->disk_io_info.disk_stats[1].w_use -
                local_disk->disk_io_info.disk_stats[0].w_use) +
                (local_disk->disk_io_info.disk_stats[1].r_use -
                local_disk->disk_io_info.disk_stats[0].r_use)) / io_req;
    }
    local_disk->disk_io_info.delay[delay_id] = temp;
    return;
}

static void get_disk_stats(local_disk *local_disk, unsigned int stats_id, const char *buf)
{
    int num;

    num = sscanf_s(buf, "%*lu %*lu %*s %lu %*lu %*lu %lu %lu %*lu %*lu %lu %*lu %*lu %*lu",
        &local_disk->disk_io_info.disk_stats[stats_id].rio,
        &local_disk->disk_io_info.disk_stats[stats_id].r_use,
        &local_disk->disk_io_info.disk_stats[stats_id].wio,
        &local_disk->disk_io_info.disk_stats[stats_id].w_use);
    if (num < DISK_STATS_DATA_COUNT) {
        log_printf(LOG_INFO, "failed get diskstats [%d]", errno);
    }
    return;
}

static void display_delay_info(const local_disk *tmp_local_disk)
{
    /*
     * I/O delay data ususally has 1~4 bits, there is a space between every two data.
     * So 500 bytes is enough for 60 data.
     */
    char delay_info[DELAY_INFO_BUF_LEN] = {0};
    size_t delay_info_size = sizeof(delay_info);
    char *pointer = delay_info;
    char delay_data[DELAY_DATA_BUF_LEN]; /* 10:data for one I/O delay data */
    size_t data_size;
    unsigned int i;
    int rc;

    for (i = 0; i < sizeof(tmp_local_disk->disk_io_info.delay) / sizeof(tmp_local_disk->disk_io_info.delay[0]); i++) {
        rc = memset_s(delay_data, sizeof(delay_data), 0, sizeof(delay_data));
        if (rc != EOK) {
            log_printf(LOG_ERR, "memset_s in function display_delay_info error");
            continue;
        }
        rc = sprintf_s(delay_data, sizeof(delay_data), "%lu", tmp_local_disk->disk_io_info.delay[i]);
        if (rc < 0) {
            log_printf(LOG_ERR, "sprintf_s in function display_delay_info error");
            continue;
        }
        data_size = strlen(delay_data);
        /* magic number 1: a space after %s */
        rc = snprintf_s(pointer, delay_info_size, data_size + 1, "%s ", delay_data);
        if (rc < 0) {
            log_printf(LOG_ERR, "snprintf_s in function display_delay_info error");
            break;
        }
        delay_info_size -= rc;
        /* if the remaining space can just store one '\0' in the tail, then break the loop */
        if (delay_info_size <= 1) {
            break;
        }
        /* cover the tailed '\0' every time snprintf_s is called, only reserve the last one when break the loop */
        pointer += rc;
    }
    log_printf(LOG_INFO, "disk is %s, io delay data: %s", tmp_local_disk->disk_io_info.disk_id, delay_info);
}

static void handle_io_delay_alarm(const local_disk *local_disk, unsigned int delay_abnomal, bool alarm)
{
    if (alarm) {
        log_printf(LOG_WARNING, "local disk:%s IO delay is too large. I/O delay threshold is %d.",
            local_disk->disk_io_info.disk_id, g_disk_io_delay);
    } else {
        log_printf(LOG_INFO, "local disk:%s IO delay is normal. I/O delay threshold is %d.",
            local_disk->disk_io_info.disk_id, g_disk_io_delay);
    }
    display_delay_info(local_disk);
}

static void check_report_alarm(local_disk *local_disk)
{
    unsigned int delay_abnormal = 0;
    unsigned int i;

    for (i = 0; i < MAX_COUNT; i++) {
        if (local_disk->disk_io_info.delay[i] > (unsigned long)g_disk_io_delay) {
            delay_abnormal++;
        }
    }

    if (delay_abnormal > MAX_DELAY_ABNORMAL && local_disk->disk_io_info.alarm == false) {
        handle_io_delay_alarm(local_disk, delay_abnormal, true);
        local_disk->disk_io_info.alarm = true;
    } else if ((delay_abnormal <= MAX_DELAY_ABNORMAL && local_disk->disk_io_info.alarm == true) ||
               (delay_abnormal <= MAX_DELAY_ABNORMAL && g_disk_io_thread_start == 1)) {
        handle_io_delay_alarm(local_disk, delay_abnormal, false);
        local_disk->disk_io_info.alarm = false;
    }
}

static bool check_and_add_disk(char *cnt_buf, int size, local_disk *local_disk_head)
{
    char *disk = NULL;
    char *p_save = NULL;
    local_disk local_disk_info;
    local_disk *tmp_local_disk = NULL;
    bool add_disk_flag = true;
    int ret;

    /* output of get_local_disk.sh is split by ',' */
    disk = strtok_r(cnt_buf, ",", &p_save);
    while (disk != NULL) {
        ret = memset_s(&local_disk_info, sizeof(local_disk), 0, sizeof(local_disk));
        if (ret != 0) {
            log_printf(LOG_ERR, "monitor_io_delay: memset_s local_disk_info failed, ret: %d", ret);
            return false;
        }

        ret = strcpy_s(local_disk_info.disk_io_info.disk_id, MAX_DISK_ID, disk);
        if (ret != 0) {
            log_printf(LOG_ERR, "monitor_io_delay: strcpy_s disk_io_info failed, ret: %d", ret);
            return false;
        }

        /* check exists in local disk list */
        custom_list_for_each(local_disk_head, tmp_local_disk) {
            if (strcmp(local_disk_info.disk_io_info.disk_id, tmp_local_disk->disk_io_info.disk_id) == 0) {
                add_disk_flag = false;
            }
        }

        /* if not exist in local disk list, then add to local disk list */
        if (add_disk_flag == true) {
            if (local_disk_add(local_disk_head, &local_disk_info) == false) {
                return false;
            }
        }
        add_disk_flag = true;
        disk = strtok_r(NULL, ",", &p_save);
    }

    return true;
}

static bool check_new_disk(local_disk *local_disk_head)
{
    char cmd[MAX_TEMPSTR] = {0};
    char cnt_buf[DISK_BUFFER_LEN] = {0};
    int ret;
    ret = strcpy_s(cmd, sizeof(cmd) - 1, "/usr/libexec/sysmonitor/get_local_disk.sh");
    if (ret != 0) {
        log_printf(LOG_ERR, "monitor_io_delay: strcpy_s cmd failed, ret: %d", ret);
        return false;
    }

    if (monitor_popen(cmd, cnt_buf, sizeof(cnt_buf) - 1, POPEN_TIMEOUT, NULL)) {
        log_printf(LOG_INFO, "failed to get local disk");
        return false;
    }

    if (strlen(cnt_buf) == 0) {
        log_printf(LOG_INFO, "get local disk failed");
        return false;
    }

    return check_and_add_disk(cnt_buf, DISK_BUFFER_LEN, local_disk_head);
}

static bool get_disk_stats_first(local_disk *local_disk_head)
{
    local_disk *tmp_local_disk = NULL;
    char cmd[MAX_TEMPSTR] = {0};
    char cnt_buf[DISK_BUFFER_LEN] = {0};
    int ret;

    custom_list_for_each(local_disk_head, tmp_local_disk) {
        ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "cat /proc/diskstats | grep -w %s",
            tmp_local_disk->disk_io_info.disk_id);
        if (ret == -1) {
            log_printf(LOG_ERR, "monitor_io_delay: snprintf_s cmd[1] failed, ret: %d", ret);
            return false;
        }

        ret = monitor_popen(cmd, cnt_buf, sizeof(cnt_buf) - 1, POPEN_TIMEOUT, NULL);
        if (ret != 0) {
            if (ret < 0) {
                log_printf(LOG_INFO, "failed to get diskstats ID %s", tmp_local_disk->disk_io_info.disk_id);
            }
            continue;
        }
        get_disk_stats(tmp_local_disk, 0, cnt_buf);
    }
    return true;
}

static bool get_disk_stats_second(local_disk *local_disk_head, unsigned int count)
{
    local_disk *tmp_local_disk = NULL;
    char cmd[MAX_TEMPSTR] = {0};
    char cnt_buf[DISK_BUFFER_LEN] = {0};
    int ret;

    custom_list_for_each(local_disk_head, tmp_local_disk) {
        ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "cat /proc/diskstats | grep -w %s",
            tmp_local_disk->disk_io_info.disk_id);
        if (ret == -1) {
            log_printf(LOG_ERR, "monitor_io_delay:snprintf_s cmd[2] failed, ret: %d", ret);
            return false;
        }
        ret = monitor_popen(cmd, cnt_buf, sizeof(cnt_buf) - 1, POPEN_TIMEOUT, NULL);
        if (ret != 0) {
            if (ret < 0) {
                log_printf(LOG_INFO, "failed to get diskstats ID %s", tmp_local_disk->disk_io_info.disk_id);
            }
            continue;
        }

        get_disk_stats(tmp_local_disk, 1, cnt_buf);
        /* get disk io delay and if 1 do not have io request, svctm is 0 */
        get_io_delay(tmp_local_disk, count);
        /* get data 60 times in five minutes, check alarm or not */
        if (count == MAX_COUNT - 1) {
            check_report_alarm(tmp_local_disk);
        }
    }

    return true;
}

static bool monitor_io_delay(unsigned int count, local_disk *local_disk_head)
{
    /* check new disk every five minutes */
    if (count == 0) {
        if (check_new_disk(local_disk_head) == false) {
            return false;
        }
    }

    /* get disk io delay first time */
    if (get_disk_stats_first(local_disk_head) == false) {
        return false;
    }

    (void)sleep(1);
    /* get disk io delay second time after one second */
    if (get_disk_stats_second(local_disk_head, count) == false) {
        return false;
    }

    if (count == MAX_COUNT - 1) {
        g_disk_io_thread_start = 0;
    }
    return true;
}

static int io_delay_parse_and_set_config(int period)
{
    bool ret = false;
    int result;

    set_thread_item_reload_flag(IO_DELAY_ITEM, false);
    ret = parse_config(IO_DELAY_CONF, parse_line);
    if ((ret == false) || (period < 0)) {
        log_printf(LOG_INFO, "io delay monitor: configuration illegal");
        ret = false;
        result = set_thread_status_check_flag(THREAD_IO_DELAY_ITEM, false);
        if (result == -1) {
            log_printf(LOG_ERR, "reload io delay monitor set check flag error");
            return RET_BREAK;
        }
    }

    if (ret) {
        result = set_thread_check_value(THREAD_IO_DELAY_ITEM, true, (unsigned int)(period - 1));
        if (result == -1) {
            log_printf(LOG_ERR, "io delay monitor set check flag or period error");
            return RET_BREAK;
        }
        return RET_SUCCESS;
    }
    return RET_CONTINUE;
}

static void *io_delay_monitor_start(void *arg)
{
    unsigned int cnt = 0;
    local_disk *disk_head = NULL;
    int period = 0;
    int result = -1;

    /* prctl does not return false if arg2 is right when arg1 is PR_SET_NAME */
    (void)prctl(PR_SET_NAME, "monitor-iodelay");
    log_printf(LOG_INFO, "local disk io delay monitor starting up");

    disk_head = malloc(sizeof(local_disk));
    if (disk_head == NULL) {
        log_printf(LOG_ERR, "malloc local_disk head error [%d]", errno);
        return NULL;
    }
    disk_head->next = NULL;

    for (;;) {
        if (get_thread_item_reload_flag(IO_DELAY_ITEM)) {
            period = get_thread_item_period(IO_DELAY_ITEM);
            result = io_delay_parse_and_set_config(period);
            if (result == RET_BREAK) {
                break;
            }
        }

        if (result == RET_SUCCESS) {
            if (monitor_io_delay(cnt, disk_head) == false) {
                goto out;
            }
        }

        if (cnt == MAX_COUNT - 1) {
            cnt = 0;
        } else {
            cnt++;
        }
        result = feed_thread_status_count(THREAD_IO_DELAY_ITEM);
        if (result == -1) {
            log_printf(LOG_ERR, "io delay monitor feed error");
            break;
        }
        (void)sleep((unsigned int)(period - 1));
    }
out:
    result = set_thread_status_check_flag(THREAD_IO_DELAY_ITEM, false);
    if (result == -1) {
        log_printf(LOG_ERR, "io delay monitor exit set check flag error");
    }
    free_local_disk(disk_head);
    return NULL;
}

void io_delay_monitor_init(void)
{
    pthread_t tid;

    if (pthread_create(&tid, NULL, io_delay_monitor_start, NULL)) {
        log_printf(LOG_ERR, "create io delay monitor thread error [%d]", errno);
        return;
    }
    set_thread_item_tid(IO_DELAY_ITEM, tid);
}
