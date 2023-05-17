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
 * Description: custom process monitor
 * Author: xuchunmei
 * Create: 2016-1-1
 */
#include "custom.h"

#include <dirent.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/wait.h>

#include <securec.h>
#include "monitor_thread.h"

static struct list_head g_custom_daemon_head;   /* daemon monitor items */
static struct list_head g_custom_periodic_head; /* periodic monitor items */
static worker_task g_task_queue[TASK_QUEUE_SIZE];
static pthread_mutex_t g_task_mtx = PTHREAD_MUTEX_INITIALIZER;

static int worker_task_init(const worker_task *task, int *index);
static void worker_task_add(const worker_task *task, int index);

static bool parse_monitor_switch(const char *item, const char *value, str_custom *t)
{
    bool result = parse_value_bool(item, value, &t->monitor_switch);
    if (!result) {
        log_printf(LOG_ERR, "custom monitor: monitor switch configuration error!");
        return false;
    }
    return true;
}

static bool parse_type(const char *item, const char *value, str_custom *t)
{
    if (!strcmp(value, "daemon")) {
        t->type = CUSTOM_DAEMON;
    } else if (!strcmp(value, "periodic")) {
        t->type = CUSTOM_PERIODIC;
    } else {
        log_printf(LOG_INFO, "custom monitor: type configuration error!");
        return false;
    }

    return true;
}

static bool check_cmd_valid(const char *cmd)
{
    int args_num;
    char exec[EXEC_MAX] = {0};
    char **args = NULL;

    args_num = get_exec_and_args(cmd, exec, &args);
    if (args_num < 0) {
        return false;
    }
    free_args(args, args_num);
    return true;
}

static bool parse_exec_start(const char *item, const char *value, str_custom *t)
{
    bool ret = false;

    if (strlen(value) == 0) {
        log_printf(LOG_ERR, "custom monitor: execstart configuration error!");
        return false;
    }
    ret = parse_value_string(item, value, t->start_cmd, MAX_CUSTOM_CMD_LEN);
    if (!ret) {
        return false;
    }

    return check_cmd_valid(t->start_cmd);
}

static bool parse_exec_other(const char *item, const char *value, str_custom *t)
{
    return true;
}

static bool parse_period(const char *item, const char *value, str_custom *t)
{
    bool result = parse_value_int(item, value, &t->period);
    if (!result) {
        log_printf(LOG_ERR, "custom monitor: period configuration error!");
        return false;
    }
    return true;
}

static bool parse_environmentfile(const char *item, const char *value, str_custom *t)
{
    if (strlen(value) == 0) {
        log_printf(LOG_ERR, "custom monitor: enviromentfile configuration error!");
        return false;
    }
    if (strlen(value) >= MAX_CFG_NAME_LEN) {
        log_printf(LOG_ERR, "custom monitor: enviromentfile path should be less than %d, error!", MAX_CFG_NAME_LEN);
        return false;
    }
    return parse_value_string(item, value, t->enviroment_file, MAX_CFG_NAME_LEN);
}

static custom_item_func g_custom_item_func_table[] = {
    { "MONITOR_SWITCH", parse_monitor_switch },
    { "TYPE", parse_type },
    { "EXECSTART", parse_exec_start },
    { "EXECSTARTPRE", parse_exec_other },
    { "EXECSTARTPOST", parse_exec_other },
    { "EXECSTOP", parse_exec_other },
    { "EXECSTOPPRE", parse_exec_other },
    { "EXECSTOPPOST", parse_exec_other },
    { "PERIOD", parse_period },
    { "ENVIROMENTFILE", parse_environmentfile },
};

static const char *g_custom_cfg_type[] = {
    "daemon",
    "periodic",
};

static bool get_value_custom(const char *config, unsigned int key_size, char *value, unsigned int value_len)
{
    char *ptr = NULL;
    unsigned int size;
    int ret;

    /* key="value", so here skip 2 to get value */
    config += key_size + 2;
    ptr = strchr(config, '\"');
    if (ptr != NULL) {
        size = (unsigned int)(ptr - config);
        if (size >= MAX_CUSTOM_CMD_LEN) {
            log_printf(LOG_ERR, "custom monitor: size should be less than %d, error!", MAX_CUSTOM_CMD_LEN);
            return false;
        }
        ret = strncpy_s(value, value_len, config, size);
        if (ret) {
            log_printf(LOG_ERR, "custom parse_line strncpy_s value error, ret: %d", ret);
            return false;
        }
    }
    return true;
}

/*
 * parse /etc/sysmonitor.d/ config files
 */
static bool parse_line(str_custom *t, const char *config)
{
    unsigned int size;
    char *ptr = NULL;
    char item[ITEM_LEN] = {0};
    char value[MAX_CONFIG] = {0};
    int ret;
    unsigned int i;

    while (*config == ' ' || *config == '\t') {
        config++;
    }

    if ((*config == '#') || (*config == '\n')) {
        return true;
    }

    if (check_conf_file_valid(config) == -1) {
        return false;
    }

    ptr = strstr(config, "=\"");
    if (ptr == NULL) {
        return false;
    }

    size = (unsigned int)(ptr - config);
    if (size >= sizeof(item)) {
        log_printf(LOG_ERR, "custom parse_line: item length(%u) too long(>%lu).", size, sizeof(item));
        return false;
    }
    ret = strncpy_s(item, sizeof(item), config, size);
    if (ret != 0) {
        log_printf(LOG_ERR, "custom parse_line: strncpy_s item failed, ret: %d", ret);
        return false;
    }

    if (get_value_custom(config, size, value, sizeof(value)) == false) {
        return false;
    }

    for (i = 0; i < array_size(g_custom_item_func_table); i++) {
        if (!strcmp(g_custom_item_func_table[i].item, item)) {
            return g_custom_item_func_table[i].func(item, value, t);
        }
    }

    log_printf(LOG_ERR, "%s not supported", item);
    return false;
}

/*
 * get environment variables from config files
 * the number of environment variables cannot exceed MAX_ENV_CONFIG
 */
static bool get_envp(const char *file_dir, char **envp, unsigned int *cout)
{
    char config[MAX_CONFIG] = {0};
    FILE *fp = NULL;
    size_t len;
    unsigned int i;
    unsigned int env = 0;
    int ret;

    if (check_file(file_dir) == false) {
        return false;
    }

    fp = fopen(file_dir, "r");
    if (fp == NULL) {
        log_printf(LOG_INFO, "open %s error [%d]", file_dir, errno);
        return false;
    }

    while (fgets(config, MAX_CONFIG, fp)) {
        i = 0;
        while (config[i] == ' ' || config[i] == '\t') {
            i++;
            continue;
        }

        if ((config[i] == '#') || (config[i] == '\n')) {
            continue;
        }

        len = strlen(&config[i]);
        if (len == 0) {
            continue;
        }
        if (config[i + len - 1] == '\n') {
            config[i + len - 1] = '\0';
            len -= 1;
        }

        envp[env] = malloc(len + 1);
        if (envp[env] == NULL) {
            log_printf(LOG_ERR, "malloc envp error.");
            *cout = env;
            (void)fclose(fp);
            return false;
        }
        ret = memcpy_s(envp[env], len + 1, &config[i], len + 1);
        if (ret != 0) {
            log_printf(LOG_ERR, "get_envp: memcpy_s envp failed, ret: %d", ret);
            free(envp[env]);
            envp[env] = NULL;
            *cout = env;
            (void)fclose(fp);
            return false;
        }

        env++;

        if (env >= MAX_ENV_CONFIG) {
            break;
        }
    }

    *cout = env;
    (void)fclose(fp);
    return true;
}

static void free_custom_env(str_custom **t)
{
    unsigned int i;

    if ((*t)->envp != NULL) {
        free((*t)->envp);
        (*t)->envp = NULL;
    }

    for (i = 0; i < (*t)->envp_config_count; i++) {
        if ((*t)->envp_config[i] != NULL) {
            free((*t)->envp_config[i]);
            (*t)->envp_config[i] = NULL;
        }
    }

    (*t)->envp_config_count = 0;
}

/*
 * free custom task
 */
static void free_custom_t(str_custom **t)
{
    if (*t == NULL) {
        return;
    }

    free_custom_env(t);

    free(*t);
    *t = NULL;
}

/*
 * close all fds of current process
 */
static int close_all_fd(void)
{
    struct rlimit lim;
    unsigned int i;

    if (getrlimit(RLIMIT_NOFILE, &lim) < 0) {
        return -1;
    }
    if (lim.rlim_cur > MAX_CLOSE_FD_NUM) {
        lim.rlim_cur = MAX_CLOSE_FD_NUM;
    }
    for (i = 0; i < lim.rlim_cur; i++) {
        (void)close((int)i);
    }

    return 0;
}

static void dup2_fd_in_child_process(void)
{
    int fd = -1;

    fd = open("/dev/null", O_RDWR, 0);
    if (fd >= 0) {
        (void)dup2(fd, STDIN_FILENO);
        (void)dup2(fd, STDOUT_FILENO);
        (void)dup2(fd, STDERR_FILENO);
        if (fd > STDERR_FILENO) {
            (void)close(fd);
        }
    }
}

/*
 * exec daemon monitor
 * do not wait child process exit
 */
static int execle_daemon(const char *psz_cmd, char **envp, pid_t *child_pid)
{
    pid_t pid;
    char exec[EXEC_MAX] = {0};
    char **args = NULL;
    int args_num;

    args_num = get_exec_and_args(psz_cmd, exec, &args);
    if (args_num < 0) {
        return ERROR_PARSE;
    }

    /* child process inherited the lock of the parent process, maybe deadlock,
    so don't operate lock between fork and execvp/execve */
    pid = fork();
    if (pid < 0) {
        log_printf(LOG_ERR, "execle_daemon: fork error [%d]", errno);
        free_args(args, args_num);
        return ERROR_FORK;
    } else if (pid == 0) {
        (void)setpgrp();
        (void)prctl(PR_SET_PDEATHSIG, SIGTERM);
        (void)close_all_fd();

        dup2_fd_in_child_process();

        if (envp == NULL) {
            (void)execvp(exec, args);
        } else {
            (void)execve(exec, args, envp);
        }

        exit(errno);
    }

    if (child_pid != NULL) {
        *child_pid = pid;
    }

    free_args(args, args_num);
    return 0;
}

/*
 * exec periodic monitor
 * wait child process to exit, exec cmd cannot timeout
 */
static int execle_periodic(str_custom *t)
{
    pid_t pid;
    int fd = -1;
    char exec[EXEC_MAX] = {0};
    char **args = NULL;
    int args_num;

    args_num = get_exec_and_args(t->start_cmd, exec, &args);
    if (args_num < 0) {
        return ERROR_PARSE;
    }

    pid = fork();
    if (pid < 0) {
        log_printf(LOG_ERR, "execle_periodic: fork error [%d]", errno);
        free_args(args, args_num);
        return ERROR_FORK;
    } else if (pid == 0) {
        (void)setpgrp();
        (void)prctl(PR_SET_PDEATHSIG, SIGTERM);
        (void)close_all_fd();

        fd = open("/dev/null", O_RDWR, 0);
        if (fd >= 0) {
            (void)dup2(fd, STDIN_FILENO);
            (void)dup2(fd, STDOUT_FILENO);
            (void)dup2(fd, STDERR_FILENO);
            if (fd > STDERR_FILENO) {
                (void)close(fd);
            }
        }

        if (t->envp == NULL) {
            (void)execvp(exec, args);
        } else {
            (void)execve(exec, args, t->envp);
        }

        exit(errno);
    }

    t->pid = pid;
    free_args(args, args_num);
    return 0;
}

/*
 * parse environment file specified by config and add system env
 */
static bool parse_env_file(str_custom *t)
{
    bool env_ret = false;
    unsigned int i;
    int ret;
    unsigned int len;

    env_ret = get_envp(t->enviroment_file, t->envp_config, &t->envp_config_count);
    if (env_ret != true) {
        return false;
    }

    /* get global environment variables number */
    for (i = 0; environ[i] != NULL; i++) {
    }
    t->envp = malloc((i + t->envp_config_count + 1) * sizeof(char *));
    if (t->envp == NULL) {
        log_printf(LOG_ERR, "malloc error.");
        return false;
    }

    ret = memcpy_s(t->envp, i * sizeof(char *), environ, i * sizeof(char *));
    if (ret != 0) {
        log_printf(LOG_ERR, "parse_env_file: memcpy_s t->envp failed, ret: %d", ret);
        return false;
    }

    if (t->envp_config_count != 0) {
        len = t->envp_config_count * sizeof(char *);
        ret = memcpy_s(t->envp + i, len, t->envp_config, len);
        if (ret != 0) {
            log_printf(LOG_ERR, "parse_env_file: memcpy_s t->envp + i failed, ret: %d", ret);
            return false;
        }
    }
    /* the last args of execl functions should be NULL */
    t->envp[i + t->envp_config_count] = NULL;
    return true;
}

static void check_to_add_list(str_custom *t, custom_type type)
{
    str_custom *ori_t = NULL;
    bool null_flag = true;
    bool is_new_cfg = true;
    struct list_head *head = (type == CUSTOM_DAEMON) ? &g_custom_daemon_head : &g_custom_periodic_head;

    list_for_each_entry(ori_t, head, list) {
        null_flag = false;
        if (ori_t != NULL && !strcmp(ori_t->conf_name, t->conf_name) &&
            ori_t->state != EXITING_STATE) {
            free_custom_t(&t);
            is_new_cfg = false;
            break;
        }
    }

    if (null_flag == true || is_new_cfg == true) {
        log_printf(LOG_INFO, "type[%s] conf_name[%s] is added to monitor list",
            g_custom_cfg_type[t->type - 1], t->conf_name);
        list_add(&t->list, head);
    }
}

static bool check_config(str_custom *t, const char *file_name, bool flag, custom_type type)
{
    int ret;

    if (flag == false || !strlen(t->start_cmd) || t->type == 0 ||
        (t->type == CUSTOM_PERIODIC && t->period == 0)) {
        free_custom_t(&t);
        return false;
    }

    if (t->type != type || t->monitor_switch == false) {
        free_custom_t(&t);
        return true;
    }

    if (strlen(t->enviroment_file) != 0) {
        if (parse_env_file(t) == false) {
            free_custom_t(&t);
            return false;
        }
    }

    ret = memcpy_s(t->conf_name, MAX_CFG_NAME_LEN, file_name, strlen(file_name));
    if (ret != 0) {
        log_printf(LOG_ERR, "check_config: memcpy_s t->conf_name failed, ret: %d", ret);
        free_custom_t(&t);
        return false;
    }

    check_to_add_list(t, type);

    return true;
}

/*
 * parse custom config
 */
static bool custom_parse_config(FILE *file, const char *file_name, custom_type type)
{
    str_custom *t = NULL;
    char config[MAX_CONFIG] = {0};
    bool flag = true;
    int ret;
    size_t len;

    t = malloc(sizeof(str_custom));
    if (t == NULL) {
        return false;
    }
    ret = memset_s(t, sizeof(str_custom), 0, sizeof(str_custom));
    if (ret != 0) {
        log_printf(LOG_ERR, "custom_parse_config: memset_s t failed, ret: %d", ret);
        free(t);
        return false;
    }
    t->state_index = -1;

    for (;;) {
        if (!fgets(config, MAX_CONFIG - 1, file)) {
            break;
        }

        len = strlen(config);
        if (len > 0 && config[len - 1] == '\n') {
            config[len - 1] = '\0';
        }

        if (parse_line(t, config) == false) {
            flag = false;
            break;
        }
    }

    return check_config(t, file_name, flag, type);
}

/*
 * load task from config
 */
static bool load_task(custom_type type, bool update)
{
    struct dirent *direntp = NULL;
    int config_fd = -1;
    FILE *fp = NULL;
    DIR *dir = NULL;
    char cfg_full_name[MAX_CFG_NAME_LEN + 18] = {0};    /* 18 is length if "/etc/sysmonitor.d/" */
    int ret;

    if (!update) {
        if (type == CUSTOM_DAEMON) {
            init_list_head(&g_custom_daemon_head);
        } else {
            init_list_head(&g_custom_periodic_head);
        }
    }

    dir = opendir(CUSTOM_CONFIG_DIR);
    if (dir == NULL) {
        log_printf(LOG_ERR, "load_task: %s not exist", CUSTOM_CONFIG_DIR);
        return false;
    }

    direntp = readdir(dir);
    while (direntp != NULL) {
        if (strlen(direntp->d_name) >= MAX_CFG_NAME_LEN) {
            log_printf(LOG_ERR, "load_task: config file name should be less than 128, file: %s",
                direntp->d_name);
            direntp = readdir(dir);
            continue;
        }
        ret = memset_s(cfg_full_name, sizeof(cfg_full_name), 0, sizeof(cfg_full_name));
        if (ret != 0) {
            log_printf(LOG_ERR, "load_task: memset_s cfg_full_name failed, ret: %d", ret);
            (void)closedir(dir);
            return false;
        }
        ret = snprintf_s(cfg_full_name, sizeof(cfg_full_name), sizeof(cfg_full_name) - 1,
            "%s%s", CUSTOM_CONFIG_DIR, direntp->d_name);
        if (ret == -1) {
            log_printf(LOG_ERR, "load_task: snprintf_s cfg_full_name failed, ret: %d", ret);
            (void)closedir(dir);
            return false;
        }

        fp = open_cfgfile(cfg_full_name, &config_fd);
        if (fp == NULL) {
            direntp = readdir(dir);
            continue;
        }
        if (custom_parse_config(fp, direntp->d_name, type) == false) {
            log_printf(LOG_ERR, "parse %s error", direntp->d_name);
        }
        (void)fclose(fp);
        direntp = readdir(dir);
    }

    (void)closedir(dir);
    return true;
}

/*
 * daemon process monitor
 */
static void monitor_daemon(struct list_head *head)
{
    str_custom *t = NULL;
    struct timespec ts;

    list_for_each_entry(t, head, list) {
        if (t != NULL && t->pid == 0) {
            (void)execle_daemon(t->start_cmd, t->envp, &t->pid);
            ts.tv_nsec = PROCESS_SLEEP_INTERVAL;
            ts.tv_sec = 0;
            (void)nanosleep(&ts, NULL);
        }
    }
}

/*
 * periodic process monitor
 */
static void monitor_periodic(void)
{
    str_custom *t = NULL;
    worker_task wtask = {0};
    struct timespec ts;
    int ret;

    list_for_each_entry(t, &g_custom_periodic_head, list) {
        if (t->state == EXITING_STATE) {
            continue;
        }
        ret = execle_periodic(t);
        if (ret == 0) {
            wtask.cpid = t->pid;
            wtask.time_count = 0;
            wtask.state = RUNNING_STATE;
            (void)worker_task_init(&wtask, &t->state_index);
            t->time_count = 0;
        } else {
            log_printf(LOG_INFO, "execle_periodic ret [%d] error", ret);
        }

        ts.tv_nsec = PROCESS_SLEEP_INTERVAL;
        ts.tv_sec = 0;
        (void)nanosleep(&ts, NULL);
    }
}

static bool check_cfg_exist_or_updated(const char *conf_name, const str_custom *del_task, str_custom *task)
{
    int ret;

    ret = memcpy_s(task->conf_name, MAX_CFG_NAME_LEN, conf_name, strlen(conf_name));
    if (ret != 0) {
        log_printf(LOG_ERR, "find_cfg_exist_or_updated: memcpy_s task.conf_name failed, ret: %d", ret);
        return false;
    }
    if (!strcmp(task->conf_name, del_task->conf_name)) {
        if (task->monitor_switch == del_task->monitor_switch && task->monitor_switch == true &&
            !strcmp(task->start_cmd, del_task->start_cmd) &&
            !strcmp(task->enviroment_file, del_task->enviroment_file) &&
            task->type == del_task->type && task->type == CUSTOM_DAEMON &&
            task->state != EXITING_STATE) {
            return true;
        }
    }

    return false;
}

/*
 * find same config in list
 */
static bool find_cfg_exist_or_updated(FILE *file, const char *conf_name, const str_custom *del_task)
{
    char config[MAX_CONFIG] = {0};
    str_custom task;
    int ret;

    ret = memset_s(&task, sizeof(task), 0, sizeof(task));
    if (ret) {
        log_printf(LOG_ERR, "find_cfg_exist_or_updated: memset_s task failed, ret: %d", ret);
        return false;
    }
    if (file == NULL || conf_name == NULL || del_task == NULL) {
        return false;
    }

    for (;;) {
        if (fgets(config, MAX_CONFIG - 1, file)) {
            (void)parse_line(&task, config);
            continue;
        }
        break;
    }

    return check_cfg_exist_or_updated(conf_name, del_task, &task);
}

static bool process_daemon_task_reload(str_custom *t, DIR *dir)
{
    struct dirent *direntp = NULL;
    char cfg_full_name[MAX_CFG_NAME_LEN + 18] = {0};    /* 18 is length of "/etc/sysmonitor.d/" */
    int config_fd = -1;
    bool find = false;
    FILE *fp = NULL;
    int ret;

    direntp = readdir(dir);
    while (direntp != NULL) {
        if (strlen(direntp->d_name) >= MAX_CFG_NAME_LEN) {
            log_printf(LOG_ERR, "reload_task: config file name should be less than 128, file: %s", direntp->d_name);
            direntp = readdir(dir);
            continue;
        }
        ret = memset_s(cfg_full_name, sizeof(cfg_full_name), 0, sizeof(cfg_full_name));
        if (ret != 0) {
            log_printf(LOG_ERR, "reload_task: memset_s cfg_full_name failed, ret: %d", ret);
            return false;
        }
        ret = snprintf_s(cfg_full_name, sizeof(cfg_full_name), sizeof(cfg_full_name) - 1,
            "%s%s", CUSTOM_CONFIG_DIR, direntp->d_name);
        if (ret == -1) {
            log_printf(LOG_ERR, "reload_task: snprintf_s cfg_full_name failed, ret: %d", ret);
            return false;
        }

        fp = open_cfgfile(cfg_full_name, &config_fd);
        if (fp == NULL) {
            direntp = readdir(dir);
            continue;
        }
        find = find_cfg_exist_or_updated(fp, direntp->d_name, t);
        (void)fclose(fp);
        if (find == true) {
            break;
        }
        direntp = readdir(dir);
    }

    if (find == false) {
        if (t->pid != 0) {
            (void)kill(-(t->pid), SIGTERM);
            t->state = EXITING_STATE;
        } else {
            list_del(&t->list);
            free_custom_t(&t);
        }
    }
    rewinddir(dir);
    return true;
}

/*
 * reload config
 * if reload config failed, then continue with old config, daemon process will not be killed
 * if daemon process config is same as old config, daemon process will not restart
 * if periodic process, config is same or not as old config, periodic process will restart
 * if reload config has new config items, then old process will be killed and custom task should be free
 */
static bool reload_task(custom_type type)
{
    str_custom *t = NULL;
    str_custom *ptr = NULL;
    struct list_head *head = NULL;
    DIR *dir = NULL;

    head = (type == CUSTOM_DAEMON) ? &g_custom_daemon_head : &g_custom_periodic_head;
    dir = opendir(CUSTOM_CONFIG_DIR);
    if (dir == NULL) {
        log_printf(LOG_ERR, "reload_task: %s not exist", CUSTOM_CONFIG_DIR);
        return false;
    }

    list_for_each_entry_safe(t, ptr, head, list) {
        if (type == CUSTOM_DAEMON) {
            if (process_daemon_task_reload(t, dir) == false) {
                (void)closedir(dir);
                return false;
            }
        } else {
            if (t->state != EXITING_STATE) {
                list_del(&t->list);
                free_custom_t(&t);
            }
        }
    }

    (void)closedir(dir);
    return load_task(type, true);
}

static void process_worker_task_running(str_custom *t, worker_task *wtask)
{
    int ret;
    int status;

    ret = waitpid(wtask->cpid, &status, WNOHANG);
    if (ret == 0) {
        (void)kill(-wtask->cpid, SIGTERM);
        wtask->state = EXITING_STATE;
        t->state = EXITING_STATE;
    } else {
        log_printf(LOG_INFO, "process_worker_task_running: waitpid error [%d] ", errno);
    }
}

static void process_worker_task_exiting(str_custom *t, worker_task *wtask)
{
    int ret;
    int status;

    ret = waitpid(wtask->cpid, &status, WNOHANG);
    if (ret == 0) {
        log_printf(LOG_INFO,
                   "process_worker_task_exiting: task[%d] process SIGTERM timeout, use SIGKILL.", wtask->cpid);
        (void)kill(-wtask->cpid, SIGKILL);
        (void)waitpid(wtask->cpid, &status, 0);
    }
    wtask->state = EXITED_STATE;
    t->state = EXITED_STATE;
}

/*
 * process periodic tasks
 * when reload config, process periodic tasks in the list
 * this has completion with thread monitor-worker
 * when task state is running, send SIGTERM to task
 * when task state is exiting, send SIGKILL to task and wait pid, free custom task
 * when task state is exited, clear task_queue info
 */
static void process_worker_task(void)
{
    str_custom *t = NULL;
    str_custom *n = NULL;
    int index;
    int ret;

    (void)sleep(1);    /* wait monitor-worker thread to recycke child process */

    (void)pthread_mutex_lock(&g_task_mtx);
    list_for_each_entry_safe(t, n, &g_custom_periodic_head, list) {
        index = t->state_index;
        if (index >= TASK_QUEUE_SIZE || index < 0) {
            log_printf(LOG_INFO, "process_worker_task: index[%d] error", index);
            continue;
        }
        if (g_task_queue[index].state == RUNNING_STATE) {
            process_worker_task_running(t, &g_task_queue[index]);
        } else if (g_task_queue[index].state == EXITING_STATE) {
            process_worker_task_exiting(t, &g_task_queue[index]);
            list_del(&t->list);
            free_custom_t(&t);
        }
        if (g_task_queue[index].state == EXITED_STATE) {
            ret = memset_s(&g_task_queue[index], sizeof(worker_task), 0, sizeof(worker_task));
            if (ret != 0) {
                log_printf(LOG_ERR, "process_worker_task: memset_s task_queue[%d] failed, ret: %d", index, ret);
                (void)pthread_mutex_unlock(&g_task_mtx);
                return;
            }
        }
    }
    (void)pthread_mutex_unlock(&g_task_mtx);
}

static void handle_daemon_task_exiting(str_custom *task)
{
    int status = 0;
    pid_t child_pid;

    child_pid = waitpid(task->pid, &status, WNOHANG);
    if (child_pid == 0) {
        log_printf(LOG_INFO, "task[%d] process SIGTERM timeout, use SIGKILL.", task->pid);
        (void)kill(-(task->pid), SIGKILL);
        (void)waitpid(task->pid, &status, 0);
    }
    list_del(&task->list);
    free_custom_t(&task);
}

static bool custom_parse_single_config_init(str_custom *t, FILE *file, custom_type type)
{
    char config[MAX_CONFIG] = {0};
    bool flag = true;

    if (t == NULL || file == NULL) {
        return false;
    }

    for (;;) {
        if (!fgets(config, MAX_CONFIG - 1, file)) {
            break;
        }
        if (parse_line(t, config) == false) {
            flag = false;
            break;
        }
    }

    if (flag == false || !strlen(t->start_cmd) || t->type == 0 ||
        (t->type == CUSTOM_PERIODIC && t->period == 0) ||
        t->monitor_switch == false || t->type != type) {
        return false;
    }
    return true;
}

/*
 * parse single config
 * if return false, we should free memory for t->envp_config and t->envp
 */
static bool custom_parse_single_config(FILE *file, custom_type type, str_custom *t)
{
    bool env_ret = false;
    int i;
    unsigned int len;
    int ret;

    env_ret = custom_parse_single_config_init(t, file, type);
    if (!env_ret) {
        return false;
    }

    /* before parse environment variables, we should free memory for envp_config and envp */
    free_custom_env(&t);
    /* get environment variables */
    if (strlen(t->enviroment_file) != 0) {
        env_ret = get_envp(t->enviroment_file, t->envp_config,
                           &t->envp_config_count);
        if (!env_ret) {
            return false;
        }

        /* get number of global environment variables */
        for (i = 0; environ[i] != NULL; i++) {}

        t->envp = malloc((i + t->envp_config_count + 1) * sizeof(char *));
        if (t->envp == NULL) {
            log_printf(LOG_INFO, "malloc error.");
            return false;
        }

        ret = memcpy_s(t->envp, i * sizeof(char *), environ, i * sizeof(char *));
        if (ret != EOK) {
            log_printf(LOG_ERR, "custom_parse_single_config memcpy_s error [%d]", ret);
            return false;
        }

        if (t->envp_config_count != 0) {
            len = t->envp_config_count * sizeof(char *);
            ret = memcpy_s(t->envp + i, len, t->envp_config, len);
            if (ret != EOK) {
                log_printf(LOG_ERR, "custom_parse_single_config memcpy_s envp_config error [%d]", ret);
                return false;
            }
        }

        t->envp[i + t->envp_config_count] = NULL; /* the last arg of execle must be NULL */
    }
    return true;
}

static bool reload_single_task(custom_type type, str_custom *t)
{
    int config_fd = -1;
    int ret;
    FILE *fp = NULL;
    char cfg_full_name[MAX_CFG_NAME_LEN + sizeof(CUSTOM_CONFIG_DIR)] = {0};

    if (t == NULL) {
        log_printf(LOG_INFO, "Custom process is NULL");
        return false;
    }

    ret = snprintf_s(cfg_full_name, sizeof(cfg_full_name), sizeof(cfg_full_name) - 1,
        "%s%s", CUSTOM_CONFIG_DIR, t->conf_name);
    if (ret < 0) {
        log_printf(LOG_ERR, "reload_single_task snprintf_s error [%d]", ret);
        return false;
    }

    fp = open_cfgfile(cfg_full_name, &config_fd);
    if (fp == NULL) {
        log_printf(LOG_INFO, "fail to open single config file %s.", cfg_full_name);
        return false;
    }

    if (custom_parse_single_config(fp, type, t) == false) {
        log_printf(LOG_INFO, "reload single config: parse %s error", t->conf_name);

        if (type != t->type) {
            log_printf(LOG_INFO, "single custom type is changed, reload sysmonitor");
            set_thread_item_reload_flag(CUSTOM_DAEMON_ITEM, true);
            set_thread_item_reload_flag(CUSTOM_PERIODIC_ITEM, true);
        }

        if (t->monitor_switch == false) {
            log_printf(LOG_INFO, "single custom monitor is switched off.");
        }

        (void)fclose(fp);
        return false;
    }

    (void)fclose(fp);
    return true;
}

static void handle_daemon_task_exit(str_custom *t, int status)
{
    int exit_code = 0;
    int ret;

    if (WIFEXITED(status)) {
        exit_code = WEXITSTATUS(status);
        if (exit_code != 0) {
            log_printf(LOG_WARNING, "custom daemon monitor: name[%s] execle start_cmd[%s] error[%d]",
                t->conf_name, t->start_cmd, exit_code);
        }
    }

    if (t->daemon_restart_times < FAIL_NUM) {
        t->daemon_restart_times++;
        log_printf(LOG_INFO, "custom daemon monitor: child process[%d] name %s exit code[%d], [%u] times.",
            t->pid, t->conf_name, exit_code, t->daemon_restart_times);
    }

    /* reload single task failed, delete from list and free task */
    ret = reload_single_task(CUSTOM_DAEMON, t);
    if (ret == false) {
        list_del(&t->list);
        free_custom_t(&t);
        return;
    }

    /* initialize the pid number to avoid other process using the number */
    t->pid = 0;
    ret = execle_daemon(t->start_cmd, t->envp, &t->pid);
    if (ret != 0) {
        log_printf(LOG_WARNING, "execle_daemon error[%d]", ret);
    }
}

static void handle_daemon_task_failed(str_custom *t, int err)
{
    int ret;

    log_printf(LOG_INFO, "custom daemon monitor: waitpid ret[%d] error", err);
    if (err == ECHILD) {
        t->pid = 0;
        ret = execle_daemon(t->start_cmd, t->envp, &t->pid);
        if (ret != 0) {
            log_printf(LOG_WARNING, "execle_daemon error[%d]", ret);
        }
    }
}

static void check_custom_daemon_monitor(void)
{
    str_custom *t = NULL;
    str_custom *n = NULL;
    int status = 0;
    pid_t child_pid;

    list_for_each_entry_safe(t, n, &g_custom_daemon_head, list) {
        if (t->pid == 0) {
            continue;
        }

        if (t->state == EXITING_STATE) {
            handle_daemon_task_exiting(t);
            continue;
        }
        child_pid = waitpid(t->pid, &status, WNOHANG);
        if (t->pid == child_pid) {
            handle_daemon_task_exit(t, status);
        } else if (child_pid < 0) {
            handle_daemon_task_failed(t, errno);
        } else if ((child_pid == 0 && (t->daemon_restart_times > 0 || !t->daemon_thread_start))) {
            t->daemon_restart_times = 0;
            t->daemon_thread_start = 1;
            log_printf(LOG_INFO, "custom daemon monitor: child process[%d] name %s started", t->pid, t->conf_name);
        }
    }
}

/*
 * daemon monitor start from here
 */
static void *custom_daemon_monitor_start(void *arg)
{
    bool ret = false;
    unsigned int period;
    int result;

    /* prctl does not return false if arg2 is right when arg1 is PR_SET_NAME */
    (void)prctl(PR_SET_NAME, "monitor-daemon");
    log_printf(LOG_INFO, "custom daemon monitor starting up");

    set_thread_item_reload_flag(CUSTOM_DAEMON_ITEM, false);
    (void)load_task(CUSTOM_DAEMON, false);
    period = (unsigned int)get_thread_item_period(CUSTOM_DAEMON_ITEM);
    log_printf(LOG_INFO, "custom daemon monitor, period:%u", period);
    result = set_thread_check_value(THREAD_CUSTOM_DAEMON_ITEM, true, period);
    if (result == -1) {
        log_printf(LOG_ERR, "custom daemon monitor set check flag or period error");
        return NULL;
    }
    monitor_daemon(&g_custom_daemon_head);

    for (;;) {
        if (get_thread_item_reload_flag(CUSTOM_DAEMON_ITEM)) {
            log_printf(LOG_INFO, "custom daemon monitor, start reload");
            set_thread_item_reload_flag(CUSTOM_DAEMON_ITEM, false);
            ret = reload_task(CUSTOM_DAEMON);
            if (ret == true) {
                monitor_daemon(&g_custom_daemon_head);
            } else {
                log_printf(LOG_INFO, "reload daemon custom monitor configuration failed");
            }
        }

        /* daemon process exit in exception */
        check_custom_daemon_monitor();

        result = feed_thread_status_count(THREAD_CUSTOM_DAEMON_ITEM);
        if (result == -1) {
            log_printf(LOG_ERR, "custom daemon monitor feed error");
            break;
        }
        /* daemon monitor interval is 10 seconds */
        (void)sleep(period);
    }
    return NULL;
}

static void check_and_exec_periodic(str_custom *t, int index, unsigned long count)
{
    worker_task wtask = {0};
    struct timespec ts;
    int ret;

    if (g_task_queue[index].state == EXITED_STATE &&
        ((count - t->time_count) >= t->period || t->pid == 0) &&
        t->state != EXITING_STATE) {
        t->pid = 0;
        ret = execle_periodic(t);
        if (ret == 0) {
            wtask.cpid = t->pid;
            wtask.time_count = 0;
            wtask.state = RUNNING_STATE;
            worker_task_add(&wtask, index);
            t->time_count = (unsigned int)count;
        } else {
            log_printf(LOG_INFO, "execle_periodic ret [%d] error", ret);
        }
        ts.tv_nsec = PROCESS_SLEEP_INTERVAL;
        ts.tv_sec = 0;
        (void)nanosleep(&ts, NULL);
    }
}

/*
 * periodic monitor start from here
 */
static void *custom_periodic_monitor_start(void *arg)
{
    str_custom *t = NULL;
    str_custom *n = NULL;
    unsigned long count = 0;
    int index;
    int ret;

    /* prctl does not return false if arg2 is right when arg1 is PR_SET_NAME */
    (void)prctl(PR_SET_NAME, "monitor-period");
    log_printf(LOG_INFO, "custom periodic monitor starting up");
    set_thread_item_reload_flag(CUSTOM_PERIODIC_ITEM, false);
    (void)load_task(CUSTOM_PERIODIC, false);
    ret = set_thread_check_value(THREAD_CUSTOM_PERIODIC_ITEM, true, CISTOM_PERIODIC_TIME);
    if (ret == -1) {
        log_printf(LOG_ERR, "custom periodic monitor set check flag or period error");
        return NULL;
    }
    monitor_periodic();

    for (;;) {
        if (get_thread_item_reload_flag(CUSTOM_PERIODIC_ITEM)) {
            log_printf(LOG_INFO, "custom periodic monitor, start reload");
            set_thread_item_reload_flag(CUSTOM_PERIODIC_ITEM, false);
            process_worker_task();
            (void)reload_task(CUSTOM_PERIODIC);
            monitor_periodic();
            count = 0;
        }

        list_for_each_entry_safe(t, n, &g_custom_periodic_head, list) {
            index = t->state_index;
            if (index >= TASK_QUEUE_SIZE || index < 0) {
                log_printf(LOG_INFO, "custom_periodic_monitor_start: index[%d] error", index);
                continue;
            }

            check_and_exec_periodic(t, index, count);
            if (t->state == EXITING_STATE && g_task_queue[index].state == EXITED_STATE) {
                list_del(&t->list);
                free_custom_t(&t);
            }
        }
        (void)sleep(1);
        count++;
        ret = feed_thread_status_count(THREAD_CUSTOM_PERIODIC_ITEM);
        if (ret == -1) {
            log_printf(LOG_ERR, "custom periodic monitor feed error");
            break;
        }
    }
    return NULL;
}

void custom_daemon_monitor_init(void)
{
    pthread_t tid;

    if (pthread_create(&tid, NULL, custom_daemon_monitor_start, NULL)) {
        log_printf(LOG_ERR, "create daemon custom monitor thread error [%d]", errno);
        return;
    }
    set_thread_item_tid(CUSTOM_DAEMON_ITEM, tid);
}

void custom_periodic_monitor_init(void)
{
    pthread_t tid;

    if (pthread_create(&tid, NULL, custom_periodic_monitor_start, NULL)) {
        log_printf(LOG_ERR, "create periodic custom monitor thread error [%d]", errno);
        return;
    }
    set_thread_item_tid(CUSTOM_PERIODIC_ITEM, tid);
}

static int worker_task_init(const worker_task *task, int *index)
{
    int i;
    unsigned int count = 0;
    int ret;

    (void)pthread_mutex_lock(&g_task_mtx);
    for (i = 0; i < TASK_QUEUE_SIZE; i++) {
        if (g_task_queue[i].cpid != 0) {
            count++;
        } else {
            break;
        }
    }

    if (count >= TASK_QUEUE_SIZE) {
        log_printf(LOG_INFO, "task queue is full! no index!");
        (void)pthread_mutex_unlock(&g_task_mtx);
        return -1;
    } else {
        *index = i;
        ret = memcpy_s(&g_task_queue[i], sizeof(worker_task), task, sizeof(worker_task));
        if (ret) {
            log_printf(LOG_ERR, "worker_task_init: memcpy_s task_queue failed, ret: %d", ret);
            (void)pthread_mutex_unlock(&g_task_mtx);
            return -1;
        }
    }

    (void)pthread_mutex_unlock(&g_task_mtx);
    return 0;
}

static void worker_task_add(const worker_task *task, int index)
{
    int ret;

    (void)pthread_mutex_lock(&g_task_mtx);
    if (index < TASK_QUEUE_SIZE && index >= 0) {
        ret = memcpy_s(&g_task_queue[index], sizeof(worker_task), task, sizeof(worker_task));
        if (ret) {
            log_printf(LOG_ERR, "worker_task_add: memcpy_s task_queue failed, ret: %d", ret);
        }
    }
    (void)pthread_mutex_unlock(&g_task_mtx);
}

static void handle_periodic_task_exiting(worker_task *task)
{
    pid_t pid;
    int status;
    int exit_code;

    pid = waitpid(task->cpid, &status, WNOHANG);
    if (task->cpid == pid) {
        task->cpid = 0;
        task->time_count = 0;
        task->state = EXITED_STATE;
        if (WIFEXITED(status)) {
            exit_code = WEXITSTATUS(status);
            if (exit_code != 0) {
                log_printf(LOG_WARNING, "worker_routine: periodic pid[%d] exec error[%d]",
                    pid, exit_code);
            }
        }
    } else if (pid == 0) {
        task->time_count++;
    } else {
        log_printf(LOG_INFO, "worker_routine: waitpid error [%d] ", errno);
        if (errno == ECHILD) {
            task->state = EXITED_STATE;
            task->cpid = 0;
            task->time_count = 0;
        }
    }

    if (task->time_count > WORKER_TASK_TIMEOUT) {
        log_printf(LOG_INFO, "execute periodic monitoring timeout [%d]", task->cpid);
        (void)kill(-task->cpid, SIGTERM);
        task->state = EXITING_STATE;
    }
}

static void handle_periodic_task_exit(worker_task *task)
{
    pid_t pid;
    int status;

    pid = waitpid(task->cpid, &status, WNOHANG);
    if (pid == 0) {
        log_printf(LOG_INFO, "task[%d] process SIGTERM timeout, use SIGKILL.", task->cpid);
        (void)kill(-task->cpid, SIGKILL);
        (void)waitpid(task->cpid, &status, 0);
    }
    task->state = EXITED_STATE;
    task->cpid = 0;
    task->time_count = 0;
}

/*
 * worker thread, check and waitpid for custom periodic task
 */
static void *worker_routine(void *arg)
{
    unsigned int i;

    /* prctl does not return false if arg2 is right when arg1 is PR_SET_NAME */
    (void)prctl(PR_SET_NAME, "monitor-worker");
    for (;;) {
        (void)pthread_mutex_lock(&g_task_mtx);
        for (i = 0; i < TASK_QUEUE_SIZE; i++) {
            if (g_task_queue[i].cpid == 0) {
                continue;
            }

            if (g_task_queue[i].state == RUNNING_STATE) {
                handle_periodic_task_exiting(&g_task_queue[i]);
            } else if (g_task_queue[i].state == EXITING_STATE) {
                handle_periodic_task_exit(&g_task_queue[i]);
            }
        }
        (void)pthread_mutex_unlock(&g_task_mtx);
        (void)sleep(1);
    }
    return NULL;
}

bool worker_task_struct_init(void)
{
    int ret;

    ret = memset_s(g_task_queue, sizeof(worker_task) * TASK_QUEUE_SIZE, 0,
        sizeof(worker_task) * TASK_QUEUE_SIZE);
    if (ret) {
        (void)printf("worker_task_struct_init: memset_s task_queue failed, ret: %d.", ret);
        return false;
    }
    return true;
}

/*
 * worker thread init, if custom periodic monitor is not enable
 * do not create worker thread
 */
bool worker_thread_init(pthread_t *tid)
{
    if (!get_thread_item_monitor_flag(CUSTOM_PERIODIC_ITEM)) {
        return true;
    }

    if (pthread_create(tid, NULL, worker_routine, NULL)) {
        log_printf(LOG_ERR, "create worker thread error [%d]", errno);
        return false;
    }

    return true;
}
