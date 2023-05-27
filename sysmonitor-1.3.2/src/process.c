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
 * Description: process monitor, process memory usage monitor
 * Author: xuchunmei
 * Create: 2016-1-1
 */
#include "process.h"

#include <unistd.h>
#include <dirent.h>

#include <securec.h>
#include "monitor_thread.h"

#define OUT_BUF_LEN 30
#define CMD_TIMEOUT 3
#define SERIAL_MONITOR 0
#define PARALLEL_MONITOR 1
/* The thread name is restricted to 16 characters, including the terminating  null  byte  ('\0'). */
#define THREAD_NAME_MAX_LENTH 16
#define PS_CONFIG_DIR "/etc/sysmonitor/process"
#define DELAY_TIME 300
#define DELAY_INTERVAL 3
#define THREAD_TIME 200
#define DEFAULT_USER "root"

#define MIN_PROCESS_RESTART_TIMEOUT 30
#define MAX_PROCESS_RESTART_TIMEOUT 300
#define MIN_RECALL_PERIOD 0
#define MAX_RECALL_PERIOD 1440

/* process recover failed, recall recover cmd period, unit: minute */
#define PS_RECALL_PERIOD 1

#define PS_N1_RECALL_STEP 2

static struct list_head g_head;
static unsigned int g_serial_task_num;
static bool g_can_ps_exit = true;
static bool g_flag_process_delay = true;    /* monitor process will check systemd status when flag sets true */
static int g_process_alarm_supress_num = 5;
static int g_process_restart_tiemout = DEFALUT_PROCESS_RESTART_TIMEOUT;
static int g_process_recall_period = PS_RECALL_PERIOD;

static void *ps_create_parallel_thread(void *arg);
typedef void (*PARSE_FUNC)(const char *item, const char *value, mtask *task);

struct item_value_func {
    char item[ITEM_LEN];
    void (*func)(const char *item, const char *value, mtask *task);
};

static void parse_monitor_period(const char *item, const char *value, mtask *task)
{
    (void)parse_value_int(item, value, &task->monitor_period);
}

static void parse_monitor_mode(const char *item, const char *value, mtask *task)
{
    if (!strcmp(value, "parallel")) {
        task->monitor_mode = PARALLEL_MONITOR;
    } else if (!strcmp(value, "serial")) {
        task->monitor_mode = SERIAL_MONITOR;
    } else {
        log_printf(LOG_INFO, "%s config illegal, check %s.", item, value);
    }
}

static void parse_monitor_check_as_param(const char *item, const char *value, mtask *task)
{
    (void)parse_value_bool(item, value, &task->chk_result_as_param);
}

static void parse_user(const char *item, const char *value, mtask *task)
{
    (void)parse_value_string(item, value, task->user, MAX_PS_CONFIG_VALUE);
}

static void parse_name(const char *item, const char *value, mtask *task)
{
    (void)parse_value_string(item, value, task->name, MAX_PS_CONFIG_VALUE);
}

static void parse_recover_command(const char *item, const char *value, mtask *task)
{
    (void)parse_value_string(item, value, task->recover_cmd, MAX_PS_CONFIG_VALUE);
}

static void parse_monitor_command(const char *item, const char *value, mtask *task)
{
    (void)parse_value_string(item, value, task->monitor_cmd, MAX_PS_CONFIG_VALUE);
}

static void parse_stop_command(const char *item, const char *value, mtask *task)
{
    (void)parse_value_string(item, value, task->stop_cmd, MAX_PS_CONFIG_VALUE);
}

static void parse_alarm_command(const char *item, const char *value, mtask *task)
{
    (void)parse_value_string(item, value, task->alarm_cmd, MAX_PS_CONFIG_VALUE);
}

static void parse_alarm_recover_command(const char *item, const char *value, mtask *task)
{
    (void)parse_value_string(item, value, task->alarm_recover_cmd, MAX_PS_CONFIG_VALUE);
}

static void parse_use_cmd_alarm(const char *item, const char *value, mtask *task)
{
    (void)parse_value_bool(item, value, &task->use_cmd_alarm);
}

static struct item_value_func g_ps_opt_array[] = {
    { "MONITOR_PERIOD", parse_monitor_period },
    { "MONITOR_MODE", parse_monitor_mode },
    { "CHECK_AS_PARAM", parse_monitor_check_as_param },
    { "USER", parse_user },
    { "NAME", parse_name },
    { "RECOVER_COMMAND", parse_recover_command },
    { "MONITOR_COMMAND", parse_monitor_command },
    { "STOP_COMMAND", parse_stop_command },
    { "ALARM_COMMAND", parse_alarm_command },
    { "ALARM_RECOVER_COMMAND", parse_alarm_recover_command },
    { "USE_CMD_ALARM", parse_use_cmd_alarm }
};

static char *strtrim(char *config, int length)
{
    char *end = NULL;
    char *sp = NULL;
    char *ep = NULL;
    int len;

    sp = config;
    end = config + length - 1;
    ep = end;

    while (sp <= end && (*sp == ' ' || *sp == '\t')) {
        sp++;
    }
    while (ep >= sp && (*ep == ' ' || *ep == '\t' || *ep == '\n')) {
        ep--;
    }
    len = (ep < sp) ? 0 : (int)(ep - sp) + 1;
    sp[len] = '\0';

    return sp;
}

static void free_monitor_list(void)
{
    mtask *n = NULL;
    mtask *t = NULL;

    list_for_each_entry_safe(t, n, &g_head, list) {
        list_del(&t->list);
        free(t);
    }
}

static bool get_value_from_config(const char *config, char *value, unsigned int value_len)
{
    int ret;
    size_t size;

    while (*config == ' ' || *config == '\t') {
        config++;
    }

    if (*config != '=') {
        return true;
    }

    config++;
    while (*config == ' ' || *config == '\t') {
        config++;
    }

    if (*config == '\0') {
        return true;
    }

    size = strlen(config);
    if (size >= value_len) {
        log_printf(LOG_ERR, "get_value_from_config: config size should be less than %u.", value_len);
        return false;
    }
    ret = strncpy_s(value, value_len, config, size);
    if (ret != 0) {
        log_printf(LOG_ERR, "get_value_from_config: strncpy_s value failed, ret: %d", ret);
        return false;
    }

    if (value[strlen(value) - 1] == '\n') {
        value[strlen(value) - 1] = '\0';
    }
    return true;
}

static bool parse_line(mtask *task, char *config, int length)
{
    char value[MAX_PS_CONFIG_VALUE] = {0};
    char item[ITEM_LEN] = {0};
    unsigned int i;
    int ret;
    PARSE_FUNC func = NULL;

    config = strtrim(config, length);
    /* # means comment */
    if (*config == '#') {
        return true;
    }

    if (check_conf_file_valid(config) == -1) {
        return false;
    }

    for (i = 0; i < array_size(g_ps_opt_array); i++) {
        if (strstr(config, g_ps_opt_array[i].item) == config) {
            config += strlen(g_ps_opt_array[i].item);
            ret = strcpy_s(item, ITEM_LEN - 1, g_ps_opt_array[i].item);
            if (ret) {
                log_printf(LOG_ERR, "parse_line: strcpy_s item failed, ret: %d.", ret);
                return false;
            }
            func = g_ps_opt_array[i].func;
            break;
        }
    }

    /*  Not match item, and return. */
    if (strlen(item) == 0) {
        return true;
    }

    if (get_value_from_config(config, value, sizeof(value)) == false) {
        return false;
    }

    if (strlen(value) == 0) {
        return true;
    }

    if (func != NULL) {
        func(item, value, task);
    }
    return true;
}

/*
 * check if process is exist
 * for systemd service, check with "systemctl status *.service | grep -w Active:"
 * for normal process, first use monitor_cmd to check, if check failed,
 * check if the process binary is exist
 */
static int check_process_exist(const mtask *t, bool check_binary)
{
    int ret;
    char tmp_cmd[MAX_PS_CONFIG_VALUE] = {0};
    bool systemd_service = false;

    if (check_binary) {
        ret = snprintf_s(tmp_cmd, sizeof(tmp_cmd), sizeof(tmp_cmd) - 1,
            "which %s > /dev/null 2>&1", t->name);
    } else {
        if (strstr(t->monitor_cmd, "systemctl") && strstr(t->monitor_cmd, "status")) {
            ret = snprintf_s(tmp_cmd, sizeof(tmp_cmd), sizeof(tmp_cmd) - 1,
                "%s | grep -w Active:", t->monitor_cmd);
            systemd_service = true;
        } else {
            ret = snprintf_s(tmp_cmd, sizeof(tmp_cmd), sizeof(tmp_cmd) - 1, "%s", t->monitor_cmd);
        }
    }

    if (ret == -1) {
        log_printf(LOG_ERR, "check_process_exist: snprintf_s for check command failed");
        return ret;
    }

    ret = monitor_cmd(DEFAULT_USER_ID, tmp_cmd, POPEN_TIMEOUT, NULL, true);
    if (ret == 0) {
        log_printf(LOG_INFO, "add %s to process monitor list", t->name);
    } else if (ret < 0) {
        log_printf(LOG_INFO, "execute %s error %d", tmp_cmd, ret);
    } else {
        if (systemd_service) {
            log_printf(LOG_INFO, "The service %s may not exist, please check", t->name);
        } else {
            if (!check_binary) {
                return check_process_exist(t, true);
            }
            log_printf(LOG_INFO, "The executable file %s may not exist in PATH, please check", t->name);
        }
    }

    return ret;
}

/*
 * check service exist, check twice, check internal is 2 seconds
 */
static bool check_service_exist(const mtask *t)
{
    int ret;
    int i;
    struct timespec ts;

    ts.tv_nsec = 0;
    ts.tv_sec = PROCESS_CHECK_TIME;

    for (i = 0; i < PROCESS_CHECK_NUM; i++) {
        ret = check_process_exist(t, false);
        if (ret == 0) {
            return true;
        } else if (ret < 0) {
            (void)nanosleep(&ts, NULL);
        } else {
            return false;
        }
    }
    log_printf(LOG_INFO, "add %s to process monitor list failed", t->name);
    return false;
}

static bool ps_check_config_illegal(mtask *task)
{
    int ret;
    struct passwd *usrinfo = NULL;

    if (!strlen(task->name) || !strlen(task->user)) {
        log_printf(LOG_INFO, "someitems is empty on process monitor! \"NAME:%s;USER:%s.\"",
            task->name, task->user);
        return false;
    }

    if (!strlen(task->monitor_cmd)) {
        ret = snprintf_s(task->monitor_cmd, MAX_PS_CONFIG_VALUE, MAX_PS_CONFIG_VALUE - 1,
            "pgrep -f $(which %s)", task->name);
        if (ret == -1) {
            log_printf(LOG_INFO, "ps_check_config_illegal: snprintf for monitor cmd failed.");
            return false;
        }
    }

    if (task->monitor_mode == PARALLEL_MONITOR && task->monitor_period == 0) {
        log_printf(LOG_INFO, "ps_check_config_illegal: MONITOR_PERIOD should not be 0 when MONITOR_MODE is parallel.");
        return false;
    }

    /* Check the user exists in the system */
    usrinfo = getpwnam((const char *)task->user);
    if (usrinfo == NULL) {
        log_printf(LOG_ERR, "error: user %s not exsit in system", task->user);
        return false;
    }

    task->uid = usrinfo->pw_uid;

    return true;
}

static bool ps_parse_config(FILE *file)
{
    mtask *t = NULL;
    bool config_ok = false;
    int ret;
    char config[MAX_CONFIG] = {0};

    t = malloc(sizeof(mtask));
    if (t == NULL) {
        return false;
    }

    ret = memset_s(t, sizeof(mtask), 0, sizeof(mtask));
    if (ret) {
        log_printf(LOG_ERR, "ps_parse_config: memset_s mtask failed, ret: %d.", ret);
        free(t);
        return false;
    }

    t->start = true;
    t->monitor_mode = SERIAL_MONITOR;
    /* Parallel monitor period is seted with global configure by default */
    t->monitor_period = (unsigned int)(get_thread_item_period(PS_ITEM));

    for (;;) {
        if (fgets(config, MAX_CONFIG, file)) {
            if (parse_line(t, config, (int)strlen(config)) == false) {
                free(t);
                return false;
            }
            continue;
        }
        break;
    }

    /*
     * even we do not set this configuration, use root permission instead
     */
    if (t->user[0] == '\0') {
        ret = strcpy_s(t->user, MAX_PS_CONFIG_VALUE, DEFAULT_USER);
        if (ret) {
            log_printf(LOG_ERR, "ps_parse_config: strcpy_s user failed, ret: %d.", ret);
            free(t);
            return false;
        }
    }

    config_ok = ps_check_config_illegal(t);
    if (config_ok == false) {
        free(t);
        return false;
    }

    if (check_service_exist(t)) {
        if (t->monitor_mode == PARALLEL_MONITOR) {
            if (pthread_create(&t->thread_id, NULL, ps_create_parallel_thread, t)) {
                log_printf(LOG_ERR, "create process monitor thread error [%d]", errno);
                free(t);
                return false;
            }
        }
        if (t->monitor_mode == SERIAL_MONITOR)
            g_serial_task_num++;

        list_add(&t->list, &g_head);
        return true;
    }

    free(t);
    return true;
}

static DIR *open_cfgdir(void)
{
    struct stat sb;
    DIR *dir = NULL;
    int ret;

    dir = opendir(PS_CONFIG_DIR);
    if (dir == NULL) {
        log_printf(LOG_WARNING, "%s not exist", PS_CONFIG_DIR);
        return NULL;
    }

    ret = memset_s(&sb, sizeof(sb), 0, sizeof(sb));
    if (ret != 0) {
        log_printf(LOG_WARNING, "open_cfgdir: memset_s sb failed, ret: %d.", ret);
        (void)closedir(dir);
        return NULL;
    }
    if (stat(PS_CONFIG_DIR, &sb) < 0) {
        log_printf(LOG_WARNING, "stat %s error [%d]", PS_CONFIG_DIR, errno);
        (void)closedir(dir);
        return NULL;
    }
    /* config file mode should be 700 */
    if (sb.st_mode & (S_IRWXG | S_IRWXO)) {
        log_printf(LOG_WARNING, "%s: bad file mode", PS_CONFIG_DIR);
        (void)closedir(dir);
        return NULL;
    }
    if (chdir(PS_CONFIG_DIR) != 0) {
        log_printf(LOG_WARNING, "chdir error [%d]", errno);
        (void)closedir(dir);
        return NULL;
    }

    return dir;
}

/* read the config file to load all task needed to be monitor */
static bool load_task(void)
{
    struct dirent *direntp = NULL;
    int config_fd = -1;
    FILE *fp = NULL;
    DIR *dir = NULL;

    init_list_head(&g_head);

    dir = open_cfgdir();
    if (dir == NULL) {
        return false;
    }

    g_serial_task_num = 0;
    direntp = readdir(dir);
    while (direntp != NULL) {
        fp = open_cfgfile(direntp->d_name, &config_fd);
        if (fp == NULL) {
            direntp = readdir(dir);
            continue;
        }
        if (ps_parse_config(fp) == false) {
            log_printf(LOG_INFO, "parse %s error", direntp->d_name);
        }
        (void)fclose(fp);
        direntp = readdir(dir);
    }

    (void)closedir(dir);
    return true;
}

/* recover the task if the task is abnormal */
static void recover_task(int chk_ret_code, const mtask *task)
{
    char recover_cmd[MAX_CONFIG];
    int ret;

    if (task->chk_result_as_param == true) {
        ret = snprintf_s(recover_cmd, MAX_CONFIG,
            MAX_CONFIG - 1, "%s %d", task->recover_cmd, chk_ret_code);
    } else {
        ret = snprintf_s(recover_cmd, MAX_CONFIG, MAX_CONFIG - 1, "%s", task->recover_cmd);
    }

    if (ret == -1) {
        log_printf(LOG_ERR, "recover_task: snprintf_s recover cmd failed.");
        return;
    }

    ret = monitor_cmd(task->uid, recover_cmd, g_process_restart_tiemout,
        task->stop_cmd, false);
    if (ret != 0) {
        log_printf(LOG_INFO, "use \"%s\" recover failed,errno %d", recover_cmd, ret);
    }
}

static void check_task_report_alarm_by_cmd(mtask *task)
{
    int ret;

    if ((int)task->fail % g_process_alarm_supress_num != 0) {
        return;
    }

    if (!strlen(task->alarm_cmd)) {
        log_printf(LOG_INFO, "%s is abnormal %d times, But alarm-cmd is null,will not alarm[warn]",
            task->name, g_process_alarm_supress_num);
    } else {
        ret = monitor_cmd(task->uid, task->alarm_cmd, POPEN_TIMEOUT, NULL, false);
        if (ret == 0) {
            log_printf(LOG_INFO, "%s is abnormal %d times, use cmd \"%s\" to alarm", task->name,
                g_process_alarm_supress_num, task->alarm_cmd);
        } else {
            log_printf(LOG_INFO, "%s is abnormal %d times, use cmd \"%s\" to alarm failed,errno [%d]",
                task->name, g_process_alarm_supress_num, task->alarm_cmd, ret);
        }
    }
}

static void check_task_report_recover(mtask *task)
{
    int ret;

    task->fail = 0;
    if (!strlen(task->alarm_recover_cmd)) {
        log_printf(LOG_INFO, "%s is recovered, But recover-cmd is null,will not alarm[warn]", task->name);
    } else {
        ret = monitor_cmd(task->uid, task->alarm_recover_cmd, POPEN_TIMEOUT, NULL, false);
        if (ret == 0) {
            task->resend_recover_cmd = false;
            log_printf(LOG_INFO, "%s is recovered, use \"%s\" to alarm", task->name, task->alarm_recover_cmd);
        } else {
            task->resend_recover_cmd = true;
            log_printf(LOG_INFO, "%s is recovered, use \"%s\" to alarm faied, errno [%d]",
                task->name, task->alarm_recover_cmd, ret);
        }
    }
}

static int process_monitor_cmd(const mtask *task)
{
    char tmp[MAX_PS_CONFIG_VALUE] = {0};
    int ret;
    bool bash_cmd = false;

    ret = snprintf_s(tmp, MAX_PS_CONFIG_VALUE, MAX_PS_CONFIG_VALUE - 1, "pgrep -f $(which %s)", task->name);
    if (ret == -1) {
        log_printf(LOG_ERR, "process_monitor_cmd: snprintf_s for monitor command failed.");
        return -1;
    }

    if (strcmp(task->monitor_cmd, tmp) == 0) {
        bash_cmd = true;
    }

    return monitor_cmd(task->uid, task->monitor_cmd, POPEN_TIMEOUT, NULL, bash_cmd);
}

static void handle_task_monitor_failed_cmd(mtask *task, int monitor_ret)
{
    task->resend_recover_cmd = false;
    task->fail++;
    if (strlen(task->recover_cmd)) {
        log_printf(LOG_WARNING, "%s is abnormal, check cmd return %d, use \"%s\" to recover",
            task->name, monitor_ret, task->recover_cmd);
        recover_task(monitor_ret, task);
        if (!process_monitor_cmd(task)) {
            check_task_report_recover(task);
            return;
        }
    } else {
        log_printf(LOG_WARNING, "%s is abnormal, check cmd return %d, recover cmd is null, will not recover",
            task->name, monitor_ret);
    }

    check_task_report_alarm_by_cmd(task);

    if (task->fail == 0xffffffff) {
        task->fail = 0x1;
    }
}

static void handle_task_report_recover_cmd(mtask *task)
{
    if (task->resend_recover_cmd || task->start || task->fail > 0) {
        check_task_report_recover(task);
    }
}

/*
 * Check process status.
 * Repo alarm by alarm cmd (configure by /etc/sysmonitor/process/XXX) when process is recovered
 */
static void check_task_repo_cmd(mtask *task)
{
    int ret;

    ret = process_monitor_cmd(task);
    if (ret > 0) {
        handle_task_monitor_failed_cmd(task, ret);
    } else if (ret < 0) {
        log_printf(LOG_ERR, "execute MONITOR_COMMAND[%s] error [%d]", task->monitor_cmd, ret);
        task->fail++;
        task->start = false;
        return;
    } else {
        handle_task_report_recover_cmd(task);
    }

    task->start = false;
}

static void clean_task_abnormal_info(mtask *task)
{
    task->fail = 0;
    task->time_count = 0;
    task->n1_recall = 0;
    task->n2_recall = 0;
}

/*
 * after recover failed for FAIL_NUM times, recover interval increases
 * when task->fail < FAIL_NUM, recover every mon_period, defalut is 3s
 * when task->fail = FAIL_NUM, report task abnormal alarm
 * when task->fail > FAIL_NUM, use task->time_count to calculate recover period
 * task->fail > FAIL_NUM: recover period increases like this:
 * 2 mon_peirod (6s), 3 mon_period (9s), 4 mon_period (12s), 5 mon_period (15s)
 * 6 mon_peirod (18s)
 * after n1_recall, defalut is 1 minute, recover every minute.
 */
static void handle_task_recover_extend(mtask *task, int monitor_ret)
{
    unsigned int mon_period;

    if (!strlen(task->recover_cmd)) {
        log_printf(LOG_INFO, "%s is abnormal, check cmd return %d, recover cmd is null, will not recover",
            task->name, monitor_ret);
        return;
    }

    if (task->monitor_mode == PARALLEL_MONITOR) {
        mon_period = task->monitor_period;
    } else {
        mon_period = (unsigned int)get_thread_item_period(PS_ITEM);
    }

    task->time_count++;
    if ((task->time_count == (task->n1_recall + 1) * (task->n1_recall + PS_N1_RECALL_STEP) / PS_N1_RECALL_STEP) &&
        (task->time_count * mon_period <= (unsigned int)g_process_recall_period * 60)) {
        log_printf(LOG_INFO, "%s is abnormal, check cmd return %d, use \"%s\" to recover",
            task->name, monitor_ret, task->recover_cmd);
        recover_task(monitor_ret, task);
        task->n1_recall++;
    } else if (task->time_count * mon_period >= (unsigned int)g_process_recall_period * 60 * (task->n2_recall + 1)) {
        log_printf(LOG_INFO, "%s is abnormal, check cmd return %d, use \"%s\" to recover",
            task->name, monitor_ret, task->recover_cmd);
        recover_task(monitor_ret, task);
        task->n2_recall++;
    }
}

static void handle_task_alarm(mtask *task, int monitor_ret)
{
    log_printf(LOG_INFO, "%s is abnormal, check cmd return %d", task->name, monitor_ret);

    task->fail++;
    task->start = false;
}

static void handle_task_report_recover(mtask *task)
{
    clean_task_abnormal_info(task);
    task->start = false;

    log_printf(LOG_INFO, "%s is recovered", task->name);
}

static void handle_task_check_failed_pri(mtask *task, int monitor_ret)
{
    int ret;

    task->fail++;
    if (!strlen(task->recover_cmd)) {
        log_printf(LOG_INFO, "%s is abnormal, check cmd return %d, recover cmd is null, will not recover",
            task->name, monitor_ret);
        return;
    }

    log_printf(LOG_INFO, "%s is abnormal, check cmd return %d, use \"%s\" to recover",
        task->name, monitor_ret, task->recover_cmd);
    recover_task(monitor_ret, task);
    ret = process_monitor_cmd(task);
    if (ret == 0) {
        if (task->start) {
            handle_task_report_recover(task);
            return;
        }
        clean_task_abnormal_info(task);
        log_printf(LOG_INFO, "%s is recovered", task->name);
    }
}

static void handle_task_monitor_failed(mtask *task, int monitor_ret)
{
    if (task->fail < FAIL_NUM) {
        handle_task_check_failed_pri(task, monitor_ret);
    } else if (task->fail == FAIL_NUM) {
        handle_task_alarm(task, monitor_ret);
    } else {
        handle_task_recover_extend(task, monitor_ret);
    }
}

/*
 * Check process status. Repo alarm by sysalarm service when process is recoverd.
 */
static void check_task_repo_alarm(mtask *task)
{
    int ret;

    ret = process_monitor_cmd(task);
    if (ret > 0) {
        handle_task_monitor_failed(task, ret);
    } else if (ret < 0) {
        log_printf(LOG_ERR, "execute MONITOR_COMMAND[%s] error [%d]", task->monitor_cmd, ret);
    } else if ((!ret && task->fail > 0) || (!ret && task->start)) {
        handle_task_report_recover(task);
    }
}

/* check if the task is abnormal */
static void check_task(mtask *task)
{
    if (task->use_cmd_alarm == false) {
        check_task_repo_alarm(task);
    } else {
        check_task_repo_cmd(task);
    }
}

static int ps_parallel_check_task(long *exe_time, mtask *task, const char *tname)
{
    int ret;
    struct timespec time_start;
    struct timespec time_end;

    if (*exe_time >= (long)task->monitor_period) {
        if (clock_gettime(CLOCK_MONOTONIC, &time_start) != 0) {
            log_printf(LOG_ERR, "get clock time faild,monitor %s thread will exit", tname);
            return RET_BREAK;
        }

        check_task(task);

        if (clock_gettime(CLOCK_MONOTONIC, &time_end) != 0) {
            log_printf(LOG_ERR, "get clock time faild,monitor %s thread will exit", tname);
            return RET_BREAK;
        }

        *exe_time = time_end.tv_sec - time_start.tv_sec;
        if (*exe_time >= (long)task->monitor_period) {
            ret = feed_thread_ps_parallel_count(THREAD_PS_PARALLEL_ITEM, task->thread_id);
            if (ret == -1) {
                return RET_BREAK;
            }
            return RET_CONTINUE;
        }
    }
    ret = feed_thread_ps_parallel_count(THREAD_PS_PARALLEL_ITEM, task->thread_id);
    if (ret == -1) {
        return RET_BREAK;
    }
    *exe_time += 1;
    return RET_SUCCESS;
}

static void *ps_create_parallel_thread(void *arg)
{
    char tname[THREAD_NAME_MAX_LENTH] = {0};
    mtask *task = arg;
    long exe_time = (long)task->monitor_period;
    int ret;
    char *tmp = NULL;
    unsigned int period;

    ret = pthread_detach(pthread_self());
    if (ret) {
        log_printf(LOG_ERR, "ps_create_parallel_thread: pthread_detach failed, ret: %d.", ret);
        return NULL;
    }

    tmp = task->name;
    if (strlen(task->name) >= THREAD_NAME_MAX_LENTH) {
        tmp = task->name + strlen(task->name) - THREAD_NAME_MAX_LENTH + 1;
    }

    ret = strncpy_s(tname, sizeof(tname), tmp, sizeof(tname) - 1);
    if (ret) {
        log_printf(LOG_ERR, "ps_create_parallel_thread: strncpy_s tname failed, ret: %d.", ret);
        return NULL;
    }
    (void)prctl(PR_SET_NAME, tname);
    period = POPEN_TIMEOUT * PARALLEL_POPEN_TIMEOUT_NUM + (unsigned int)g_process_restart_tiemout + 1;
    ret = set_ps_parallel_check_value(THREAD_PS_PARALLEL_ITEM, true, task->thread_id, period);
    if (ret == -1) {
        log_printf(LOG_ERR, "ps create parallel thread: set check flag or period failed");
        return NULL;
    }

    for (;;) {
        if (get_thread_item_reload_flag(PS_ITEM) && g_can_ps_exit == true) {
            break;
        }

        ret = ps_parallel_check_task(&exe_time, task, tname);
        if (ret == RET_BREAK) {
            break;
        } else if (ret == RET_SUCCESS) {
            (void)sleep(1);
        }
    }
    ret = set_ps_parallel_check_flag(THREAD_PS_PARALLEL_ITEM, false, task->thread_id);
    if (ret == -1) {
        log_printf(LOG_ERR, "ps create parallel thread exit, set check flag failed");
    }
    task->thread_id = 0;
    return NULL;
}

/* run the queue to check all the task in the list */
static void serial_monitor_runqueue(void)
{
    mtask *t = NULL;
    mtask *n = NULL;
    struct timespec ts;

    ts.tv_nsec = PROCESS_SLEEP_INTERVAL;
    ts.tv_sec = 0;

    list_for_each_entry(t, &g_head, list) {
        if (t->monitor_mode == SERIAL_MONITOR) {
            check_task(t);
            (void)nanosleep(&ts, NULL);
        }
    }

    list_for_each_entry_safe(t, n, &g_head, list) {
        if (t->monitor_mode == PARALLEL_MONITOR && t->thread_id == 0) {
            list_del(&t->list);
            free(t);
        }
    }
}

static bool reload_task(void)
{
    mtask *t = NULL;
    bool all_parallel_thread_exit = false;
    bool ret = false;

    /*
     * Waiting for all parallel monitoring thread to exit.
     * Notes: There is not needed to free list, pthread will exit and free list when receive reload-signal.
     * Related func: ps_create_parallel_thread().
     */
    for (;;) {
        all_parallel_thread_exit = true;
        list_for_each_entry(t, &g_head, list) {
            if (t->monitor_mode == PARALLEL_MONITOR && t->thread_id != 0) {
                all_parallel_thread_exit = false;
                (void)sleep(1);
                break;
            }
        }

        if (all_parallel_thread_exit == true) {
            break;
        }
    }

    set_thread_item_reload_flag(PS_ITEM, false);
    /* Free serial-moitor list */
    free_monitor_list();

    g_can_ps_exit = false;
    ret = load_task();
    return ret;
}

static void check_system_state(void)
{
    char *cmd = "systemctl is-system-running";
    char out[OUT_BUF_LEN] = {0};
    int i = 0;

    if (get_log_interface_flag() == DAEMON_SYSLOG && g_flag_process_delay == true) {
        for (;;) {
            (void)monitor_popen(cmd, out, sizeof(out) - 1, CMD_TIMEOUT, NULL);
            if (strstr(out, "running") || strstr(out, "degraded")) {
                break;
            }

            (void)sleep(DELAY_INTERVAL);
            i++;
            if (i >= DELAY_TIME / DELAY_INTERVAL) {
                log_printf(LOG_INFO, "wait system running over %d seconds. break!", DELAY_TIME);
                break;
            }
        }
    }
}

static unsigned int get_process_check_period(void)
{
    unsigned int period;
    period = POPEN_TIMEOUT * POPEN_TIMEOUT_NUM + PROCESS_CHECK_NUM * PROCESS_CHECK_TIME +
        (unsigned int)get_thread_item_period(PS_ITEM) + (unsigned int)g_process_restart_tiemout + PROCESS_OTHER_TIME;
    return period;
}

static void *ps_monitor_start(void *arg)
{
    bool ret = false;
    struct timespec ts;
    int time_reduce;
    unsigned int period;
    int result;

    /* prctl does not return false if arg2 is right when arg1 is PR_SET_NAME */
    (void)prctl(PR_SET_NAME, "monitor-process");
    log_printf(LOG_INFO, "process monitor starting up");
    check_system_state();
    log_printf(LOG_INFO, "process monitor started");

    set_thread_item_reload_flag(PS_ITEM, false);
    period = get_process_check_period();
    result = set_thread_check_value(THREAD_PS_ITEM, true, period);
    if (result == -1) {
        log_printf(LOG_ERR, "process monitor set check flag or period error");
        return NULL;
    }
    log_printf(LOG_INFO, "process monitor, period:%u", period);
    ret = load_task();
    for (;;) {
        if (get_thread_item_reload_flag(PS_ITEM)) {
            log_printf(LOG_INFO, "process monitor, start reload");
            ret = reload_task();
            if (ret == false) {
                log_printf(LOG_INFO, "reload process monitor configuration failed");
            }

            g_can_ps_exit = true;
            log_printf(LOG_INFO, "reload process monitor end");
        }

        if (ret == true) {
            serial_monitor_runqueue();
        }

        /* time_reduce unit: ms */
        time_reduce = get_thread_item_period(PS_ITEM) * 1000 - THREAD_TIME * (int)g_serial_task_num;
        if (time_reduce > 0) {
            ts.tv_nsec = (time_reduce % 1000) * 1000 * 1000;
            ts.tv_sec = time_reduce / 1000;
            (void)nanosleep(&ts, NULL);
        }
        result = feed_thread_status_count(THREAD_PS_ITEM);
        if (result == -1) {
            log_printf(LOG_ERR, "process monitor feed error");
            break;
        }
    }
    return NULL;
}

void ps_monitor_init(void)
{
    pthread_t tid;

    if (pthread_create(&tid, NULL, ps_monitor_start, NULL)) {
        log_printf(LOG_ERR, "create process monitor thread error [%d]", errno);
        return;
    }
    set_thread_item_tid(PS_ITEM, tid);
}

bool parse_process_monitor_delay(const char *item, const char *value)
{
    if (!strcmp(value, "off")) {
        g_flag_process_delay = false;
    } else if (strcmp(value, "on")) {
        log_printf(LOG_INFO, "%s set error", item);
        return false;
    }
    return true;
}

bool parse_process_alarm_supress(const char *value)
{
    g_process_alarm_supress_num = (int)strtol(value, NULL, STRTOL_NUMBER_BASE);
    if (check_int(value) == false || g_process_alarm_supress_num <= 0) {
        log_printf(LOG_INFO, "PROCESS_ALARM_SUPRESS_NUM set error");
        return false;
    }
    return true;
}

bool parse_process_restart_tiemout(const char *value)
{
    g_process_restart_tiemout = (int)strtol(value, NULL, STRTOL_NUMBER_BASE);
    if (check_int(value) == false ||
        g_process_restart_tiemout < MIN_PROCESS_RESTART_TIMEOUT ||
        g_process_restart_tiemout > MAX_PROCESS_RESTART_TIMEOUT) {
        log_printf(LOG_INFO, "PROCESS_RESTART_TIMEOUT set error,  the value must between %d and %d",
            MIN_PROCESS_RESTART_TIMEOUT, MAX_PROCESS_RESTART_TIMEOUT);
        return false;
    }
    return true;
}

bool parse_process_recall_period(const char *value)
{
    g_process_recall_period = (int)strtol(value, NULL, STRTOL_NUMBER_BASE);
    if (check_int(value) == false || g_process_recall_period <= MIN_RECALL_PERIOD ||
        g_process_recall_period > MAX_RECALL_PERIOD) {
        log_printf(LOG_INFO, "PROCESS_RECALL_PERIOD set error");
        return false;
    }
    return true;
}
