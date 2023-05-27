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
 * Description: Monitor the zombie process number
 * Author: Suo Ben <suoben@huawei.com>
 * Create: 2016-5-27
 */

#include "zombie.h"

#include <unistd.h>
#include <securec.h>

#include "common.h"
#include "monitor_thread.h"

#define ZOMBIE_EXTDES      "zombie process count"
#define MAX_MONITORCOMMAND 4096
#define BUF_LEN            100

static unsigned long g_alarm_cnt = 500;
static unsigned long g_resume_cnt = 400;
static int g_thread_start = 1;

struct item_value_func {
    char item[ITEM_LEN];
    bool (*func)(const char *item, const char *value);
};

static bool parse_zombie_alarm(const char *item, const char *value)
{
    return parse_value_ulong(item, value, &g_alarm_cnt);
}

static bool parse_zombie_resume(const char *item, const char *value)
{
    return parse_value_ulong(item, value, &g_resume_cnt);
}

static bool parse_zombie_period(const char *item, const char *value)
{
    unsigned int period;
    bool ret = false;

    ret = parse_value_int(item, value, &period);
    if (ret) {
        set_thread_item_period(ZOMBIE_ITEM, (int)period);
    }
    return ret;
}

static const struct item_value_func g_item_array[] = {
    { "ALARM", parse_zombie_alarm },
    { "RESUME", parse_zombie_resume },
    { "PERIOD", parse_zombie_period }
};

static bool parse_line(const char *config)
{
    char item[ITEM_LEN] = {0};
    char value[VALUE_LEN] = {0};
    char *ptr = NULL;
    unsigned int size;
    unsigned int i;
    errno_t rc;

    while (*config == ' ' || *config == '\t') {
        config++;
    }

    if (*config == '#') {
        return true;
    }

    ptr = strstr(config, "=\"");
    if (ptr == NULL) {
        return true;
    }

    size = (unsigned int)(ptr - config);
    size = size < (unsigned int)sizeof(item) ? size : (unsigned int)sizeof(item) - 1;
    rc = strncpy_s(item, sizeof(item), config, size);
    if (rc != EOK) {
        log_printf(LOG_ERR, "parse_line strncpy_s error [%d]", rc);
        return false;
    }

    get_value(config, size, value, sizeof(value));
    if (!strlen(value)) {
        return true;
    }

    for (i = 0; i < array_size(g_item_array); i++) {
        if (strcmp(item, g_item_array[i].item) == 0 && g_item_array[i].func != NULL) {
            return g_item_array[i].func(item, value);
        }
    }

    return true;
}

static void zombie_get_parent_process(void)
{
    char cmd[MAX_MONITORCOMMAND] = {0};
    char ppid_buf[MAX_TEMPSTR] = {0};
    errno_t rc;

    rc = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "/usr/libexec/sysmonitor/getzombieparent.py");
    if (rc < 0) {
        log_printf(LOG_ERR, "zombie_get_parent_process snprintf_s error [%d]", rc);
        return;
    }

    if (monitor_popen(cmd, ppid_buf, sizeof(ppid_buf), POPEN_TIMEOUT, NULL)) {
        log_printf(LOG_INFO, "failed to get zombie process info");
        return;
    }

    ppid_buf[MAX_TEMPSTR - 1] = '\0';
}

static bool get_zombie_process(unsigned long *cnt)
{
    char cmd[MAX_MONITORCOMMAND] = {0};
    char cnt_buf[BUF_LEN] = {0};
    errno_t rc;

    rc = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1,
                    "ps -A -o stat,ppid,pid,cmd | grep -e '^[Zz]' | awk '{print $0}' | wc -l");
    if (rc < 0) {
        log_printf(LOG_ERR, "monitor_zombie snprintf_s error [%d]", rc);
        return false;
    }
    if (monitor_popen(cmd, cnt_buf, sizeof(cnt_buf), POPEN_TIMEOUT, NULL)) {
        log_printf(LOG_ERR, "failed to get zombie process count");
        return false;
    }

    cnt_buf[BUF_LEN - 1] = '\0';
    *cnt = strtoul(cnt_buf, NULL, 0);
    if (errno == EINVAL || errno == ERANGE) {
        log_printf(LOG_ERR, "process count is wrong");
        return false;
    }

    return true;
}

static void monitor_zombie(bool *status)
{
    unsigned long cnt;
    bool execute_result = false;

    execute_result = get_zombie_process(&cnt);
    if (!execute_result) {
        return;
    }

    if (cnt >= g_alarm_cnt && *status == false) {
        log_printf(LOG_WARNING, "zombie process count alarm: %lu (alarm: %lu, resume: %lu)",
            cnt, g_alarm_cnt, g_resume_cnt);
        *status = true;
        zombie_get_parent_process();
    } else if ((cnt <= g_resume_cnt && *status == true) || (cnt <= g_resume_cnt && g_thread_start)) {
        log_printf(LOG_INFO, "zombie process count resume: %lu (alarm: %lu, resume: %lu)",
            cnt, g_alarm_cnt, g_resume_cnt);
        *status = false;
    }
    g_thread_start = 0;

    return;
}

static int zombie_parse_config(void)
{
    bool ret = false;
    int period;
    int result;

    ret = parse_config(ZOMBIE_CONF, parse_line);
    period = get_thread_item_period(ZOMBIE_ITEM);
    set_thread_item_reload_flag(ZOMBIE_ITEM, false);
    if ((ret == false) || (g_alarm_cnt <= g_resume_cnt || period <= 0)) {
        log_printf(LOG_ERR,
            "zombie process monitor: configuration illegal, alarm is %lu, resume is %lu, period is %d",
            g_alarm_cnt, g_resume_cnt, period);
        ret = false;
        result = set_thread_status_check_flag(THREAD_ZOMBIE_ITEM, false);
        if (result == -1) {
            log_printf(LOG_ERR, "reload zombie monitor set check flag error");
            return RET_BREAK;
        }
    }
    if (ret) {
        clear_thread_status(THREAD_ZOMBIE_ITEM);
        result = set_thread_check_value(THREAD_ZOMBIE_ITEM, true, (unsigned int)period);
        if (result == -1) {
            log_printf(LOG_ERR, "zombie monitor set check flag or period error");
            return RET_BREAK;
        }
        return RET_SUCCESS;
    }

    return RET_CONTINUE;
}

static void *zombie_monitor_start(void *arg)
{
    bool failed = false;
    int result = -1;
    log_printf(LOG_INFO, "zombie monitor starting up");

    for (;;) {
        if (get_thread_item_reload_flag(ZOMBIE_ITEM)) {
            log_printf(LOG_INFO, "zombie monitor, start reload");
            result = zombie_parse_config();
            if (result == RET_BREAK) {
                break;
            }
        }
        if (result == RET_SUCCESS) {
            monitor_zombie(&failed);
            result = feed_thread_status_count(THREAD_ZOMBIE_ITEM);
            if (result == -1) {
                log_printf(LOG_ERR, "zombie monitor feed error");
                break;
            }
        }
        (void)sleep((unsigned int)get_thread_item_period(ZOMBIE_ITEM));
    }

    return NULL;
}

void zombie_monitor_init(void)
{
    pthread_t tid;

    if (pthread_create(&tid, NULL, zombie_monitor_start, NULL)) {
        log_printf(LOG_ERR, "create zombie monitor thread error [%d]", errno);
        return;
    }
    set_thread_item_tid(ZOMBIE_ITEM, tid);
}
