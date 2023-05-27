/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * sysmonitor licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Description: common interface for test
 * Author: xuchunmei
 * Create: 2019-9-28
 */
#include "common_interface.h"

#include <unistd.h>
#include <securec.h>

const static pid_t g_monitor_main_pid = 0;
static int g_monitor_log_fd = -1;
static char g_log_path[LOG_FILE_LEN] = {0};
static int g_log_interface_flag = -1;
static bool g_flag_log_ok = false;
static pthread_mutex_t g_log_fd_mutex = PTHREAD_MUTEX_INITIALIZER;
static monitor_thread g_thread_item[MONITOR_ITEMS_CNT];

void init_log_for_test(const char *name)
{
    int ret;

    if (name == NULL) {
        return;
    }

    g_log_interface_flag = NORMAL_WRITE;
    ret = strncpy_s(g_log_path, sizeof(g_log_path), name, sizeof(g_log_path) - 1);
    if (ret != 0) {
        return;
    }

    if (g_monitor_log_fd >= 0) {
        (void)close(g_monitor_log_fd);
    }

    g_monitor_log_fd = open(g_log_path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, LOG_FILE_PERMISSION);
    if (g_monitor_log_fd < 0) {
        return;
    }

    g_flag_log_ok = true;
}

void clear_log_config(const char *name)
{
    if (name == NULL) {
        return;
    }

    if (g_monitor_log_fd >= 0) {
        (void)close(g_monitor_log_fd);
        g_monitor_log_fd = -1;
    }

    (void)memset_s(g_log_path, sizeof(g_log_path), 0, sizeof(g_log_path));
    g_flag_log_ok = false;
    g_log_interface_flag = DAEMON_SYSLOG;
    (void)unlink(name);
}

/*
 * write msg to log file
 */
static void write_log(const char *msg)
{
    ssize_t ret;

    (void)pthread_mutex_lock(&g_log_fd_mutex);
    ret = faccessat(0, g_log_path, F_OK, 0);
    if (ret != 0) {
        (void)close(g_monitor_log_fd);
        g_monitor_log_fd = open(g_log_path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, LOG_FILE_PERMISSION);
        if (g_monitor_log_fd < 0) {
            (void)printf("[sysmonitor]: reopen %s failed,errno[%d].\n", g_log_path, errno);
            (void)pthread_mutex_unlock(&g_log_fd_mutex);
            return;
        }
    }
    (void)lseek(g_monitor_log_fd, 0, SEEK_END);
    ret = write(g_monitor_log_fd, msg, strlen(msg));
    if (ret == -1) {
        (void)printf("[sysmonitor]: write to log file failed, errno[%d].\n", errno);
    }
    (void)pthread_mutex_unlock(&g_log_fd_mutex);
}

static int get_log_time(struct tm *t)
{
    time_t now;
    int ret;
    struct tm *ret_t = NULL;

    now = time((time_t)0);
    ret = memset_s(t, sizeof(struct tm), 0, sizeof(struct tm));
    if (ret != 0) {
        return -1;
    }

    ret_t = localtime_r(&now, t);
    if (ret_t == NULL) {
        return -1;
    }

    return 0;
}

static void log_for_daemon(int priority, const char *detail)
{
    int ret;
    char msg[MAX_LOG_LEN + MAX_TEMPSTR] = { 0 };

    ret = snprintf_s(msg, MAX_LOG_LEN + MAX_TEMPSTR, strlen(detail) + MAX_TEMPSTR - 1,
        "sysmonitor[%d]: %s", g_monitor_main_pid, detail);
    if (ret == -1) {
        syslog(priority, "log_it snprintf_s for msg error [%d]", ret);
    }
    syslog(priority, "%s", msg);
}

static void log_for_normal(const char *detail, struct tm t)
{
    char msg[MAX_LOG_LEN + MAX_TEMPSTR] = { 0 };
    int ret;

    ret = snprintf_s(msg, MAX_LOG_LEN + MAX_TEMPSTR, MAX_LOG_LEN + MAX_TEMPSTR - 1,
        "[LOC %04d-%02d-%02d:%02d:%02d:%02d]sysmonitor[%d]: %s\n",
        t.tm_year + TM_YEAR_BEGIN, t.tm_mon + 1, t.tm_mday,
        t.tm_hour, t.tm_min, t.tm_sec, g_monitor_main_pid, detail);
    if (ret == -1) {
        (void)printf("log_it: snprintf_s msg failed");
        return;
    }

    if (g_flag_log_ok) {
        write_log(msg);
    } else {
        (void)printf("%s", msg);
    }
}

/*
 * write info to log file, use syslog or write interface
 */
static void log_it(int priority, const char *detail)
{
    struct tm t;

    if (get_log_time(&t) != 0) {
        return;
    }

    if (g_log_interface_flag == DAEMON_SYSLOG) {
        log_for_daemon(priority, detail);
    } else {
        log_for_normal(detail, t);
    }
}

void log_printf(int priority, const char *format, ...)
{
    char msg_buffer[MAX_LOG_LEN] = {0};
    int ret;
    va_list arg_list;

    va_start(arg_list, format);
    ret = vsnprintf_s(msg_buffer, sizeof(msg_buffer), sizeof(msg_buffer) - 1, format, arg_list);
    if (ret == -1 && msg_buffer[0] == '\0') {
        (void)printf("log_printf: vsnprintf_s aMsgBuffer failed");
        va_end(arg_list);
        return;
    }

    va_end(arg_list);
    log_it(priority, msg_buffer);
}

int get_log_interface_flag(void)
{
    return g_log_interface_flag;
}

bool get_flag_log_ok(void)
{
    return g_flag_log_ok;
}

monitor_thread *get_thread_item_info(int type)
{
    if (type < 0 || type >= MONITOR_ITEMS_CNT) {
        return NULL;
    }
    return &g_thread_item[type];
}

void set_log_interface_flag(int flag)
{
    g_log_interface_flag = flag;
}

void set_flag_log_ok(bool flag)
{
    g_flag_log_ok = flag;
}

int exec_cmd_test(const char *cmd)
{
    return monitor_cmd(DEFAULT_USER_ID, cmd, 0, NULL, true);
}

bool get_thread_item_reload_flag(monitor_item_type type)
{
    return g_thread_item[type].reload;
}

void set_thread_item_reload_flag(monitor_item_type type, bool flag)
{
    g_thread_item[type].reload = flag;
}

bool get_thread_item_monitor_flag(monitor_item_type type)
{
    return g_thread_item[type].monitor;
}

void set_thread_item_monitor_flag(monitor_item_type type, bool flag)
{
    g_thread_item[type].monitor = flag;
}

bool get_thread_item_alarm_flag(monitor_item_type type)
{
    return g_thread_item[type].alarm;
}

int get_thread_item_period(monitor_item_type type)
{
    return g_thread_item[type].period;
}

void set_thread_item_period(monitor_item_type type, int period)
{
    g_thread_item[type].period = period;
}

void set_thread_item_tid(monitor_item_type type, pthread_t tid)
{
    g_thread_item[type].tid = tid;
}

void recover_sysmonitor(void)
{
    (void)exec_cmd_test("mv /usr/bin/sysmonitor /usr/bin/sysmonitor.del");
    (void)exec_cmd_test("mv /usr/bin/sysmonitor.back /usr/bin/sysmonitor");
    (void)exec_cmd_test("systemctl restart sysmonitor");
    (void)exec_cmd_test("rm /usr/bin/sysmonitor.del -rf");
    (void)printf("recover sysmonitor\n");
}

void init_sysmonitor(void)
{
    (void)exec_cmd_test("mv /usr/bin/sysmonitor /usr/bin/sysmonitor.back");
    (void)exec_cmd_test("cp ./sysmonitor/sysmonitor_test /usr/bin/sysmonitor");
    (void)exec_cmd_test("systemctl restart sysmonitor");
    (void)printf("init sysmonitor\n");
}