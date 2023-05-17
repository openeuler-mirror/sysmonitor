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
 * Description: main for sysmonitor
 * Author: xuchunmei
 * Create: 2016-1-1
 */
#define _GNU_SOURCE
#include "sysmonitor.h"

#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <libgen.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <securec.h>

#include "common.h"
#include "custom.h"
#include "disk.h"
#include "fsmonitor.h"
#include "filemonitor.h"
#include "process.h"
#include "sys_resources.h"
#include "sys_event.h"
#include "zombie.h"
#include "monitor_thread.h"

/* monitor period for each item */
#define PS_PERIOD 3
#define DISK_PERIOD 60
#define INODE_PERIOD 60
#define IODELAY_PERIOD 5
#define CUSTOM_DAEMON_PERIOD 10
#define ZOMBIE_PERIOD 60
#define MONITOR_SUM 16
#define HEARTBEAT_TIMEOUT 15
#define RESTART_ALARM_TIMES_MAX 1000
#define RESTART_ALARM_PERIOD_MAX 60
#define SYSMONITOR_PIDFILE_MODE 0640
#define PIDFILE "/var/run/sysmonitor.pid"
#define USER_ARGS 2
#define SKIP_TWO_CHARS_LEN 2

static monitor_thread g_thread_item[MONITOR_ITEMS_CNT];

#define W_LOG_DEFAULT_PATH "/var/log/sysmonitor.log" /* normal mode, write path */
#define W_LOG_CONF_FILE "/etc/sysmonitor/w_log_conf" /* normal mode, write config */

static int g_log_interface_flag = DAEMON_SYSLOG;
static int g_monitor_log_fd = -1;
static pid_t g_monitor_main_pid;
static char g_log_path[LOG_FILE_LEN] = {0};
static bool g_flag_log_ok = false;
static bool g_flag_utc = false;
static pthread_mutex_t g_log_fd_mutex = PTHREAD_MUTEX_INITIALIZER;

struct item_value_func {
    char item[ITEM_LEN];
    bool (*func)(const char *item, const char *value);
};

bool get_thread_item_reload_flag(monitor_item_type type)
{
    return g_thread_item[type].reload;
}

void set_thread_item_reload_flag(monitor_item_type type, bool flag)
{
    g_thread_item[type].reload = flag;
}

int get_log_interface_flag(void)
{
    return g_log_interface_flag;
}

bool get_flag_log_ok(void)
{
    return g_flag_log_ok;
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

/*
 * write msg to log file
 */
static void write_log(const char *msg)
{
    int ret;
    ssize_t write_ret;

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
    write_ret = write(g_monitor_log_fd, msg, strlen(msg));
    if (write_ret == -1) {
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

    if (g_flag_utc == true) {
        ret_t = gmtime_r(&now, t);
    } else {
        ret_t = localtime_r(&now, t);
    }

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

    if (g_flag_utc == true) {
        ret = snprintf_s(msg, MAX_LOG_LEN + MAX_TEMPSTR, MAX_LOG_LEN + MAX_TEMPSTR - 1,
            "[UTC %04d-%02d-%02d:%02d:%02d:%02d]sysmonitor[%d]: %s\n",
            t.tm_year + TM_YEAR_BEGIN, t.tm_mon + 1, t.tm_mday,
            t.tm_hour, t.tm_min, t.tm_sec, g_monitor_main_pid, detail);
    } else {
        ret = snprintf_s(msg, MAX_LOG_LEN + MAX_TEMPSTR, MAX_LOG_LEN + MAX_TEMPSTR - 1,
            "[LOC %04d-%02d-%02d:%02d:%02d:%02d]sysmonitor[%d]: %s\n",
            t.tm_year + TM_YEAR_BEGIN, t.tm_mon + 1, t.tm_mday,
            t.tm_hour, t.tm_min, t.tm_sec, g_monitor_main_pid, detail);
    }

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

static void close_log(void)
{
    if (g_log_interface_flag == NORMAL_WRITE) {
        if (g_monitor_log_fd >= 0) {
            (void)close(g_monitor_log_fd);
            g_monitor_log_fd = -1;
        }
    }
}

static void handle_lock_pidfile_failed(const char *pidfile, int error_no, int fd)
{
    char buf[MAX_TEMPSTR] = {0};
    char *ep = NULL;
    long other_pid;
    char err_buf[MAX_STRERROR_SIZE] = {0};
    ssize_t num;
    char *err_ret = NULL;

    num = read(fd, buf, sizeof(buf) - 1);
    if (num > 0) {
        /* use decimal conversion */
        other_pid = strtol(buf, &ep, STRTOL_NUMBER_BASE);
        if (other_pid > 0 && ep != buf && *ep == '\n' && other_pid != LONG_MAX) {
            err_ret = strerror_r(error_no, err_buf, sizeof(err_buf));
            log_printf(LOG_ERR, "can't lock %s, otherpid may be %ld: %s", pidfile, other_pid, err_ret);
        }
    } else {
        err_ret = strerror_r(error_no, err_buf, sizeof(err_buf));
        log_printf(LOG_ERR, "can't lock %s, otherpid unknown: %s", pidfile, err_ret);
    }
}

static bool write_pid_to_file(pid_t pid, const char *pidfile, int fd)
{
    char buf[MAX_TEMPSTR] = {0};
    char err_buf[MAX_STRERROR_SIZE] = {0};
    int ret;
    char *err_ret = NULL;
    ssize_t num;

    ret = snprintf_s(buf, sizeof(buf), sizeof(buf) - 1, "%ld\n", (long)pid);
    if (ret == -1) {
        log_printf(LOG_ERR, "acquire_daemonlock: snprintf_s buf failed");
        return false;
    }
    (void)lseek(fd, (off_t)0, SEEK_SET);
    num = write(fd, buf, strlen(buf));
    if (num < 0) {
        err_ret = strerror_r(errno, err_buf, sizeof(err_buf));
        log_printf(LOG_ERR, "acquire_daemonlock: write %s error, %s", pidfile, err_ret);
        return false;
    }
    if (ftruncate(fd, num)) {
        err_ret = strerror_r(errno, err_buf, sizeof(err_buf));
        log_printf(LOG_ERR, "acquire_daemonlock: ftruncate error, %s", err_ret);
        return false;
    }

    return true;
}

static bool acquire_daemonlock(const char *pidfile, bool update, pid_t pid)
{
    static int fd = -1;
    char err_buf[MAX_STRERROR_SIZE] = {0};
    char *err_ret = NULL;

    if (update == false) {
        /* Initial mode is 0600 to prevent flock() race/DoS. */
        fd = open(pidfile, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        if (fd == -1) {
            err_ret = strerror_r(errno, err_buf, sizeof(err_buf));
            log_printf(LOG_ERR, "can't open or create %s: %s", pidfile, err_ret);
            return false;
        }
        if (flock(fd, LOCK_EX | LOCK_NB) < OK) {
            handle_lock_pidfile_failed(pidfile, errno, fd);
            (void)close(fd);
            fd = -1;
            return false;
        }
        (void)fchmod(fd, SYSMONITOR_PIDFILE_MODE);
        (void)fcntl(fd, F_SETFD, 1);
    }

    if (write_pid_to_file(pid, pidfile, fd) == false) {
        (void)close(fd);
        fd = -1;
        (void)unlink(pidfile);
        return false;
    }

    return true;
}

static bool daemonize(void)
{
    int fd = -1;
    pid_t pid;
    bool ret = false;

    ret = acquire_daemonlock(PIDFILE, false, getpid());
    if (ret == false) {
        log_printf(LOG_ERR, "daemonize: acquire_daemonlock failed.");
        return false;
    }
    if (g_log_interface_flag == DAEMON_SYSLOG) {
        pid = fork();
        if (pid < 0) {
            log_printf(LOG_ERR, "daemonize: fork error");
            return false;
        } else if (pid != 0) {
            ret = acquire_daemonlock(PIDFILE, true, pid);
            if (ret) {
                exit(0);
            }
            return false;
        }

        (void)setsid();
        fd = open("/dev/null", O_RDWR, 0);
        if (fd >= 0) {
            (void)dup2(fd, STDIN_FILENO);
            (void)dup2(fd, STDOUT_FILENO);
            (void)dup2(fd, STDERR_FILENO);

            (void)close(fd);
        }
    }

    g_monitor_main_pid = getpid();
    return true;
}

static void monitor_var_init(void)
{
    int i;

    g_thread_item[PS_ITEM].init = ps_monitor_init;
    g_thread_item[FS_ITEM].init = fs_monitor_init;
    g_thread_item[DISK_ITEM].init = disk_monitor_init;
    g_thread_item[INODE_ITEM].init = inode_monitor_init;
    g_thread_item[FILE_ITEM].init = file_monitor_init;
    g_thread_item[CUSTOM_DAEMON_ITEM].init = custom_daemon_monitor_init;
    g_thread_item[CUSTOM_PERIODIC_ITEM].init = custom_periodic_monitor_init;
    g_thread_item[IO_DELAY_ITEM].init = io_delay_monitor_init;
    g_thread_item[SYSTEM_ITEM].init = sys_resources_monitor_init;
    g_thread_item[SYS_EVENT_ITEM].init = sys_event_monitor_init;
    g_thread_item[ZOMBIE_ITEM].init = zombie_monitor_init;

    g_thread_item[PS_ITEM].period = PS_PERIOD;
    g_thread_item[DISK_ITEM].period = DISK_PERIOD;
    g_thread_item[INODE_ITEM].period = INODE_PERIOD;
    g_thread_item[IO_DELAY_ITEM].period = IODELAY_PERIOD;
    g_thread_item[CUSTOM_DAEMON_ITEM].period = CUSTOM_DAEMON_PERIOD;
    g_thread_item[ZOMBIE_ITEM].period = ZOMBIE_PERIOD;

    for (i = 0; i < MONITOR_ITEMS_CNT; i++) {
        g_thread_item[i].monitor = true;
        g_thread_item[i].alarm = false;
        g_thread_item[i].reload = true;
    }

    /* init system resources monitor item */
    sys_resources_item_init_early();
    sys_event_item_init_early();
}

static bool montor_item_root_start(void)
{
    int i;

    for (i = 0; i < MONITOR_ITEMS_CNT; i++) {
        if (g_thread_item[i].monitor == true && g_thread_item[i].init) {
            g_thread_item[i].init();
            if (g_thread_item[i].tid == 0) {
                return false;
            }
        }
    }

    return true;
}

static bool monitor_start(void)
{
    if (!montor_item_root_start()) {
        return false;
    }
    return true;
}

static void quit_handler(int signo)
{
    (void)unlink(HEARTBEAT_SOCKET);
    close_sys_event_fd();
    close_log();
    (void)unlink(PIDFILE);
    _exit(EXIT_SUCCESS);
}

static void reload_handler(int signo)
{
    int i;

    for (i = 0; i < MONITOR_ITEMS_CNT; i++) {
        g_thread_item[i].reload = true;
    }
    clear_all_thread_status();
}

static void sig_setup(void)
{
    struct sigaction quit_action;
    struct sigaction reload_action;
    int ret;
    unsigned int sig_size = sizeof(struct sigaction);

    ret = memset_s(&quit_action, sig_size, 0, sig_size);
    if (ret) {
        log_printf(LOG_ERR, "sig_setup: memset_s quit_action failed, ret: %d.", ret);
        return;
    }
    ret = memset_s(&reload_action, sig_size, 0, sig_size);
    if (ret) {
        log_printf(LOG_ERR, "sig_setup: memset_s reload_action failed, ret: %d.", ret);
        return;
    }

    quit_action.sa_handler = quit_handler;
    reload_action.sa_handler = reload_handler;

    (void)sigaction(SIGINT, &quit_action, NULL);
    (void)sigaction(SIGTERM, &quit_action, NULL);
    (void)sigaction(SIGUSR2, &reload_action, NULL);

    (void)signal(SIGPIPE, SIG_IGN);
}

static bool _parse_value_off(const char *item, const char *value, bool *v)
{
    if (strcmp(value, "off") == 0) {
        *v = false;
    } else if (strcmp(value, "on") != 0) {
        log_printf(LOG_INFO, "%s set error", item);
        return false;
    }
    return true;
}

static bool _parse__process_monitor(const char *item, const char *value)
{
    return _parse_value_off(item, value, &g_thread_item[PS_ITEM].monitor);
}

static bool _parse_process_monitor_delay(const char *item, const char *value)
{
    return parse_process_monitor_delay(item, value);
}

static bool _parse_process_alarm_supress(const char *item, const char *value)
{
    return parse_process_alarm_supress(value);
}

static bool _parse__process_monitor_period(const char *item, const char *value)
{
    g_thread_item[PS_ITEM].period = (int)strtol(value, NULL, STRTOL_NUMBER_BASE);
    if (check_int(value) == false || g_thread_item[PS_ITEM].period <= 0) {
        log_printf(LOG_INFO, "PROCESS_MONITOR_PERIOD set error");
        return false;
    }
    return true;
}

static bool _parse__process_recall_period(const char *item, const char *value)
{
    return parse_process_recall_period(value);
}

static bool _parse__process_restart_timeout(const char *item, const char *value)
{
    return parse_process_restart_tiemout(value);
}

static bool _parse__filesystem_monitor(const char *item, const char *value)
{
    return _parse_value_off(item, value, &g_thread_item[FS_ITEM].monitor);
}

static bool _parse__signal_monitor(const char *item, const char *value)
{
    return sys_event_monitor_parse(item, value, SIGNAL, true);
}

static bool _parse__disk_monitor(const char *item, const char *value)
{
    return _parse_value_off(item, value, &g_thread_item[DISK_ITEM].monitor);
}

static bool _parse__disk_monitor_period(const char *item, const char *value)
{
    g_thread_item[DISK_ITEM].period = (int)strtol(value, NULL, STRTOL_NUMBER_BASE);
    if (check_int(value) == false || g_thread_item[DISK_ITEM].period <= 0) {
        log_printf(LOG_INFO, "DISK_MONITOR_PERIOD set error");
        return false;
    }
    return true;
}

static bool _parse__inode_monitor(const char *item, const char *value)
{
    return _parse_value_off(item, value, &g_thread_item[INODE_ITEM].monitor);
}

static bool _parse__inode_monitor_period(const char *item, const char *value)
{
    g_thread_item[INODE_ITEM].period = (int)strtol(value, NULL, STRTOL_NUMBER_BASE);
    if (check_int(value) == false || g_thread_item[INODE_ITEM].period <= 0) {
        log_printf(LOG_INFO, "INODE_MONITOR_PERIOD set error");
        return false;
    }
    return true;
}

static bool _parse__netcard_monitor(const char *item, const char *value)
{
    return sys_event_monitor_parse(item, value, NETWORK, true);
}

static bool _parse__file_monitor(const char *item, const char *value)
{
    return _parse_value_off(item, value, &g_thread_item[FILE_ITEM].monitor);
}


static bool _parse__cpu_monitor(const char *item, const char *value)
{
    return sys_resources_monitor_parse(item, value, CPU, true);
}

static bool _parse__mem_monitor(const char *item, const char *value)
{
    return sys_resources_monitor_parse(item, value, MEM, true);
}

static bool _parse__pscnt_monitor(const char *item, const char *value)
{
    return sys_resources_monitor_parse(item, value, PSCNT, true);
}

static bool _parse__fdcnt_monitor(const char *item, const char *value)
{
    return sys_resources_monitor_parse(item, value, SYSTEM_FDCNT, true);
}

static bool _parse__custom_daemon_monitor(const char *item, const char *value)
{
    return _parse_value_off(item, value, &g_thread_item[CUSTOM_DAEMON_ITEM].monitor);
}

static bool _parse__custom_periodic_monitor(const char *item, const char *value)
{
    return _parse_value_off(item, value, &g_thread_item[CUSTOM_PERIODIC_ITEM].monitor);
}

static bool _parse__io_delay_monitor(const char *item, const char *value)
{
    return _parse_value_off(item, value, &g_thread_item[IO_DELAY_ITEM].monitor);
}


static bool _parse__zombie_monitor(const char *item, const char *value)
{
    return _parse_value_off(item, value, &g_thread_item[ZOMBIE_ITEM].monitor);
}

static bool _parse__process_fd_num_monitor(const char *item, const char *value)
{
    return sys_event_monitor_parse(item, value, FDSTAT, true);
}

static bool _parse_net_rate_limit_burst(const char *item, const char *value)
{
    return parse_net_ratelimit_burst(value);
}

static bool _parse_fd_monitor_log_path(const char *item, const char *value)
{
    return parse_fd_monitor_log_path(value);
}

static bool _parse_check_thread_monitor(const char *item, const char *value)
{
    return check_thread_monitor(item, value);
}

static bool _parse_check_thread_failure_num(const char *item, const char *value)
{
    return check_thread_failure_num(item, value);
}

static const struct item_value_func g_opt_array[] = {
    { "PROCESS_MONITOR", _parse__process_monitor },
    { "PROCESS_MONITOR_PERIOD", _parse__process_monitor_period },
    { "PROCESS_ALARM_SUPRESS_NUM", _parse_process_alarm_supress },
    { "PROCESS_MONITOR_DELAY", _parse_process_monitor_delay },
    { "PROCESS_RESTART_TIMEOUT", _parse__process_restart_timeout },
    { "PROCESS_RECALL_PERIOD", _parse__process_recall_period },
    { "FILESYSTEM_MONITOR", _parse__filesystem_monitor },
    { "SIGNAL_MONITOR", _parse__signal_monitor },
    { "DISK_MONITOR", _parse__disk_monitor },
    { "DISK_MONITOR_PERIOD", _parse__disk_monitor_period },
    { "INODE_MONITOR", _parse__inode_monitor },
    { "INODE_MONITOR_PERIOD", _parse__inode_monitor_period },
    { "NETCARD_MONITOR", _parse__netcard_monitor },
    { "FILE_MONITOR", _parse__file_monitor },
    { "CPU_MONITOR", _parse__cpu_monitor },
    { "MEM_MONITOR", _parse__mem_monitor },
    { "PSCNT_MONITOR", _parse__pscnt_monitor },
    { "FDCNT_MONITOR", _parse__fdcnt_monitor },
    { "CUSTOM_DAEMON_MONITOR", _parse__custom_daemon_monitor },
    { "CUSTOM_PERIODIC_MONITOR", _parse__custom_periodic_monitor },
    { "IO_DELAY_MONITOR", _parse__io_delay_monitor },
    { "PROCESS_FD_NUM_MONITOR", _parse__process_fd_num_monitor },
    { "NET_RATE_LIMIT_BURST", _parse_net_rate_limit_burst },
    { "FD_MONITOR_LOG_PATH", _parse_fd_monitor_log_path },
    { "ZOMBIE_MONITOR", _parse__zombie_monitor },
    { "CHECK_THREAD_MONITOR", _parse_check_thread_monitor },
    { "CHECK_THREAD_FAILURE_NUM", _parse_check_thread_failure_num }
};

static bool parse_line(const char *config)
{
    char item[ITEM_LEN];
    char value[MAX_TEMPSTR];
    char *ptr = NULL;
    unsigned int size;
    unsigned int i;
    int ret;

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

    ret = memset_s(item, sizeof(item), 0, sizeof(item));
    if (ret) {
        log_printf(LOG_ERR, "parse_line: memset_s item failed, ret: %d.", ret);
        return false;
    }
    ret = memset_s(value, sizeof(value), 0, sizeof(value));
    if (ret) {
        log_printf(LOG_ERR, "parse_line: memset_s value failed, ret: %d.", ret);
        return false;
    }

    size = (unsigned int)(ptr - config);
    if (size >= sizeof(item)) {
        log_printf(LOG_ERR, "sysmonitor parse_line: item length(%u) too long(>%u).", size, sizeof(item));
        return false;
    }
    ret = strncpy_s(item, sizeof(item), config, size);
    if (ret) {
        log_printf(LOG_ERR, "parse_line: strncpy_s item failed, ret: %d.", ret);
        return false;
    }
    get_value(config, size, value, sizeof(value));
    for (i = 0; i < array_size(g_opt_array); i++) {
        if (strcmp(item, g_opt_array[i].item) != 0) {
            continue;
        }
        if (g_opt_array[i].func != NULL) {
            return g_opt_array[i].func(item, value);
        } else {
            return false;
        }
    }

    return true;
}

static bool check_config_path_valid(const char *config)
{
    if (strlen(config) > LOG_FILE_LEN - 1) {
        (void)printf("[sysmonitor] log path length is more than %d bytes\n", LOG_FILE_LEN - 1);
        return false;
    }

    if (*config != '/') {
        (void)printf("[sysmonitor] log path must begin with /\n");
        return false;
    }

    if (strchr(config, '\"') == NULL) {
        (void)printf("[sysmonitor] log path must end with \"\n");
        return false;
    }

    return true;
}

static bool parse_log_path(const char *config, const char *value)
{
    int ret;
    char tmp_path[LOG_FILE_LEN] = {0};

    if (check_config_path_valid(config) == false) {
        return false;
    }

    if (strlen(value) == 0) {
        (void)printf("[sysmonitor] log path len can`t be empty\n");
        return false;
    }

    ret = strncpy_s(tmp_path, LOG_FILE_LEN, value, LOG_FILE_LEN - 1);
    if (ret) {
        (void)printf("parse_line_log_path: strncpy_s log_path failed, ret: %d.", ret);
        return false;
    }

    if (!check_log_path(tmp_path)) {
        return false;
    }

    ret = strncpy_s(g_log_path, LOG_FILE_LEN, tmp_path, LOG_FILE_LEN - 1);
    if (ret) {
        (void)printf("parse_line_log_path: strncpy_s log_path failed, ret: %d", ret);
        return false;
    }

    return true;
}

static bool parse_line_log_path(const char *config)
{
    char words[ITEM_LEN] = {0};
    char value[LOG_FILE_LEN] = {0};
    char *ptr = NULL;
    unsigned int size;
    int ret;

    while (*config == ' ' || *config == '\t') {
        config++;
    }

    if (*config == '#' || *config == '\n') {
        return true;
    }

    if (check_conf_file_valid(config) == -1) {
        return false;
    }

    ptr = strstr(config, "=\"");
    if (ptr != NULL) {
        size = (unsigned int)(ptr - config);
        if (size >= sizeof(words)) {
            (void)printf("parse_line_log_path: key length(%u) too long(>%lu).", size, sizeof(words));
            return false;
        }
        ret = strncpy_s(words, sizeof(words), config, size);
        if (ret) {
            (void)printf("parse_line_log_path: strncpy_s words failed, ret: %d.", ret);
            return false;
        }

        get_value(config, size, value, sizeof(value));
        if (!strcmp(words, "WRITE_LOG_PATH")) {
            return parse_log_path(ptr + SKIP_TWO_CHARS_LEN, value);
        } else if (!strcmp(words, "UTC_TIME")) {
            if (!strcmp(value, "on")) {
                g_flag_utc = true;
            }
            return true;
        }
    }

    (void)printf("[sysmonitor] keyword '%s' not found\n", words);
    return false;
}

static int init_log(void)
{
    int ret;

    if (g_log_interface_flag == NORMAL_WRITE) {
        ret = parse_config(W_LOG_CONF_FILE, parse_line_log_path);
        if (ret == false || strlen(g_log_path) == 0) {
            ret = strncpy_s(g_log_path, sizeof(g_log_path), W_LOG_DEFAULT_PATH, sizeof(g_log_path) - 1);
            if (ret) {
                (void)printf("init_log: strncpy_s log_path failed, ret: %d.", ret);
                return ERROR_OPEN;
            }
            (void)printf("[sysmonitor] parse '%s' failed, default log path '%s' will be used\n",
                W_LOG_CONF_FILE, g_log_path);
        }

        g_monitor_log_fd = open(g_log_path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, LOG_FILE_PERMISSION);
        if (g_monitor_log_fd < OK) {
            (void)printf("[sysmonitor] open '%s' failed, process will exit.errno[%d]\n", g_log_path, errno);
            return ERROR_OPEN;
        }
    }

    g_flag_log_ok = true;
    return 0;
}

static int parse_args(int argc, const char **argv)
{
    if (argc != USER_ARGS) {
        (void)printf("Usage: 'sysmonitor --daemon' or 'sysmonitor --normal'\n");
        return ERROR_ARGS_WRONG;
    }

    if (strcmp(argv[1], "--daemon") == 0) {
        g_log_interface_flag = DAEMON_SYSLOG;
    } else if (strcmp(argv[1], "--normal") == 0) {
        g_log_interface_flag = NORMAL_WRITE;
    } else {
        (void)printf("Usage: 'sysmonitor --daemon' or 'sysmonitor --normal'\n");
        return ERROR_ARGS_WRONG;
    }

    return 0;
}

static int check_monitor_thread(pthread_t *worker_tid)
{
    int i;

    for (i = 0; i < MONITOR_ITEMS_CNT; i++) {
        if (g_thread_item[i].tid && !pthread_tryjoin_np(g_thread_item[i].tid, NULL)) {
            g_thread_item[i].tid = 0;
            if (g_thread_item[i].init != NULL) {
                g_thread_item[i].init();
            }
            if (g_thread_item[i].tid == 0) {
                return -1;
            }
        }
    }
    if (*worker_tid != 0 && !pthread_tryjoin_np(*worker_tid, NULL) &&
        worker_thread_init(worker_tid) == false) {
        return -1;
    }

    return 0;
}

static int monitor_struct_init(void)
{
    int ret;

    ret = memset_s(g_thread_item, sizeof(monitor_thread) * MONITOR_ITEMS_CNT, 0,
        sizeof(monitor_thread) * MONITOR_ITEMS_CNT);
    if (ret) {
        (void)printf("main, memset_s thread_item failed, ret: %d.", ret);
        return -1;
    }

    if (worker_task_struct_init() == false) {
        return -1;
    }

    return 0;
}

static bool monitor_thread_start(pthread_t *worker_tid)
{
    if (worker_thread_init(worker_tid) == false || monitor_start() == false) {
        return false;
    }

    return true;
}

int main(int argc, char **argv)
{
    pthread_t worker_tid = 0;
    int ret;
    bool delete_pid_file = false;

    if (monitor_struct_init() == -1) {
        goto err;
    }

    ret = parse_args(argc, (const char **)argv);
    if (ret != 0) {
        goto err;
    }

    ret = init_log();
    if (ret != 0) {
        goto err;
    }

    monitor_var_init();
    if (parse_config(CONF, parse_line) == false) {
        goto err;
    }

    /* after parse /etc/sysconfig/sysmonitor, init system resources monitor item */
    sys_resources_item_init();
    sys_event_item_init();

    /*
     * Creat daemon after log-init,So we can record error and info.
     * Creat daemon after monitor_var_init,beacase 'systemctl status' return parent process status.
     */
    if (daemonize() == false) {
        goto err;
    }

    delete_pid_file = true;

    sig_setup();
    log_printf(LOG_INFO, "[--------------------------sysmonitor starting up----------------------------]");

    if (thread_status_struct_init() == -1) {
        goto err;
    }

    if (monitor_thread_start(&worker_tid) == false) {
        goto err;
    }

    for (;;) {
        if (check_monitor_thread(&worker_tid) == -1) {
            goto err;
        }
        if (check_thread_status() == -1) {
            goto err;
        }
        (void)sleep(SYSMONITOR_PERIOD);
    }
err:
    close_log();
    if (delete_pid_file) {
        (void)unlink(PIDFILE);
    }
    exit(EXIT_FAILURE);
}
