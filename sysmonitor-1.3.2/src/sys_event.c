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
 * Description: sysmonitor event monitor, handle msg from sysmonitor module
 * Author: xuchunmei
 * Create: 2019-3-21
 */
#include "sys_event.h"

#include <signal.h>
#include <unistd.h>
#include <poll.h>
#include <securec.h>
#include "common.h"
#include "monitor_thread.h"

#define SYS_EVENT_FD_PATH "/proc/sysmonitor"
#define PROC_FDTHRESHOLD "/proc/fdthreshold"
#define RROC_FDENABLE "/proc/fdenable"
#define SIGCATCHMAK "/sys/module/sysmonitor/parameters/sigcatchmask"
#define NETRATELIMIT_BURST "/sys/module/sysmonitor/parameters/netratelimit_burst"
#define NET_RATELIMIT_BURST_MAX 100
#define PR_FD_ALARM_MAX 100

#define SIGNAL_COUNT 31
#define SIG_NAME_LEN 12
#define MAX_EVENT 20
#define AUP 0x0001
#define ADOWN 0x0002
#define ANEWADDR 0x0004
#define ADELADDR 0x0008
#define IP_ADDR_LEN 64
#define FIB_INFO_LEN 256
#define CMD_LEN 100

typedef struct system_event_info_s {
    bool monitor;
    bool alarm;
} system_event_info;

typedef struct _netask {
    char dev[MAX_DEV];
    unsigned int event;
    struct list_head list;
} netask;

static int g_sys_event_fd = -1;
static unsigned long g_signo;
static unsigned long g_pr_alarm_ratio = 80;    /* process fd usage alarm value, default 80 */
static struct list_head g_net_head;

#define FD_MONITOR_LOG_FILE "/var/log/fd_monitor.log"
#define FD_LOG_FILE_MAX_SIZE (512 * 1024)
char g_fd_log_path[LOG_FILE_LEN] = {0};
static int g_fd_log_fd = -1;
static pthread_mutex_t g_fd_log_fd_mutex = PTHREAD_MUTEX_INITIALIZER;

static system_event_info g_sys_event_info[SYS_EVENT_CNT];

static char g_signal_string[SIGNAL_COUNT][SIG_NAME_LEN] = {
    "SIGHUP",  "SIGINT",    "SIGQUIT", "SIGILL",   "SIGTRAP", "SIGABRT", "SIGBUS",  "SIGFPE",
    "SIGKILL", "SIGUSR1",   "SIGSEGV", "SIGUSR2",  "SIGPIPE", "SIGALRM", "SIGTERM", "SIGSTKFLT",
    "SIGCHLD", "SIGCONT",   "SIGSTOP", "SIGTSTP",  "SIGTTIN", "SIGTTOU", "SIGURG",  "SIGXCPU",
    "SIGXFSZ", "SIGVTALRM", "SIGPROF", "SIGWINCH", "SIGIO",   "SIGPWR",  "SIGSYS",
};

static int g_net_ratelimit_burst = 5;
static int g_poll_timeout = POLL_TIMEOUT_DEFAULT;

void set_poll_timeout(int timeout)
{
    if (timeout <= 0) {
        return;
    }
    g_poll_timeout = timeout;
}

void close_sys_event_fd(void)
{
    if (g_sys_event_fd >= 0) {
        (void)close(g_sys_event_fd);
        g_sys_event_fd = -1;
    }
}

bool parse_net_ratelimit_burst(const char *value)
{
    g_net_ratelimit_burst = (int)strtol(value, NULL, STRTOL_NUMBER_BASE);
    if (check_int(value) == false || g_net_ratelimit_burst < 0 ||
        g_net_ratelimit_burst > NET_RATELIMIT_BURST_MAX) {
        log_printf(LOG_INFO, "NET_RATE_LIMIT_BURST set error");
        return false;
    }
    return true;
}

bool parse_fd_monitor_log_path(const char *value)
{
    int ret;

    if (!check_log_path(value)) {
        return false;
    }

    ret = strncpy_s(g_fd_log_path, LOG_FILE_LEN, value, LOG_FILE_LEN - 1);
    if (ret) {
        log_printf(LOG_ERR, "parse fd monitor log path failed.");
        return false;
    }
    return true;
}

static void close_fd_log_fd(void)
{
    if (g_fd_log_fd >= 0) {
        (void)close(g_fd_log_fd);
        g_fd_log_fd = -1;
    }
}

static int rewrite_log_file(int *fd)
{
    off_t file_size;
    int new_fd = -1;
    char file_name[MAX_TEMPSTR] = {0};
    char msg_buffer[MAX_LOG_LEN] = {0};
    int ret;

    ret = snprintf_s(file_name, sizeof(file_name), sizeof(file_name) - 1, "%s.old", g_fd_log_path);
    if (ret == -1) {
        log_printf(LOG_ERR, "rewrite_log_file: snprintf_s file_name failed");
        return -1;
    }
    ret = snprintf_s(msg_buffer, sizeof(msg_buffer), sizeof(msg_buffer) - 1,
        "#################fd info####################\n%-23s%-12s%-24s%-12s\n", "TIME", "PID", "CMD", "FD");
    if (ret == -1) {
        log_printf(LOG_ERR, "rewrite_log_file: snprintf_s msg_buffer failed");
        return -1;
    }

    file_size = lseek(*fd, 0, SEEK_END);
    if (file_size == 0) {
        if (write(*fd, msg_buffer, strlen(msg_buffer)) == ERR) {
            log_printf(LOG_ERR, "write log  to %s failed,error num [%d]", g_fd_log_path, errno);
            return -1;
        }
    }

    if (file_size >= FD_LOG_FILE_MAX_SIZE) {
        (void)close(*fd);
        if (rename(g_fd_log_path, file_name) != 0) {
            log_printf(LOG_ERR, "rename %s failed,err:%s.\n", g_fd_log_path, strerror(errno));
        }
        new_fd = open(g_fd_log_path, O_CREAT | O_RDWR | O_APPEND | O_CLOEXEC, LOG_FILE_PERMISSION);
        if (new_fd < 0) {
            return -1;
        }
        /* wirte title to log file */
        if (write(new_fd, msg_buffer, strlen(msg_buffer)) == ERR) {
            log_printf(LOG_ERR, "write log  to %s failed,error num [%d]", g_fd_log_path, errno);
            (void)close(new_fd);
            return -1;
        }
        *fd = new_fd;
    }
    return 0;
}

static void write_log2file(const char *log_msg)
{
    int ret;
    char msg[MAX_LOG_LEN + MAX_TEMPSTR] = {0};
    time_t cur_time;
    struct tm ret_t;
    struct tm *t = NULL;

    ret = memset_s(&ret_t, sizeof(ret_t), 0, sizeof(ret_t));
    if (ret) {
        log_printf(LOG_ERR, "write_log2file: memset_s ret_t failed, ret: %d", ret);
        return;
    }

    cur_time = time((time_t)0);

    t = localtime_r(&cur_time, &ret_t);
    if (t == NULL) {
        return;
    }

    ret = snprintf_s(msg, MAX_LOG_LEN + MAX_TEMPSTR, MAX_LOG_LEN + MAX_TEMPSTR - 1,
        "%04d-%02d-%02d %02d:%02d:%02d    %s\n",
        ret_t.tm_year + TM_YEAR_BEGIN, ret_t.tm_mon + 1, ret_t.tm_mday, ret_t.tm_hour,
        ret_t.tm_min, ret_t.tm_sec, log_msg);
    if (ret == -1) {
        log_printf(LOG_ERR, "write_log2file: snprintf_s aMsgBuffer failed");
        return;
    }

    (void)pthread_mutex_lock(&g_fd_log_fd_mutex);

    ret = faccessat(0, g_fd_log_path, F_OK, 0);
    if (ret != 0) {
        close_fd_log_fd();
        g_fd_log_fd = open(g_fd_log_path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, LOG_FILE_PERMISSION);
        if (g_fd_log_fd < 0) {
            (void)pthread_mutex_unlock(&g_fd_log_fd_mutex);
            log_printf(LOG_ERR, "create file %s failed.", g_fd_log_path);
            return;
        }
    }

    ret = rewrite_log_file(&g_fd_log_fd);
    if (ret != 0) {
        (void)pthread_mutex_unlock(&g_fd_log_fd_mutex);
        return;
    }

    if (write(g_fd_log_fd, msg, strlen(msg)) < 0) {
        log_printf(LOG_ERR, "write log  to %s failed.", g_fd_log_path);
    }

    (void)pthread_mutex_unlock(&g_fd_log_fd_mutex);
}

static void fd_log_printf(const char *format, ...)
{
    char msg_buffer[MAX_LOG_LEN] = {0};
    int ret;

    va_list arg_list;

    va_start(arg_list, format);
    ret = vsnprintf_s(msg_buffer, sizeof(msg_buffer), sizeof(msg_buffer) - 1, format, arg_list);
    if (ret == -1) {
        log_printf(LOG_ERR, "fd_log_printf: vsnprintf_s msg_buffer failed");
        va_end(arg_list);
        return;
    }

    va_end(arg_list);
    write_log2file(msg_buffer);
}

static bool parse_signal_value(const char *item, const char *value)
{
    unsigned int i;

    for (i = 0; i < SIGNAL_COUNT; i++) {
        if (!strcmp(item, g_signal_string[i])) {
            if (!strcmp(value, "on")) {
                g_signo |= (unsigned long)(1ul << i);
                return true;
            } else if (strcmp(value, "off")) {
                log_printf(LOG_INFO, "%s set error", g_signal_string[i]);
                return false;
            }
        }
    }

    log_printf(LOG_INFO, "%s not supported", item);
    return false;
}

static bool parse_process_fd_value(const char *item, const char *value)
{
    if (!strlen(value)) {
        return false;
    }

    if (!strcmp(item, "PR_FD_ALARM")) {
        if (check_int(value) == false) {
            return false;
        }
        if (strtol(value, NULL, STRTOL_NUMBER_BASE) == 0 ||
            strtol(value, NULL, STRTOL_NUMBER_BASE) == PR_FD_ALARM_MAX) {
            return false;
        }
        g_pr_alarm_ratio = (unsigned long)strtol(value, NULL, STRTOL_NUMBER_BASE);
        return true;
    }

    return true;
}

struct config_parse_func {
    char config_file[ITEM_LEN];
    bool (*parse_line_func)(const char *config);
    void (*check_config)(bool parse_ok);
};

static bool parse_line(const char *config, int type)
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
            log_printf(LOG_ERR, "parse_line: item length(%u) too long(>%lu).", size, sizeof(item));
            return false;
        }
        ret = strncpy_s(item, sizeof(item), config, size);
        if (ret != 0) {
            log_printf(LOG_ERR, "parse_line: strncpy_s item failed, ret: %d", ret);
            return false;
        }
        get_value(config, size, value, sizeof(value));

        if (type == SIGNAL) {
            return parse_signal_value(item, value);
        } else if (type == FDSTAT) {
            return parse_process_fd_value(item, value);
        }
    }
    return true;
}

static bool parse_signal_line(const char *config)
{
    return parse_line(config, SIGNAL);
}

static bool parse_process_fd_line(const char *config)
{
    return parse_line(config, FDSTAT);
}

static netask *find_netask(const char *dev)
{
    netask *t = NULL;

    list_for_each_entry(t, &g_net_head, list) {
        if (!strcmp(t->dev, dev)) {
            return t;
        }
    }
    return NULL;
}

static void free_netask_list(void)
{
    netask *t = NULL;
    netask *n = NULL;

    list_for_each_entry_safe(t, n, &g_net_head, list) {
        list_del(&t->list);
        free(t);
    }
}

static bool set_rtnetlink_group(const char *event, netask *e)
{
    if (!strcmp(event, "UP")) {
        e->event = e->event | AUP;
    } else if (!strcmp(event, "DOWN")) {
        e->event = e->event | ADOWN;
    } else if (!strcmp(event, "NEWADDR")) {
        e->event = e->event | ANEWADDR;
    } else if (!strcmp(event, "DELADDR")) {
        e->event = e->event | ADELADDR;
    } else if (!strlen(event)) {
        e->event = e->event | AUP | ADOWN | ANEWADDR | ADELADDR;
    } else {
        log_printf(LOG_ERR, "event %s not supported", event);
        return false;
    }

    return true;
}

static netask *alloc_for_netask(const char *dev, bool *find)
{
    netask *e = NULL;
    int ret;

    e = find_netask(dev);
    if (e != NULL) {
        return e;
    }

    *find = false;
    e = malloc(sizeof(netask));
    if (e == NULL) {
        log_printf(LOG_ERR, "malloc error");
        return NULL;
    }

    ret = memset_s(e, sizeof(netask), 0, sizeof(netask));
    if (ret != 0) {
        log_printf(LOG_ERR, "network parse_line: memset_s e failed, ret: %d", ret);
        goto err;
    }

    ret = strncpy_s(e->dev, sizeof(e->dev), dev, sizeof(e->dev) - 1);
    if (ret != 0) {
        log_printf(LOG_ERR, "network parse_line: strncpy_s e dev failed, ret: %d", ret);
        goto err;
    }
    return e;

err:
    free(e);
    e = NULL;

    return NULL;
}

static bool parse_and_set_event(const char *config, netask *e, bool find)
{
    char event[MAX_EVENT] = {0};
    int i = 0;

    while (*config != '\n') {
        if (i > MAX_EVENT - 1) {
            log_printf(LOG_ERR, "event too long");
            goto err;
        }
        event[i++] = *config;
        config++;
    }

    if (set_rtnetlink_group(event, e) == false) {
        goto err;
    }

    if (find == false) {
        list_add(&e->list, &g_net_head);
    }

    return true;

err:
    if (find == false) {
        free(e);
        e = NULL;
    }
    return false;
}

static bool parse_network_line(const char *config)
{
    char dev[MAX_DEV] = {0};
    netask *e = NULL;
    bool find = true;
    int i;

    if (strlen(config) == 0) {
        log_printf(LOG_ERR, "The length of netcard monitor configuration is 0");
        return false;
    }

    if (config[strlen(config) - 1] != '\n') {
        log_printf(LOG_ERR, "The configuration line of netcard monitor is too long");
        return false;
    }

    while (*config == ' ' || *config == '\t') {
        config++;
    }

    if (*config == '#' || *config == '\n') {
        return true;
    }

    i = 0;
    for (;;) {
        if (*config == ' ' || *config == '\t' || *config == '\n') {
            break;
        }
        if (i > MAX_DEV - 1) {
            log_printf(LOG_ERR, "netcard name too long (>16)");
            return false;
        }
        dev[i] = *config;
        config++;
        i++;
    }

    e = alloc_for_netask(dev, &find);
    if (e == NULL) {
        return false;
    }

    while (*config == ' ' || *config == '\t') {
        config++;
    }

    return parse_and_set_event(config, e, find);
}

static void sig_set_mask(void)
{
    char cmd[CMD_LEN] = {0};
    int ret;

    ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "%lu", g_signo);
    if (ret == -1) {
        log_printf(LOG_ERR, "sig_set_mask: snprintf_s cmd failed");
        return;
    }

    ret = set_value_to_file(cmd, SIGCATCHMAK);
    if (ret == -1) {
        log_printf(LOG_ERR, "sig_set_mask: set_value_to_file failed");
        return;
    }

    log_printf(LOG_INFO, "set signo mask %lu", g_signo);
}

static void check_signal_config(bool parse_ok)
{
    log_printf(LOG_INFO, "signal monitor starting up");
    sig_set_mask();
}

static int chang_kernel_interface_value(void)
{
    int ret;
    char buf[MAX_TEMPSTR] = {0};

    ret = snprintf_s(buf, sizeof(buf), sizeof(buf) - 1, "%lu", g_pr_alarm_ratio);
    if (ret == -1) {
        log_printf(LOG_ERR, "chang_kernel_interface_value: snprintf_s buf failed");
        return -1;
    }

    ret = set_value_to_file(buf, PROC_FDTHRESHOLD);
    if (ret == -1) {
        log_printf(LOG_ERR, "chang_kernel_interface_value: set_value_to_file failed");
        return -1;
    }

    ret = set_value_to_file("1", RROC_FDENABLE);
    if (ret == -1) {
        log_printf(LOG_ERR, "chang_kernel_interface_value: set_value_to_file failed");
        return -1;
    }

    return ret;
}

static void check_process_fd_config(bool parse_ok)
{
    int ret;

    log_printf(LOG_INFO, "process fd num monitor starting up");
    if (parse_ok == false) {
        log_printf(LOG_INFO, "[error]process fd num monitor: configuration illegal, will use defalut value");
    }

    ret = chang_kernel_interface_value();
    if (ret != 0) {
        log_printf(LOG_INFO, "process fd num monitor: echo value to interface failed.");
    }
}

static void set_net_ratelimit(void)
{
    char buf[CMD_LEN] = {0};
    int ret;

    ret = snprintf_s(buf, CMD_LEN, CMD_LEN - 1, "%d", g_net_ratelimit_burst);
    if (ret == -1) {
        log_printf(LOG_ERR, "set_net_ratelimit: snprintf_s buf failed.");
        return;
    }
    ret = set_value_to_file(buf, NETRATELIMIT_BURST);
    if (ret == -1) {
        log_printf(LOG_ERR, "set net ratelimit to kernel module failed: %d", ret);
        return;
    }
    log_printf(LOG_INFO, "set net ratelimit %d", g_net_ratelimit_burst);
}

static void check_network_config(bool parse_ok)
{
    log_printf(LOG_INFO, "netcard monitor starting up");

    if (parse_ok == false) {
        log_printf(LOG_INFO, "read netcard monitor configuration error");
    }

    set_net_ratelimit();
}

static struct config_parse_func g_config_func[SYS_EVENT_CNT] = {
    { "/etc/sysmonitor/signal", parse_signal_line, check_signal_config },
    { "/etc/sysmonitor/process_fd_conf", parse_process_fd_line, check_process_fd_config },
    { "/etc/sysmonitor/network", parse_network_line, check_network_config }
};

static void parse_sys_event_config(void)
{
    unsigned int i;
    bool config_ok = false;

    for (i = 0; i < array_size(g_config_func); i++) {
        if (g_sys_event_info[i].monitor == false) {
            continue;
        }
        config_ok = parse_config(g_config_func[i].config_file, g_config_func[i].parse_line_func);
        g_config_func[i].check_config(config_ok);
    }
}

static int handle_signo_callchain(const signo_mesg *sg_msg, char *palarm_msg, size_t size, unsigned int len)
{
    int ret;

    if (sg_msg->send_chain_comm[0][0] == '\0') {
        ret = 0;
    } else if (sg_msg->send_chain_comm[1][0] == '\0') {
        ret = snprintf_s(palarm_msg + size - len, len, len - 1,
            "(%s[%d])",
            sg_msg->send_chain_comm[0], sg_msg->send_chain_pid[0]);
    } else if (sg_msg->send_chain_comm[2][0] == '\0') {
        ret = snprintf_s(palarm_msg + size - len, len, len - 1,
            "(%s[%d]<-%s[%d])",
            sg_msg->send_chain_comm[0], sg_msg->send_chain_pid[0],
            sg_msg->send_chain_comm[1], sg_msg->send_chain_pid[1]);
    } else if (sg_msg->send_chain_comm[3][0] == '\0') {
        ret = snprintf_s(palarm_msg + size - len, len, len - 1,
            "(%s[%d]<-%s[%d]<-%s[%d])",
            sg_msg->send_chain_comm[0], sg_msg->send_chain_pid[0],
            sg_msg->send_chain_comm[1], sg_msg->send_chain_pid[1],
            sg_msg->send_chain_comm[2], sg_msg->send_chain_pid[2]);
    } else {
        ret = snprintf_s(palarm_msg + size - len, len, len - 1,
            "(%s[%d]<-%s[%d]<-%s[%d]<-%s[%d])",
            sg_msg->send_chain_comm[0], sg_msg->send_chain_pid[0],
            sg_msg->send_chain_comm[1], sg_msg->send_chain_pid[1],
            sg_msg->send_chain_comm[2], sg_msg->send_chain_pid[2],
            sg_msg->send_chain_comm[3], sg_msg->send_chain_pid[3]);
    }
    return ret;
}

static int handle_signo_msg(const sysmonitor_event_msg *event_msg)
{
    signo_mesg *sg_msg = NULL;
    int ret;
    unsigned int len;
	char alarm_msg[PARAS_LEN];

    sg_msg = (signo_mesg *)event_msg->msg;
    if ((sg_msg->signo <= SIGNAL_COUNT) && (g_signo & (1ul << (sg_msg->signo - 1)))) {

        ret = snprintf_s((char *)alarm_msg, sizeof(alarm_msg), sizeof(alarm_msg) - 1,
            "comm:%s exe:%s[%d](parent comm:%s parent exe:%s[%d]) send %s to comm:%s exe:%s[%d].",
            sg_msg->send_comm, sg_msg->send_exe, sg_msg->send_pid,
            sg_msg->send_parent_comm, sg_msg->send_parent_exe, sg_msg->send_parent_pid,
            g_signal_string[sg_msg->signo - 1], sg_msg->recv_comm, sg_msg->recv_exe, sg_msg->recv_pid);
        if (ret == -1 && alarm_msg[0] == '\0') {
            log_printf(LOG_ERR, "sig_monitor_start: snprintf_s alarm_msg failed.");
            return -1;
        }

        len = sizeof(alarm_msg) - ret;
        ret = handle_signo_callchain(sg_msg, alarm_msg, sizeof(alarm_msg), len);
        if (ret == -1) {
            log_printf(LOG_ERR, "sig_monitor_start: snprintf_s alarm_msg failed.");
            return -1;
        }
        log_printf(LOG_INFO, "%s", alarm_msg);
    }

    return 0;
}

static int handle_fdstat_msg(const sysmonitor_event_msg *event_msg)
{
    struct fdstat *fdinfo = NULL;

    fdinfo = (struct fdstat *)event_msg->msg;
    log_printf(LOG_INFO, "pid [%d] cmd [%s]  fd more than [%u]", fdinfo->pid, fdinfo->comm, fdinfo->total_fd_num);
    fd_log_printf("%-12d%-24s%-12u", fdinfo->pid, fdinfo->comm, fdinfo->total_fd_num);

    return 0;
}

struct net_event_handle_func {
    int event;
    int (*func)(const netmonitor_info *info);
};

static int handle_net_device_event(const netmonitor_info *info)
{
    unsigned int net_event = AUP | ADOWN;
    netask *e = NULL;

    if (!list_empty(&g_net_head)) {
        e = find_netask(info->dev);
        if (e == NULL) {
            return 0;
        }
        net_event = e->event;
    }

    if ((info->event == UP) && (net_event & AUP)) {
        log_printf(LOG_INFO, "%s: device is up, comm: %s[%d], parent comm: %s[%d]",
            info->dev, info->comm, info->pid, info->parent_comm, info->parent_pid);
    } else if ((info->event == DOWN) && (net_event & ADOWN)) {
        log_printf(LOG_INFO, "%s: device is down, comm: %s[%d], parent comm: %s[%d]",
            info->dev, info->comm, info->pid, info->parent_comm, info->parent_pid);
    }

    return 0;
}

static int handle_address_event(const netmonitor_info *info)
{
    char ip_addr[IP_ADDR_LEN] = {0};
    bool ipv6 = false;
    netask *e = NULL;
    unsigned int net_event = AUP | ADOWN | ANEWADDR | ADELADDR;

    if (!list_empty(&g_net_head)) {
        e = find_netask(info->dev);
        if (e == NULL) {
            return 0;
        }
        net_event = e->event;
    }

    if (info->event == NEWADDR6 || info->event == DELADDR6) {
        ipv6 = true;
    }

    if (!ipv6) {
        if (!inet_ntop(AF_INET, (void *)&info->addr.in, ip_addr, sizeof(ip_addr))) {
            log_printf(LOG_INFO, "convert ipv4 address failed");
            return -1;
        }
    } else {
        if (!inet_ntop(AF_INET6, (void *)&info->addr.in6, ip_addr, sizeof(ip_addr))) {
            log_printf(LOG_INFO, "convert ipv6 address failed");
            return -1;
        }
    }

    if ((info->event == NEWADDR || info->event == NEWADDR6) && (net_event & ANEWADDR)) {
        log_printf(LOG_INFO, "%s: ip[%s] prefixlen[%d] is added, comm: %s[%d], parent comm: %s[%d]",
            info->dev, ip_addr, info->plen, info->comm, info->pid, info->parent_comm, info->parent_pid);
    } else if ((info->event == DELADDR || info->event == DELADDR6) && (net_event & ADELADDR)) {
        log_printf(LOG_INFO, "%s: ip[%s] prefixlen[%d] is deleted, comm: %s[%d], parent comm: %s[%d]",
            info->dev, ip_addr, info->plen, info->comm, info->pid, info->parent_comm, info->parent_pid);
    }

    return 0;
}

struct event_msg {
    int event;
    const char *name;
};

static const struct event_msg g_event_msg[] = {
    { FIB_DEL, "Fib4 deleting" },
    { FIB_ADD, "Fib4 insert" },
    { FIB_REPLACE, "Fib4 replace" },
    { FIB_APPEND, "Fib4 append" },
    { FIB6_DEL, "Fib6 deleting" },
    { FIB6_ADD, "Fib6 insert" },
    { FIB6_REPLACE, "Fib6 replace" },
    { FIB6_APPEND, "Fib6 append" },
};

static int handle_fib_event(const netmonitor_info *info)
{
    char ip_addr[IP_ADDR_LEN] = {0};
    char fib_info[FIB_INFO_LEN] = {0};
    unsigned int i;
    int ret;
    struct in_addr ipv4_addr = info->addr.in;

    if (!inet_ntop(AF_INET, (void *)&ipv4_addr, ip_addr, sizeof(ip_addr))) {
        log_printf(LOG_INFO, "convert ipv4 address failed");
        return -1;
    }

    for (i = 0; i < array_size(g_event_msg); i++) {
        if (g_event_msg[i].event == info->event) {
            ret = snprintf_s(fib_info, FIB_INFO_LEN, FIB_INFO_LEN - 1,
                "%s table=%d %s/%d, comm: %s[%d], parent comm: %s[%d]",
                g_event_msg[i].name, info->tb_id, ip_addr, info->plen,
                info->comm, info->pid, info->parent_comm, info->parent_pid);
            if (ret == -1 && fib_info[0] == '\0') {
                log_printf(LOG_ERR, "snprintf_s msg failed, ret: %d", ret);
                return -1;
            }
            log_printf(LOG_INFO, "%s", fib_info);
            return 0;
        }
    }

    return 0;
}

static int handle_fib6_event(const netmonitor_info *info)
{
    char ip_addr[IP_ADDR_LEN] = {0};
    char fib_info[FIB_INFO_LEN] = {0};
    unsigned int i;
    int ret;

    if (!inet_ntop(AF_INET6, (void *)&info->addr.in6, ip_addr, sizeof(ip_addr))) {
        log_printf(LOG_INFO, "convert ipv6 address failed");
        return -1;
    }

    for (i = 0; i < array_size(g_event_msg); i++) {
        if (g_event_msg[i].event == info->event) {
            ret = snprintf_s(fib_info, FIB_INFO_LEN, FIB_INFO_LEN - 1,
                "%s %s/%d, comm: %s[%d], parent comm: %s[%d]",
                g_event_msg[i].name, ip_addr, info->plen,
                info->comm, info->pid, info->parent_comm, info->parent_pid);
            if (ret == -1 && fib_info[0] == '\0') {
                log_printf(LOG_ERR, "snprintf_s msg failed, ret: %d", ret);
                return -1;
            }
            log_printf(LOG_INFO, "%s", fib_info);
            return 0;
        }
    }

    return 0;
}

static const struct net_event_handle_func g_net_event_array[] = {
    { UP, handle_net_device_event },
    { DOWN, handle_net_device_event },
    { DELADDR, handle_address_event },
    { NEWADDR, handle_address_event },
    { DELADDR6, handle_address_event },
    { NEWADDR6, handle_address_event },
    { FIB_DEL, handle_fib_event },
    { FIB_ADD, handle_fib_event },
    { FIB_REPLACE, handle_fib_event },
    { FIB_APPEND, handle_fib_event },
    { FIB6_DEL, handle_fib6_event },
    { FIB6_ADD, handle_fib6_event },
    { FIB6_REPLACE, handle_fib6_event },
    { FIB6_APPEND, handle_fib6_event }
};

static int handle_net_msg(const sysmonitor_event_msg *event_msg)
{
    netmonitor_info *info = NULL;
    unsigned int i;

    info = (netmonitor_info *)event_msg->msg;
    for (i = 0; i < array_size(g_net_event_array); i++) {
        if (info->event == g_net_event_array[i].event) {
            return g_net_event_array[i].func(info);
        }
    }
    return 0;
}

struct event_msg_handle_func {
    int type;
    int (*handler)(const sysmonitor_event_msg *msg);
};

static const struct event_msg_handle_func g_msg_handler[SYS_EVENT_CNT] = {
    { SIGNAL, handle_signo_msg },
    { FDSTAT, handle_fdstat_msg },
    { NETWORK, handle_net_msg }
};

static int handle_sys_event_msg(const sysmonitor_event_msg *msg)
{
    unsigned int i;

    for (i = 0; i < array_size(g_msg_handler); i++) {
        if (g_msg_handler[i].type == msg->type) {
            if (g_sys_event_info[i].monitor == false) {
                return 0;
            }
            return g_msg_handler[i].handler(msg);
        }
    }
    return 0;
}

static void *sys_event_monitor_start(void *arg)
{
    struct pollfd pollfd;
    sysmonitor_event_msg msg;
    int ret;
    ssize_t read_ret;

    (void)prctl(PR_SET_NAME, "monitor-sysent");
    log_printf(LOG_INFO, "system event starting up");

    init_list_head(&g_net_head);

    g_fd_log_fd = open(g_fd_log_path, O_WRONLY | O_APPEND | O_CREAT, LOG_FILE_PERMISSION);
    if (g_fd_log_fd < 0) {
        log_printf(LOG_INFO, "open %s failed, fd monitor info will not log, errno[%d]\n", g_fd_log_path, errno);
    }

    g_sys_event_fd = open(SYS_EVENT_FD_PATH, O_CLOEXEC);
    if (g_sys_event_fd < 0) {
        set_thread_item_tid(SYS_EVENT_ITEM, 0);
        log_printf(LOG_INFO, "sys_event: open %s failed, sysmonitor init module failed.", SYS_EVENT_FD_PATH);
        goto err;
    }

    pollfd.fd = g_sys_event_fd;
    pollfd.events = POLLIN;
    pollfd.revents = 0;

    for (;;) {
        if (get_thread_item_reload_flag(SYS_EVENT_ITEM)) {
            log_printf(LOG_INFO, "system event monitor, start reload");
            free_netask_list();
            parse_sys_event_config();
            set_thread_item_reload_flag(SYS_EVENT_ITEM, false);
        }

        ret = poll(&pollfd, 1, g_poll_timeout);
        if (ret < 0) {
            log_printf(LOG_ERR, "poll from sys event fd error[%d]", ret);
            break;
        } else if (ret == 0) {
            /* poll timeout */
            continue;
        }

        read_ret = read(g_sys_event_fd, &msg, sizeof(msg));
        if (read_ret < 0) {
            if (errno != EINTR) {
                log_printf(LOG_INFO, "read from sys event fd error[%d]", errno);
                break;
            }
            continue;
        }

        ret = handle_sys_event_msg(&msg);
        if (ret != 0) {
            break;
        }
    }
err:
    close_sys_event_fd();
    close_fd_log_fd();
    free_netask_list();
    return NULL;
}

void sys_event_item_init_early(void)
{
    int i;
    int ret;

    for (i = 0; i < SYS_EVENT_CNT; i++) {
        g_sys_event_info[i].monitor = true;
        g_sys_event_info[i].alarm = false;
    }

    /* set default fd monitor log path */
    ret = strncpy_s(g_fd_log_path, LOG_FILE_LEN, FD_MONITOR_LOG_FILE, LOG_FILE_LEN - 1);
    if (ret != 0) {
        log_printf(LOG_ERR, "init fd monitor log path[%s] failed, ret: %d", FD_MONITOR_LOG_FILE, ret);
    }
}

void sys_event_item_init(void)
{
    int i;

    set_thread_item_monitor_flag(SYS_EVENT_ITEM, false);
    for (i = 0; i < SYS_EVENT_CNT; i++) {
        if (g_sys_event_info[i].monitor == true) {
            set_thread_item_monitor_flag(SYS_EVENT_ITEM, true);
            break;
        }
    }
}

bool sys_event_monitor_parse(const char *item, const char *value, int type, bool monitor)
{
    return parse_value_bool(item, value,
        monitor ? &g_sys_event_info[type].monitor : &g_sys_event_info[type].alarm);
}

void sys_event_monitor_init(void)
{
    pthread_t tid;

    if (pthread_create(&tid, NULL, sys_event_monitor_start, NULL)) {
        log_printf(LOG_ERR, "create sys event monitor thread error [%d]", errno);
        return;
    }

    set_thread_item_tid(SYS_EVENT_ITEM, tid);
}
