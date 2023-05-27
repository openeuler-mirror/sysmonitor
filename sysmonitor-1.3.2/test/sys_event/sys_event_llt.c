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
 * Description: testcase for network, signal and process fd
 * Author: xuchunmei
 * Create: 2019-10-28
 */
#define _GNU_SOURCE
#include <CUnit/Basic.h>
#include <CUnit/Automated.h>
#include <CUnit/Console.h>
#include <securec.h>
#include "sys_event.h"
#include "../common_interface/common_interface.h"

#define EVENT_TEST_LOG "/home/sys_event.log"
#define MAXBUF 200
#define EVENT_FD_TEST_LOG "/home/fd_monitor.log"

typedef enum {
    CUNIT_SCREEN = 0,
    CUNIT_XMLFILE,
    CUNIT_CONSOLE
} cu_run_mode;

static monitor_thread *g_sysevent_info = NULL;
#define POLL_TIMEOUT_TEST 1
#define TIME_SLEEP 2
#define USLEEP_INTERVAL (100 * 1000)

static char g_dev[MAX_DEV] = {0};

static int init_before_test(void)
{
    int ret;
    unsigned long len;

    g_sysevent_info = get_thread_item_info(SYS_EVENT_ITEM);
    if (g_sysevent_info == NULL) {
        return 1;
    }
    (void)monitor_popen(
        "ip link show | grep 'BROADCAST,MULTICAST,UP,LOWER_UP' | awk '{print $2}' | cut -f 1 -d ':' | head -n 1",
        g_dev, sizeof(g_dev) - 1, 0, NULL);
    len = strlen(g_dev);
    if (len > 0 && g_dev[len - 1] == '\n') {
        g_dev[len - 1] = '\0';
    }
    init_log_for_test(EVENT_TEST_LOG);
    (void)exec_cmd_test("systemctl stop sysmonitor");
    ret = exec_cmd_test("lsmod | grep sysmonitor");
    if (ret != 0) {
        exec_cmd_test("insmod /lib/modules/sysmonitor/sysmonitor.ko");
    }
    sys_event_item_init_early();
    (void)sys_event_monitor_parse("SIGNAL_MONITOR", "OFF", SIGNAL, true);
    (void)sys_event_monitor_parse("NETCARD_MONITOR", "OFF", NETWORK, true);
    (void)sys_event_monitor_parse("PROCESS_FD_NUM_MONITOR", "OFF", FDSTAT, true);
    set_poll_timeout(POLL_TIMEOUT_TEST);
    sys_event_item_init();
    return 0;
}

static int clean_after_test(void)
{
    close_sys_event_fd();
    clear_log_config(EVENT_TEST_LOG);
    return 0;
}

static void wait_for_reload(void)
{
    (void)exec_cmd_test("rm -rf /home/sys_event.log");
    g_sysevent_info->reload = true;
    while (true) {
        if (!g_sysevent_info->reload) {
            break;
        }
        usleep(USLEEP_INTERVAL);
    }
}

static void exec_add_ip_addr(const int net_num, const int ipvlan_num)
{
    char temp[MAX_TEMPSTR] = {0};
    int ret;

    ret = snprintf_s(temp, sizeof(temp), sizeof(temp) - 1, "ip addr add 2.1.1.%d/16 dev ipv%d", net_num, ipvlan_num);
    if (ret == -1 && temp[0] == '\0') {
        log_printf(LOG_INFO, "snprintf for create add_ip_addr string failed.");
        return;
    }
    (void)exec_cmd_test(temp);
}

static void exec_del_ip_addr(const int net_num, const int ipvlan_num)
{
    char temp[MAX_TEMPSTR] = {0};
    int ret;

    ret = snprintf_s(temp, sizeof(temp), sizeof(temp) - 1, "ip addr del 2.1.1.%d/16 dev ipv%d", net_num, ipvlan_num);
    if (ret == -1 && temp[0] == '\0') {
        log_printf(LOG_INFO, "snprintf for create del_ip_addr string failed.");
        return;
    }
    (void)exec_cmd_test(temp);
}

static void test_net_monitor_fun_001()
{
    int ret;

    (void)exec_cmd_test("rm -rf /home/sys_event.log");
    sys_event_monitor_init();
    ret = exec_cmd_test("cat /home/sys_event.log | grep 'netcard monitor starting up'");
    CU_ASSERT(ret != 0);
    (void)sys_event_monitor_parse("NETCARD_MONITOR", "ON", NETWORK, true);
    sys_event_item_init();
    wait_for_reload();
    ret = exec_cmd_test("cat /home/sys_event.log | grep 'netcard monitor starting up'");
    CU_ASSERT(ret == 0);
}

static void test_net_monitor_fun_002()
{
    int ret;
    char temp[MAX_CONFIG] = {0};
    char cmd[MAX_CONFIG + MAX_TEMPSTR] = {0};

    (void)exec_cmd_test("mv /etc/sysmonitor/network /etc/sysmonitor/network-bak");
    (void)exec_cmd_test("rm -rf /home/sys_event.log");
    wait_for_reload();
    ret = exec_cmd_test("cat /home/sys_event.log | grep 'open /etc/sysmonitor/network error'");
    CU_ASSERT(ret == 0);
    (void)memset_s(temp, sizeof(temp) - 1, 'a', sizeof(temp) - 1);
    (void)snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "echo %s > /etc/sysmonitor/network", temp);
    (void)exec_cmd_test(cmd);
    (void)exec_cmd_test("echo 12345678901234567 >> /etc/sysmonitor/network");
    (void)exec_cmd_test("echo ' enp1s0 UPDOWNUPDOWNUPDOWNUPDOWN' >> /etc/sysmonitor/network");
    (void)exec_cmd_test("echo 'enp1s0 DOWNED' >> /etc/sysmonitor/network");
    (void)parse_net_ratelimit_burst("100");
    wait_for_reload();
    ret = exec_cmd_test("cat /home/sys_event.log | grep 'The configuration line of netcard monitor is too long'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_event.log | grep 'netcard name too long (>16)'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_event.log | grep 'event too long'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_event.log | grep 'event DOWNED not supported'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_event.log | grep 'set net ratelimit 100'");
    CU_ASSERT(ret == 0);
}

static void test_net_event_003()
{
    int ret;

    (void)exec_cmd_test("rm -rf /home/sys_event.log");
    (void)exec_cmd_test("ip -6 addr add 2001::11/48 dev ipv1");
    (void)exec_cmd_test("ip -6 addr del 2001::11/48 dev ipv1");
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_event.log | grep 'ipv1: ip' | grep '2001::11' | "
                        "grep 'prefixlen' | grep 48 | grep 'is added, comm'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_event.log | grep 'ipv1: ip' | grep '2001::11' | "
                        "grep 'prefixlen' | grep 48 | grep 'is deleted, comm'");
    CU_ASSERT(ret == 0);
}

static void test_net_event_002()
{
    int ret;
    const int net_num1 = 11, ipvlan_num1 = 1;
    const int net_num2 = 12, ipvlan_num2 = 2;

    (void)exec_cmd_test("echo > /etc/sysmonitor/network");
    wait_for_reload();
    (void)exec_cmd_test("rm -rf /home/sys_event.log");
    (void)exec_cmd_test("ip link set ipv1 up");
    (void)exec_cmd_test("ip link set ipv1 down");
    ret = exec_cmd_test("cat /home/sys_event.log | grep 'ipv1: device is down, comm'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("ip link set ipv1 up");
    ret = exec_cmd_test("cat /home/sys_event.log | grep 'ipv1: device is up, comm'");
    CU_ASSERT(ret == 0);
    exec_add_ip_addr(net_num1, ipvlan_num1);
    ret = exec_cmd_test("cat /home/sys_event.log | grep 'ipv1: ip' | grep '2.1.1.*' | "
                        "grep 'prefixlen' | grep 16 | grep 'is added, comm'");
    CU_ASSERT(ret == 0);
    exec_del_ip_addr(net_num1, ipvlan_num1);
    ret = exec_cmd_test("cat /home/sys_event.log | grep 'ipv1: ip' | grep '2.1.1.*' | "
                        "grep 'prefixlen' | grep 16 | grep 'is deleted, comm'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("ip link set ipv2 up");
    (void)exec_cmd_test("ip link set ipv2 down");
    ret = exec_cmd_test("cat /home/sys_event.log | grep 'ipv2: device is down, comm'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("ip link set ipv2 up");
    ret = exec_cmd_test("cat /home/sys_event.log | grep 'ipv2: device is up, comm'");
    CU_ASSERT(ret == 0);
    exec_add_ip_addr(net_num2, ipvlan_num2);
    ret = exec_cmd_test("cat /home/sys_event.log | grep 'ipv2: ip' | grep '2.1.1.*' | "
                        "grep 'prefixlen' | grep 16 | grep 'is added, comm'");
    CU_ASSERT(ret == 0);
    exec_del_ip_addr(net_num2, ipvlan_num2);
    ret = exec_cmd_test("cat /home/sys_event.log | grep 'ipv2: ip' | grep '2.1.1.*' | "
                        "grep 'prefixlen' | grep 16 | grep 'is deleted, comm'");
    CU_ASSERT(ret == 0);
}

static void test_net_event_001()
{
    int ret;
    const int net_num1 = 21, ipvlan_num1 = 1;
    const int net_num2 = 22, ipvlan_num2 = 2;

    (void)exec_cmd_test("rm -rf /home/sys_event.log");
    (void)exec_cmd_test("echo 'ipv1 NEWADDR' >> /etc/sysmonitor/network");
    (void)exec_cmd_test("echo 'ipv1 DELADDR' >> /etc/sysmonitor/network");
    wait_for_reload();
    (void)exec_cmd_test("ip link set ipv1 up");
    (void)exec_cmd_test("ip link set ipv1 down");
    ret = exec_cmd_test("cat /home/sys_event.log | grep 'ipv1: device is down, comm'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("ip link set ipv1 up");
    ret = exec_cmd_test("cat /home/sys_event.log | grep 'ipv1: device is up, comm'");
    CU_ASSERT(ret == 0);
    exec_add_ip_addr(net_num1, ipvlan_num1);
    ret = exec_cmd_test("cat /home/sys_event.log | grep 'ipv1: ip' | grep '2.1.1.*' | "
                        "grep 'prefixlen' | grep 16 | grep 'is added, comm'");
    CU_ASSERT(ret == 0);
    exec_del_ip_addr(net_num1, ipvlan_num1);
    ret = exec_cmd_test("cat /home/sys_event.log | grep 'ipv1: ip' | grep '2.1.1.*' | "
                        "grep 'prefixlen' | grep 16 | grep 'is deleted, comm'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("ip link set ipv2 up");
    (void)exec_cmd_test("ip link set ipv2 down");
    ret = exec_cmd_test("cat /home/sys_event.log | grep 'ipv2: device is down, comm'");
    CU_ASSERT(ret != 0);
    (void)exec_cmd_test("ip link set ipv2 up");
    ret = exec_cmd_test("cat /home/sys_event.log | grep 'ipv2: device is up, comm'");
    CU_ASSERT(ret != 0);
    exec_add_ip_addr(net_num2, ipvlan_num2);
    ret = exec_cmd_test("cat /home/sys_event.log | grep 'ipv2: ip' | grep '2.1.1.*' | "
                        "grep 'prefixlen' | grep 16 | grep 'is added, comm'");
    CU_ASSERT(ret != 0);
    exec_del_ip_addr(net_num2, ipvlan_num2);
    ret = exec_cmd_test("cat /home/sys_event.log | grep 'ipv2: ip' | grep '2.1.1.*' | "
                        "grep 'prefixlen' | grep 16 | grep 'is deleted, comm'");
    CU_ASSERT(ret != 0);
}

static void create_ipvlan(const char *name)
{
    char temp[MAX_TEMPSTR] = {0};
    int ret;

    ret = snprintf_s(temp, sizeof(temp), sizeof(temp) - 1,
                     "ip link add link %s name %s type ipvlan mode l2e", g_dev, name);
    if (ret == -1 && temp[0] == '\0') {
        log_printf(LOG_INFO, "snprintf for create ipvlan string failed.");
        return;
    }
    (void)exec_cmd_test(temp);
}

static void test_net_monitor_fun_003()
{
    int ret;
    const int net_num = 11, ipvlan_num = 1;

    create_ipvlan("ipv1");
    create_ipvlan("ipv2");
    (void)exec_cmd_test("echo 'ipv1 UP' > /etc/sysmonitor/network");
    (void)exec_cmd_test("rm -rf /home/sys_event.log");
    wait_for_reload();
    (void)exec_cmd_test("ip link set ipv2 up");
    ret = exec_cmd_test("cat /home/sys_event.log | grep 'ipv2: device is up, comm'");
    CU_ASSERT(ret != 0);
    (void)exec_cmd_test("ip link set ipv1 down");
    (void)exec_cmd_test("ip link set ipv1 up");
    ret = exec_cmd_test("cat /home/sys_event.log | grep 'ipv1: device is up, comm'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("ip link set ipv1 down");
    ret = exec_cmd_test("cat /home/sys_event.log | grep 'ipv1: device is down, comm'");
    CU_ASSERT(ret != 0);
    (void)exec_cmd_test("rm -rf /home/sys_event.log");
    (void)exec_cmd_test("echo 'ipv1 DOWN' >> /etc/sysmonitor/network");
    wait_for_reload();
    (void)exec_cmd_test("ip link set ipv1 up");
    (void)exec_cmd_test("ip link set ipv1 down");
    ret = exec_cmd_test("cat /home/sys_event.log | grep 'ipv1: device is down, comm'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("ip link set ipv1 up");
    ret = exec_cmd_test("cat /home/sys_event.log | grep 'ipv1: device is up, comm'");
    CU_ASSERT(ret == 0);
    exec_add_ip_addr(net_num, ipvlan_num);
    ret = exec_cmd_test("cat /home/sys_event.log | grep 'ipv1: ip' | grep '2.1.1.*' | "
                        "grep 'prefixlen' | grep 16 | grep 'is added, comm'");
    CU_ASSERT(ret != 0);
    exec_del_ip_addr(net_num, ipvlan_num);
    ret = exec_cmd_test("cat /home/sys_event.log | grep 'ipv1: ip' | grep '2.1.1.*' | "
                        "grep 'prefixlen' | grep 16 | grep 'is deleted, comm'");
    CU_ASSERT(ret != 0);
    test_net_event_001();
    test_net_event_002();
    test_net_event_003();
    (void)exec_cmd_test("ip link del ipv1 && ip link del ipv2");
}

static void test_net_monitor_fun_004()
{
    int ret;
    const int net_num = 11, ipvlan_num = 1;
    char temp[MAX_TEMPSTR] = {0};

    (void)exec_cmd_test("rm -rf /home/sys_event.log");
    create_ipvlan("ipv1");
    (void)exec_cmd_test("ip link set ipv1 up");
    exec_add_ip_addr(net_num, ipvlan_num);
    (void)snprintf_s(temp, sizeof(temp), sizeof(temp) - 1, "ip route change 2.1.0.%d/16 dev ipv1", 0);
    (void)exec_cmd_test(temp);
    exec_del_ip_addr(net_num, ipvlan_num);

    ret = exec_cmd_test("cat /home/sys_event.log | grep 'Fib4 replace table=254 2.1.0.[0]/16, comm: ip'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_event.log | grep 'Fib4 deleting table=254 2.1.0.[0]/16, comm: ip'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("ip link del ipv1");
    (void)exec_cmd_test("mv /etc/sysmonitor/network-bak /etc/sysmonitor/network");
}

static void test_parse_nrb_fun_001()
{
    bool ret = false;

    ret = parse_net_ratelimit_burst("-1");
    CU_ASSERT(ret == false);
    ret = parse_net_ratelimit_burst("0");
    CU_ASSERT(ret == true);
    ret = parse_net_ratelimit_burst("100");
    CU_ASSERT(ret == true);
    ret = parse_net_ratelimit_burst("101");
    CU_ASSERT(ret == false);
}

static void set_fd_log_path()
{
    bool ret = false;
    ret = parse_fd_monitor_log_path(EVENT_FD_TEST_LOG);

    CU_ASSERT(ret == true);
}

static void test_process_fd_monitor_fun_001()
{
    int ret;

    (void)exec_cmd_test("rm -rf /home/sys_event.log");
    sys_event_monitor_init();
    ret = exec_cmd_test("cat /home/sys_event.log | grep 'process fd num monitor starting up'");
    CU_ASSERT(ret != 0);
    (void)sys_event_monitor_parse("PROCESS_FD_NUM_MONITOR", "ON", FDSTAT, true);
    sys_event_item_init();
    wait_for_reload();
    ret = exec_cmd_test("cat /home/sys_event.log | grep 'process fd num monitor starting up'");
    CU_ASSERT(ret == 0);
}

static void test_process_fd_monitor_fun_002()
{
    int ret;
#if 0
    long num;
    unsigned long len;
    char buf[MAXBUF] = {0};
    char enablebuf[MAXBUF] = {0};
#endif

    (void)exec_cmd_test("mv /etc/sysmonitor/process_fd_conf /etc/sysmonitor/process_fd_conf-bak");
    (void)exec_cmd_test("rm -rf /home/sys_event.log");
    wait_for_reload();
    ret = exec_cmd_test("cat /home/sys_event.log | grep 'open /etc/sysmonitor/process_fd_conf error'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("echo 'PR_FD_ALARM=\"80.0\"' > /etc/sysmonitor/process_fd_conf");
    wait_for_reload();
    ret = exec_cmd_test("cat /home/sys_event.log | "
        "grep 'process fd num monitor: configuration illegal, will use defalut value'");
    CU_ASSERT(ret == 0);

    (void)exec_cmd_test("echo 'PR_FD_ALARM=\"0\"' > /etc/sysmonitor/process_fd_conf");
    wait_for_reload();
    ret = exec_cmd_test("cat /home/sys_event.log | "
        "grep 'process fd num monitor: configuration illegal, will use defalut value'");
    CU_ASSERT(ret == 0);

    (void)exec_cmd_test("echo 'PR_FD_ALARM=\"100\"' > /etc/sysmonitor/process_fd_conf");
    wait_for_reload();
    ret = exec_cmd_test("cat /home/sys_event.log | "
        "grep 'process fd num monitor: configuration illegal, will use defalut value'");
    CU_ASSERT(ret == 0);

    (void)exec_cmd_test("mv /etc/sysmonitor/process_fd_conf-bak /etc/sysmonitor/process_fd_conf");
    wait_for_reload();

#if 0
    (void)monitor_popen("cat /proc/fdthreshold", buf, sizeof(buf) - 1, 0, NULL);
    len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') {
        buf[len - 1] = '\0';
    }
    num = strtol(buf, NULL, STRTOL_NUMBER_BASE);
    CU_ASSERT(num == DEFAULT_FDTHRESHOLD);

    (void)monitor_popen("cat /proc/fdenable", enablebuf, sizeof(enablebuf) - 1, 0, NULL);
    len = strlen(enablebuf);
    if (len > 0 && enablebuf[len - 1] == '\n') {
        enablebuf[len - 1] = '\0';
    }
    num = strtol(enablebuf, NULL, STRTOL_NUMBER_BASE);
    CU_ASSERT(num == DEFAULT_FDENABLE);
#endif
}

static void test_process_fd_monitor_fun_003()
{
    int ret;
    char buf[MAXBUF] = {0};
    char fdbuf[MAXBUF] = {0};
    char catcmd[MAXBUF] = {0};
    char fdcatcmd[MAXBUF] = {0};
    unsigned long len;

    set_fd_log_path();
    ret = strncpy_s(catcmd, sizeof(catcmd),
        "grep \"sys_event_fd\" /home/sys_event.log | awk -F ']' '{print $1}' | awk -F '-' '{print $3}' "
        "| cut -c4- | head -n 1",
        sizeof(catcmd) - 1);
    if (ret == -1)
        return;

    ret = strncpy_s(fdcatcmd, sizeof(fdcatcmd),
        "grep \"sys_event_fd\" /home/fd_monitor.log | awk -F ' ' '{print $2}' | awk 'NR==1{print $1}'",
        sizeof(fdcatcmd) - 1);
    if (ret == -1)
        return;

    (void)exec_cmd_test("rm -rf /home/sys_event.log");
    (void)exec_cmd_test("rm -rf /home/fd_monitor.log");
    (void)exec_cmd_test("./sys_event/sys_event_fd &");
    (void)monitor_popen(catcmd, buf, sizeof(buf) - 1, 0, NULL);
    len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') {
        buf[len - 1] = '\0';
    }

    (void)monitor_popen(fdcatcmd, fdbuf, sizeof(fdbuf) - 1, 0, NULL);
    len = strlen(fdbuf);
    if (len > 0 && fdbuf[len - 1] == '\n') {
        fdbuf[len - 1] = '\0';
    }

    ret = strcmp(buf, fdbuf);
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("kill -9 $(ps aux | grep sys_event_fd | grep -v grep | awk '{print $2}')");
    (void)exec_cmd_test("rm -rf /home/test_sys_fd");
    (void)exec_cmd_test("rm -rf /home/fd_monitor.log");
}

static void test_signal_monitor_fun_001(void)
{
    int ret;

    (void)exec_cmd_test("rm -rf /home/sys_event.log");
    sys_event_monitor_init();
    ret = exec_cmd_test("cat /home/sys_event.log | grep 'signal monitor starting up'");
    CU_ASSERT(ret != 0);
    (void)sys_event_monitor_parse("SIGNAL_MONITOR", "ON", SIGNAL, true);
    sys_event_item_init();
    wait_for_reload();
    ret = exec_cmd_test("cat /home/sys_event.log | grep 'signal monitor starting up'");
    CU_ASSERT(ret == 0);
}

static void test_signal_monitor_fun_002(void)
{
#if 0
    int ret;

    (void)exec_cmd_test("sleep 1000&");
    (void)exec_cmd_test("kill -9 $(ps aux | grep 'sleep 1000' | grep -v grep | awk '{print $2}')");
    ret = exec_cmd_test("cat /home/sys_event.log | grep 'send SIGKILL to comm:sleep'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("mv /etc/sysmonitor/signal /etc/sysmonitor/signal-bak");
    (void)exec_cmd_test("echo ' SIGKILL=\"of\"' > /etc/sysmonitor/signal");
    (void)exec_cmd_test("echo 'SIGXX=\"on\"' >> /etc/sysmonitor/signal");
    (void)exec_cmd_test("echo 'SIGXX=\"on\"' >> /etc/sysmonitor/signal");
    (void)exec_cmd_test("echo '123456789012345678901234567890123456789012345678901=\"on\"'"
						">> /etc/sysmonitor/signal");
    wait_for_reload();
    ret = exec_cmd_test("cat /home/sys_event.log | grep 'SIGKILL set error'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_event.log | grep 'SIGXX not supported'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_event.log | grep 'parse_line: item length(51) too long(>50).'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("mv /etc/sysmonitor/signal-bak /etc/sysmonitor/signal");
#endif
}

int main(int argc, char **argv)
{
    CU_pSuite suite = NULL;
    unsigned int num_failures;
    cu_run_mode g_cunit_mode = CUNIT_SCREEN;

    if (argc > 1) {
        g_cunit_mode = (cu_run_mode)strtol(argv[1], NULL, STRTOL_NUMBER_BASE);
    }

    if (CU_initialize_registry() != CUE_SUCCESS) {
        return CU_get_error();
    }

    suite = CU_add_suite("sys_event", init_before_test, clean_after_test);
    if (suite == NULL) {
        goto err;
    }

    (void)CU_ADD_TEST(suite, test_net_monitor_fun_001);
    (void)CU_ADD_TEST(suite, test_net_monitor_fun_002);
    (void)CU_ADD_TEST(suite, test_net_monitor_fun_003);
    (void)CU_ADD_TEST(suite, test_net_monitor_fun_004);
    (void)CU_ADD_TEST(suite, test_parse_nrb_fun_001);
    (void)CU_ADD_TEST(suite, test_process_fd_monitor_fun_001);
    (void)CU_ADD_TEST(suite, test_process_fd_monitor_fun_002);
    (void)CU_ADD_TEST(suite, test_process_fd_monitor_fun_003);
    (void)CU_ADD_TEST(suite, test_signal_monitor_fun_001);
    (void)CU_ADD_TEST(suite, test_signal_monitor_fun_002);

    switch (g_cunit_mode) {
        case CUNIT_SCREEN:
            CU_basic_set_mode(CU_BRM_VERBOSE);
            (void)CU_basic_run_tests();
            break;
        case CUNIT_XMLFILE:
            CU_set_output_filename("sys_event");
            (void)CU_list_tests_to_file();
            CU_automated_run_tests();
            break;
        case CUNIT_CONSOLE:
            CU_console_run_tests();
            break;
        default:
            (void)printf("not suport cunit mode, only suport: 0 or 1\n");
            goto err;
    }

    num_failures = CU_get_number_of_failures();
    CU_cleanup_registry();
    return num_failures;
err:
    CU_cleanup_registry();
    return CU_get_error();
}
