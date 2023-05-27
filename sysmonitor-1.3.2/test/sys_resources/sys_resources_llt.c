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
 * Description: llt test file for sys_sources
 * Author: zhangguangzhi
 * Create: 2019-07-25
 */

#include <stdlib.h>
#include <CUnit/Basic.h>
#include <CUnit/Automated.h>
#include <CUnit/Console.h>
#include <unistd.h>
#include <stdio.h>
#include <dirent.h>

#include <securec.h>
#include "sys_resources.h"
#include "common.h"
#include "../common_interface/common_interface.h"

#define TIME_SLEEP 2
#define TIME_SLEEP_TEST 60
#define REPORT_CMD_TIMEOUT 60
#define MAX_PSCNT_TEST 1024
#define TIME_SLEEP_PSCNT 1
#define TIME_SLEEP_THREADS 3
#define TEST_THREADS_NUM_DEFAULT 10
#define TEST_THREADS_NUM_MAX 1024
#define TEST_THREADS_NUM_MID 200
#define GENERATE_NUM_DEFAULT 10
#define FD_ALARM_RATIO 0.03
#define GENERATE_FD_NUM 1024
#define PID_MAX 32768
#define FILE_MAX 39276
#define THREADS_MAX 21604
static monitor_thread *g_sysres_info;
static char g_pid_max[MAX_TEMPSTR] = {0};
static char g_file_max[MAX_TEMPSTR] = {0};
static char g_threads_max[MAX_TEMPSTR] = {0};

static int set_sys_resources_max(const char *max_str, char *sys_max, unsigned int max_num)
{
    int ret;
    char cmd[MAX_TEMPSTR] = {0};
    char cat_cmd[MAX_TEMPSTR] = {0};

    ret = snprintf_s(cat_cmd, sizeof(cat_cmd), sizeof(cat_cmd) - 1, "cat %s", max_str);
    if (ret == -1) {
        (void)printf("set sys resources max snprintf_s cat cmd failed, ret: %d, max_str:%s\n", ret, max_str);
        return ret;
    }
    (void)monitor_popen(cat_cmd, sys_max, MAX_TEMPSTR - 1, 0, NULL);

    ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "echo %u > %s", max_num, max_str);
    if (ret == -1) {
        (void)printf("set sys resources max snprintf_s cmd failed, ret: %d, max_str:%s\n", ret, max_str);
        return ret;
    }
    ret = exec_cmd_test(cmd);
    CU_ASSERT(ret == 0);
	return ret;
}

static int recover_sys_resources_max(const char *max_str, const char *sys_max)
{
    int ret;
    char cmd[MAX_CONFIG] = {0};

    ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "echo %s > %s", sys_max, max_str);
    if (ret == -1) {
        (void)printf("recover sys resources max snprintf_s cmd failed, ret: %d, max_str:%s\n", ret, max_str);
        return ret;
    }
    ret = exec_cmd_test(cmd);
    CU_ASSERT(ret == 0);
	return ret;
}

static int init_before_test_mem(void)
{
    init_log_for_test("/home/sys_res.log");
    g_sysres_info = get_thread_item_info(SYSTEM_ITEM);
    if (g_sysres_info == NULL) {
        return 1;
    }
    return 0;
}

static int cleanup_after_test_mem(void)
{
    clear_log_config("/home/sys_res.log");
    return 0;
}

static void init_generate_cpu_usage(void)
{
    (void)exec_cmd_test("echo '#! /bin/bash' > /home/generate_cpu_usage.sh");
    (void)exec_cmd_test("echo 'while ((1))' >> /home/generate_cpu_usage.sh");
    (void)exec_cmd_test("echo 'do' >> /home/generate_cpu_usage.sh");
    (void)exec_cmd_test("echo 'echo 111 > /dev/null' >> /home/generate_cpu_usage.sh");
    (void)exec_cmd_test("echo 'done' >> /home/generate_cpu_usage.sh");
}

static void clear_generate_cpu_usage(void)
{
    (void)exec_cmd_test("kill -9 $(ps aux | grep generate_cpu | grep -v grep | awk '{print $2}')");
    (void)exec_cmd_test("rm -rf /home/generate_cpu_usage.sh");
}

static void test_mem_show_alarm_info_001()
{
    int ret;
    bool flag = false;

    sys_resources_item_init_early();
    (void)sys_resources_monitor_parse("CPU_MONITOR", "OFF", CPU, true);
    (void)sys_resources_monitor_parse("PSCNT_MONITOR", "OFF", PSCNT, true);
    (void)sys_resources_monitor_parse("FDCNT_MONITOR", "OFF", SYSTEM_FDCNT, true);
    sys_resources_item_init();
    flag = sys_resources_monitor_parse("MEM_MONITOR", "ON", MEM, true);
    CU_ASSERT(flag == true);
    flag = sys_resources_monitor_parse("MEM_ALARM", "OFF", MEM, false);
    CU_ASSERT(flag == true);

    (void)exec_cmd_test("mv /etc/sysmonitor/memory /etc/sysmonitor/memory-bak");
    (void)exec_cmd_test("echo 'ALARM=\"90\"' > /etc/sysmonitor/memory");
    (void)exec_cmd_test("echo 'RESUME=\"80\"' >> /etc/sysmonitor/memory");
    (void)exec_cmd_test("echo 'PERIOD=\"1\"' >> /etc/sysmonitor/memory");

    sys_resources_monitor_init();
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep \"show_memory_info end.\"");
    CU_ASSERT(ret != 0);
    ret = exec_cmd_test("cat /home/sys_res.log | grep \"sysrq show memory info in message.\"");
    CU_ASSERT(ret != 0);

    (void)exec_cmd_test("rm -rf /etc/sysmonitor/memory");
    (void)exec_cmd_test("mv /etc/sysmonitor/memory-bak /etc/sysmonitor/memory");
}

static void test_mem_show_alarm_info_002()
{
    int ret;

    (void)exec_cmd_test("mv /etc/sysmonitor/memory /etc/sysmonitor/memory-bak");
    (void)exec_cmd_test("echo 'ALARM=\"2\"' > /etc/sysmonitor/memory");
    (void)exec_cmd_test("echo 'RESUME=\"1\"' >> /etc/sysmonitor/memory");
    (void)exec_cmd_test("echo 'PERIOD=\"1\"' >> /etc/sysmonitor/memory");

    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP + 1);
    ret = exec_cmd_test("cat /home/sys_res.log | grep \"show_memory_info end.\"");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_res.log | grep \"sysrq show memory info in message.\"");
    CU_ASSERT(ret == 0);

    (void)exec_cmd_test("rm -rf /etc/sysmonitor/memory");
    (void)exec_cmd_test("mv /etc/sysmonitor/memory-bak /etc/sysmonitor/memory");
}

static void test_cpu_monitor_fun_001()
{
    int ret;

    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    (void)exec_cmd_test("mv /etc/sysmonitor/cpu /etc/sysmonitor/cpu-bak");
    (void)sys_resources_monitor_parse("CPU_MONITOR", "OFF", CPU, true);
    (void)sys_resources_monitor_parse("MEM_MONITOR", "OFF", MEM, true);
    (void)sys_resources_monitor_parse("PSCNT_MONITOR", "OFF", PSCNT, true);
    (void)sys_resources_monitor_parse("FDCNT_MONITOR", "OFF", SYSTEM_FDCNT, true);
    sys_resources_item_init();
    (void)exec_cmd_test("echo 'ALARM=\"2\"' > /etc/sysmonitor/cpu");
    (void)exec_cmd_test("echo 'RESUME=\"1\"' >> /etc/sysmonitor/cpu");
    (void)exec_cmd_test("echo 'MONITOR_PERIOD=\"1\"' >> /etc/sysmonitor/cpu");
    (void)exec_cmd_test("echo 'STAT_PERIOD=\"1\"' >> /etc/sysmonitor/cpu");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'cpu monitor starting up'");
    CU_ASSERT(ret != 0);

    (void)sys_resources_monitor_parse("CPU_MONITOR", "ON", CPU, true);
    sys_resources_item_init();
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'cpu monitor starting up'");
    CU_ASSERT(ret == 0);
}

static void test_cpu_monitor_fun_002()
{
    int ret;

    (void)exec_cmd_test("rm -rf /etc/sysmonitor/cpu");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'open /etc/sysmonitor/cpu error'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("echo 'TESTLONGITEMTESTLONGITEMTESTLONGITEMTESTLONGITEMTESTLONGITEM=\"123\"' "
                        "> /etc/sysmonitor/cpu");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'parse_line: item length(60) too long(>50)'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'cpu monitor: configuration illegal'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    (void)exec_cmd_test("echo 'ALARM=\"80\"' > /etc/sysmonitor/cpu");
    (void)exec_cmd_test("echo 'RESUME=\"90\"' >> /etc/sysmonitor/cpu");
    (void)exec_cmd_test("echo 'MONITOR_PERIOD=\"1\"' >> /etc/sysmonitor/cpu");
    (void)exec_cmd_test("echo 'STAT_PERIOD=\"1\"' >> /etc/sysmonitor/cpu");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'cpu monitor: configuration illegal'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("echo 'ALARM=\"90\"' > /etc/sysmonitor/cpu");
    (void)exec_cmd_test("echo 'RESUME=\"80\"' >> /etc/sysmonitor/cpu");
    (void)exec_cmd_test("echo 'MONITOR_PERIOD=\"1\"' >> /etc/sysmonitor/cpu");
    (void)exec_cmd_test("echo 'STAT_PERIOD=\"1\"' >> /etc/sysmonitor/cpu");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'cpu monitor starting up'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'system resource monitor period: 1'");
    CU_ASSERT(ret == 0);
}

static void test_cpu_monitor_fun_003()
{
    int ret;

    (void)exec_cmd_test("echo 'ALARM=\"0.05\"' > /etc/sysmonitor/cpu");
    (void)exec_cmd_test("echo 'RESUME=\"0.01\"' >> /etc/sysmonitor/cpu");
    (void)exec_cmd_test("echo 'MONITOR_PERIOD=\"1\"' >> /etc/sysmonitor/cpu");
    (void)exec_cmd_test("echo 'STAT_PERIOD=\"1\"' >> /etc/sysmonitor/cpu");
    (void)exec_cmd_test("echo '#! /bin/bash' > /home/generate_cpu_usage.sh");
    (void)exec_cmd_test("echo 'while ((1))' >> /home/generate_cpu_usage.sh");
    (void)exec_cmd_test("echo 'do' >> /home/generate_cpu_usage.sh");
    (void)exec_cmd_test("echo 'echo 111 > /dev/null' >> /home/generate_cpu_usage.sh");
    (void)exec_cmd_test("echo 'done' >> /home/generate_cpu_usage.sh");
    (void)exec_cmd_test("sh /home/generate_cpu_usage.sh &");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'CPU usage alarm:'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("kill -9 $(ps aux | grep generate_cpu | grep -v grep | awk '{print $2}')");
    (void)exec_cmd_test("rm -rf /home/generate_cpu_usage.sh");
    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    (void)exec_cmd_test("echo 'ALARM=\"90\"' > /etc/sysmonitor/cpu");
    (void)exec_cmd_test("echo 'RESUME=\"80\"' >> /etc/sysmonitor/cpu");
    (void)exec_cmd_test("echo 'MONITOR_PERIOD=\"1\"' >> /etc/sysmonitor/cpu");
    (void)exec_cmd_test("echo 'STAT_PERIOD=\"1\"' >> /etc/sysmonitor/cpu");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'CPU usage resume:'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("rm -rf /etc/sysmonitor/cpu && mv /etc/sysmonitor/cpu-bak /etc/sysmonitor/cpu");
}

static void test_cpu_domain_loadconf_abn_001(void)
{
    int ret;

    (void)exec_cmd_test("mv /etc/sysmonitor/cpu /etc/sysmonitor/cpu-bak");
    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    (void)exec_cmd_test("echo 'DOMAIN=\"a,0,1\"' >> /etc/sysmonitor/cpu");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'DOMAIN config illegal, check a,0,1'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'cpu monitor: configuration illegal'");
    CU_ASSERT(ret == 0);

    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    (void)exec_cmd_test("echo 'DOMAIN=\"0,1,513\"' >> /etc/sysmonitor/cpu");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'invalid CPU ID: 513'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'cpu monitor: configuration illegal'");
    CU_ASSERT(ret == 0);

    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    (void)exec_cmd_test("echo 'DOMAIN=\"-1\"' >> /etc/sysmonitor/cpu");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'DOMAIN config illegal, check -1'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'cpu monitor: configuration illegal'");
    CU_ASSERT(ret == 0);

    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    (void)exec_cmd_test("echo 'DOMAIN=\"0-1,a\"' >> /etc/sysmonitor/cpu");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'DOMAIN config illegal, check 0-1,a'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'cpu monitor: configuration illegal'");
    CU_ASSERT(ret == 0);

    (void)exec_cmd_test("rm -rf /etc/sysmonitor/cpu && mv /etc/sysmonitor/cpu-bak /etc/sysmonitor/cpu");
}

static void test_cpu_domain_loadconf_abn_002(void)
{
    int ret;

    (void)exec_cmd_test("mv /etc/sysmonitor/cpu /etc/sysmonitor/cpu-bak");
    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    (void)exec_cmd_test("echo 'DOMAIN=\"a-1\"' > /etc/sysmonitor/cpu");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'DOMAIN config illegal, check a-1'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'cpu monitor: configuration illegal'");
    CU_ASSERT(ret == 0);

    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    (void)exec_cmd_test("echo 'DOMAIN=\"2-1\"' > /etc/sysmonitor/cpu");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'invalid CPU range: 2-1'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'cpu monitor: configuration illegal'");
    CU_ASSERT(ret == 0);

    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    (void)exec_cmd_test("echo 'DOMAIN=\"0-513\"' > /etc/sysmonitor/cpu");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'invalid CPU ID: 513'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'cpu monitor: configuration illegal'");
    CU_ASSERT(ret == 0);

    (void)exec_cmd_test("rm -rf /etc/sysmonitor/cpu && mv /etc/sysmonitor/cpu-bak /etc/sysmonitor/cpu");
}

static void test_cpu_domain_loadconf_abn_003(void)
{
    int ret;

    (void)exec_cmd_test("mv /etc/sysmonitor/cpu /etc/sysmonitor/cpu-bak");
    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    (void)exec_cmd_test("echo 'DOMAIN=\"0\" ALARM=\"1\" RESUME=\"2\"' > /etc/sysmonitor/cpu");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'invalid CPU alarm/resume value:  1.0%, 2.0%'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'cpu monitor: configuration illegal'");
    CU_ASSERT(ret == 0);

    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    (void)exec_cmd_test("echo 'DOMAIN=\"0\" ALARM=\"abc\" RESUME=\"2\"' > /etc/sysmonitor/cpu");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'invalid CPU alarm value: abc'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'cpu monitor: configuration illegal'");
    CU_ASSERT(ret == 0);

    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    (void)exec_cmd_test("echo 'DOMAIN=\"0\" ALARM=\"2\" RESUME=\"abc\"' > /etc/sysmonitor/cpu");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'invalid CPU resume value: abc'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'cpu monitor: configuration illegal'");
    CU_ASSERT(ret == 0);

    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    (void)exec_cmd_test("echo 'DOMAIN=\"0\" ALARM=\"9.999999999\" RESUME=\"2\"' > /etc/sysmonitor/cpu");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'parse ALARM failed, length exceeds'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'cpu monitor: configuration illegal'");
    CU_ASSERT(ret == 0);

    (void)exec_cmd_test("rm -rf /etc/sysmonitor/cpu && mv /etc/sysmonitor/cpu-bak /etc/sysmonitor/cpu");
}

static void test_cpu_domain_loadconf_abn_004(void)
{
    int ret;

    (void)exec_cmd_test("mv /etc/sysmonitor/cpu /etc/sysmonitor/cpu-bak");
    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    (void)exec_cmd_test("echo 'DOMAIN=\"0,1,1\"' > /etc/sysmonitor/cpu");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'repeated CPU ID 1'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'cpu monitor: configuration illegal'");
    CU_ASSERT(ret == 0);

    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    (void)exec_cmd_test("echo 'DOMAIN=\"0,1\"' > /etc/sysmonitor/cpu");
    (void)exec_cmd_test("echo 'DOMAIN=\"1-2\"' >> /etc/sysmonitor/cpu");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'repeated CPU ID 1'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'cpu monitor: configuration illegal'");
    CU_ASSERT(ret == 0);

    (void)exec_cmd_test("rm -rf /etc/sysmonitor/cpu && mv /etc/sysmonitor/cpu-bak /etc/sysmonitor/cpu");
}

static void test_cpu_domain_loadconf_abn_005(void)
{
    int ret;

    (void)exec_cmd_test("mv /etc/sysmonitor/cpu /etc/sysmonitor/cpu-bak");
    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    (void)exec_cmd_test("echo 'DOMAIN=\"-\"' > /etc/sysmonitor/cpu");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'DOMAIN config illegal, check -'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'cpu monitor: configuration illegal'");
    CU_ASSERT(ret == 0);

    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    (void)exec_cmd_test("echo 'DOMAIN=\",\"' > /etc/sysmonitor/cpu");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'DOMAIN config illegal, check ,'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'cpu monitor: configuration illegal'");
    CU_ASSERT(ret == 0);

    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    (void)exec_cmd_test("echo 'DOMAIN=\"-,\"' > /etc/sysmonitor/cpu");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'DOMAIN config illegal, check -,'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'cpu monitor: configuration illegal'");
    CU_ASSERT(ret == 0);

    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    (void)exec_cmd_test("echo 'DOMAIN=\",1\"' > /etc/sysmonitor/cpu");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'DOMAIN config illegal, check ,1'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'cpu monitor: configuration illegal'");
    CU_ASSERT(ret == 0);

    (void)exec_cmd_test("rm -rf /etc/sysmonitor/cpu && mv /etc/sysmonitor/cpu-bak /etc/sysmonitor/cpu");
}


static void test_cpu_domain_loadconf_abn_006(void)
{
    int ret;

    (void)exec_cmd_test("mv /etc/sysmonitor/cpu /etc/sysmonitor/cpu-bak");
    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    (void)exec_cmd_test("echo 'DOMAIN=\"1,,2\"' > /etc/sysmonitor/cpu");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'DOMAIN config illegal, check 1,,2'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'cpu monitor: configuration illegal'");
    CU_ASSERT(ret == 0);

    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    (void)exec_cmd_test("echo 'DOMAIN=\"1--7\"' > /etc/sysmonitor/cpu");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'DOMAIN config illegal, check 1--7'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'cpu monitor: configuration illegal'");
    CU_ASSERT(ret == 0);

    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    (void)exec_cmd_test("echo 'DOMAIN=\"1-2-7\"' > /etc/sysmonitor/cpu");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'DOMAIN config illegal, check 1-2-7'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'cpu monitor: configuration illegal'");
    CU_ASSERT(ret == 0);

    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    (void)exec_cmd_test("echo 'DOMAIN=\"1-,2\"' > /etc/sysmonitor/cpu");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'DOMAIN config illegal, check 1-,2'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'cpu monitor: configuration illegal'");
    CU_ASSERT(ret == 0);

    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    (void)exec_cmd_test("echo 'DOMAIN=\"1,-2\"' > /etc/sysmonitor/cpu");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'DOMAIN config illegal, check 1,-2'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'cpu monitor: configuration illegal'");
    CU_ASSERT(ret == 0);

    (void)exec_cmd_test("rm -rf /etc/sysmonitor/cpu && mv /etc/sysmonitor/cpu-bak /etc/sysmonitor/cpu");
}

static void test_cpu_domain_loadconf_abn_007(void)
{
    int ret;

    (void)exec_cmd_test("mv /etc/sysmonitor/cpu /etc/sysmonitor/cpu-bak");

    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    (void)exec_cmd_test("echo 'DOMAIN=\"1,2,\"' > /etc/sysmonitor/cpu");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'DOMAIN config illegal, check 1,2,'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'cpu monitor: configuration illegal'");
    CU_ASSERT(ret == 0);

    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    (void)exec_cmd_test("echo 'DOMAIN=\"1,2-\"' > /etc/sysmonitor/cpu");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'DOMAIN config illegal, check 1,2-'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'cpu monitor: configuration illegal'");
    CU_ASSERT(ret == 0);

    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    (void)exec_cmd_test("echo 'DOMAIN=\"0\" ALARM=\"99999999\" RESUME=\"88888888\"' > /etc/sysmonitor/cpu");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'parse ALARM failed, length exceeds 7'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'cpu monitor: configuration illegal'");
    CU_ASSERT(ret == 0);

    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    (void)exec_cmd_test("echo 'DOMAIN=\"0\" ALARM=\"90\" RESUME=\"-2\"' > /etc/sysmonitor/cpu");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'invalid CPU resume value'");
    CU_ASSERT(ret == 0);

    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    (void)exec_cmd_test("echo 'DOMAIN=\"0\" ALARM=\"101\" RESUME=\"80\"' > /etc/sysmonitor/cpu");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'invalid CPU alarm/resume value'");
    CU_ASSERT(ret == 0);

    (void)exec_cmd_test("rm -rf /etc/sysmonitor/cpu && mv /etc/sysmonitor/cpu-bak /etc/sysmonitor/cpu");
}

static void test_cpu_domain_monitor_fun_001(void)
{
    int ret;

    (void)exec_cmd_test("mv /etc/sysmonitor/cpu /etc/sysmonitor/cpu-bak");
    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    (void)exec_cmd_test("echo 'MONITOR_PERIOD=\"1\"' > /etc/sysmonitor/cpu");
    (void)exec_cmd_test("echo 'STAT_PERIOD=\"1\"' >> /etc/sysmonitor/cpu");
    (void)exec_cmd_test("echo 'DOMAIN=\"0\" ALARM=\"0.05\" RESUME=\"0.01\"' >> /etc/sysmonitor/cpu");
    init_generate_cpu_usage();
    (void)exec_cmd_test("taskset -c 0 sh /home/generate_cpu_usage.sh &");

    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'CPU 0 usage alarm:'");
    CU_ASSERT(ret == 0);

    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    clear_generate_cpu_usage();
    (void)exec_cmd_test("echo 'MONITOR_PERIOD=\"1\"' > /etc/sysmonitor/cpu");
    (void)exec_cmd_test("echo 'STAT_PERIOD=\"1\"' >> /etc/sysmonitor/cpu");
    (void)exec_cmd_test("echo 'DOMAIN=\"0\" ALARM=\"90\" RESUME=\"80\"' >> /etc/sysmonitor/cpu");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'CPU 0 usage resume:'");
    CU_ASSERT(ret == 0);

    (void)exec_cmd_test("rm -rf /etc/sysmonitor/cpu && mv /etc/sysmonitor/cpu-bak /etc/sysmonitor/cpu");
}

static void test_cpu_domain_monitor_fun_002(void)
{
    int ret;

    (void)exec_cmd_test("mv /etc/sysmonitor/cpu /etc/sysmonitor/cpu-bak");
    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    (void)exec_cmd_test("echo 'ALARM=\"0.05\"' > /etc/sysmonitor/cpu");
    (void)exec_cmd_test("echo 'RESUME=\"0.01\"' >> /etc/sysmonitor/cpu");
    (void)exec_cmd_test("echo 'MONITOR_PERIOD=\"1\"' >> /etc/sysmonitor/cpu");
    (void)exec_cmd_test("echo 'STAT_PERIOD=\"1\"' >> /etc/sysmonitor/cpu");
    (void)exec_cmd_test("echo 'DOMAIN=\"0\" ALARM=\"90\" RESUME=\"80\"' >> /etc/sysmonitor/cpu");
    init_generate_cpu_usage();
    (void)exec_cmd_test("taskset -c 1 sh /home/generate_cpu_usage.sh &");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'CPU usage alarm:'");
    CU_ASSERT(ret != 0);

    clear_generate_cpu_usage();
    (void)exec_cmd_test("rm -rf /etc/sysmonitor/cpu && mv /etc/sysmonitor/cpu-bak /etc/sysmonitor/cpu");
}

static void test_cpu_domain_monitor_fun_003(void)
{
    int ret;

    (void)exec_cmd_test("mv /etc/sysmonitor/cpu /etc/sysmonitor/cpu-bak");
    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    (void)exec_cmd_test("echo 'MONITOR_PERIOD=\"1\"' > /etc/sysmonitor/cpu");
    (void)exec_cmd_test("echo 'STAT_PERIOD=\"1\"' >> /etc/sysmonitor/cpu");
    (void)exec_cmd_test("echo 'DOMAIN=\"0\"' >> /etc/sysmonitor/cpu");
    (void)exec_cmd_test("echo 'DOMAIN=\"2\"' >> /etc/sysmonitor/cpu");
    g_sysres_info->reload = true;
    (void)exec_cmd_test("echo 0 > /sys/devices/system/cpu/cpu2/online");
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'failed to read CPU 2 stats, check cpu state'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'skip monitor on CPU 2'");
    CU_ASSERT(ret == 0);

    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    (void)exec_cmd_test("echo 'MONITOR_PERIOD=\"1\"' > /etc/sysmonitor/cpu");
    (void)exec_cmd_test("echo 'STAT_PERIOD=\"1\"' >> /etc/sysmonitor/cpu");
    (void)exec_cmd_test("echo 'DOMAIN=\"0\"' >> /etc/sysmonitor/cpu");
    (void)exec_cmd_test("echo 'DOMAIN=\"1\" ALARM=\"0.05\" RESUME=\"0.01\"' >> /etc/sysmonitor/cpu");
    init_generate_cpu_usage();
    (void)exec_cmd_test("taskset -c 1 sh /home/generate_cpu_usage.sh &");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'CPU 1 usage alarm:'");
    CU_ASSERT(ret == 0);

    clear_generate_cpu_usage();
    (void)exec_cmd_test("echo 1 > /sys/devices/system/cpu/cpu2/online");
    (void)exec_cmd_test("rm -rf /etc/sysmonitor/cpu && mv /etc/sysmonitor/cpu-bak /etc/sysmonitor/cpu");
}

static void test_cpu_reportcmd_abn_001(void)
{
    int ret;

    (void)exec_cmd_test("mv /etc/sysmonitor/cpu /etc/sysmonitor/cpu-bak");
    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    (void)exec_cmd_test("echo 'REPORT_COMMAND=\"0123456789012345678901234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789012345678901234567890123456789"
                        "0123456789\"' > /etc/sysmonitor/cpu");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'parse REPORT_COMMAND failed'");
    CU_ASSERT(ret == 0);

    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    (void)exec_cmd_test("echo 'REPORT_COMMAND=\"!@#$%^&*()\"' > /etc/sysmonitor/cpu");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'include nonsecure character!' | grep '!@#' | grep '()'");
    CU_ASSERT(ret == 0);

    (void)exec_cmd_test("rm -rf /etc/sysmonitor/cpu && mv /etc/sysmonitor/cpu-bak /etc/sysmonitor/cpu");
}

static void test_cpu_reportcmd_abn_002(void)
{
    int ret;

    (void)exec_cmd_test("mv /etc/sysmonitor/cpu /etc/sysmonitor/cpu-bak");
    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    (void)exec_cmd_test("echo 'MONITOR_PERIOD=\"1\"' > /etc/sysmonitor/cpu");
    (void)exec_cmd_test("echo 'STAT_PERIOD=\"1\"' >> /etc/sysmonitor/cpu");
    (void)exec_cmd_test("echo 'DOMAIN=\"0-2,3\" ALARM=\"0.05\" RESUME=\"0.01\"' >> /etc/sysmonitor/cpu");
    (void)exec_cmd_test("echo 'REPORT_COMMAND=\"abc\"' >> /etc/sysmonitor/cpu");
    init_generate_cpu_usage();
    (void)exec_cmd_test("taskset -c 0 sh /home/generate_cpu_usage.sh &");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | egrep 'monitor cmd: psz_cmd.* execl error'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_res.log | egrep 'execute REPORT_COMMAND.* failed'");
    CU_ASSERT(ret == 0);
    clear_generate_cpu_usage();

    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    (void)exec_cmd_test("echo 'MONITOR_PERIOD=\"1\"' > /etc/sysmonitor/cpu");
    (void)exec_cmd_test("echo 'STAT_PERIOD=\"1\"' >> /etc/sysmonitor/cpu");
    (void)exec_cmd_test("echo 'DOMAIN=\"1\" ALARM=\"0.05\" RESUME=\"0.01\"' >> /etc/sysmonitor/cpu");
    (void)exec_cmd_test("echo 'REPORT_COMMAND=\"sleep 90\"' >> /etc/sysmonitor/cpu");
    init_generate_cpu_usage();
    (void)exec_cmd_test("taskset -c 1 sh /home/generate_cpu_usage.sh &");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP + REPORT_CMD_TIMEOUT + 1);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'execute \"sleep 90\" timeout'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_res.log | egrep 'execute REPORT_COMMAND.* failed'");
    CU_ASSERT(ret == 0);
    clear_generate_cpu_usage();

    (void)exec_cmd_test("rm -rf /etc/sysmonitor/cpu && mv /etc/sysmonitor/cpu-bak /etc/sysmonitor/cpu");
}

static void test_cpu_reportcmd_fun_001(void)
{
    int ret;

    (void)exec_cmd_test("mv /etc/sysmonitor/cpu /etc/sysmonitor/cpu-bak");
    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    (void)exec_cmd_test("echo 'ALARM=\"0.05\"' > /etc/sysmonitor/cpu");
    (void)exec_cmd_test("echo 'RESUME=\"0.01\"' >> /etc/sysmonitor/cpu");
    (void)exec_cmd_test("echo 'MONITOR_PERIOD=\"1\"' >> /etc/sysmonitor/cpu");
    (void)exec_cmd_test("echo 'STAT_PERIOD=\"1\"' >> /etc/sysmonitor/cpu");
    (void)exec_cmd_test("echo 'REPORT_COMMAND=\"/home/report_cmd.sh\"' >> /etc/sysmonitor/cpu");
    (void)exec_cmd_test("echo '#! /bin/bash' > /home/report_cmd.sh");
    (void)exec_cmd_test("echo 'echo report >> /tmp/test' >> /home/report_cmd.sh");
    (void)exec_cmd_test("chmod +x /home/report_cmd.sh");
    init_generate_cpu_usage();
    (void)exec_cmd_test("taskset -c 2 sh /home/generate_cpu_usage.sh &");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | egrep 'execute REPORT_COMMAND.* successfully'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /tmp/test | grep 'report'");
    CU_ASSERT(ret == 0);

    clear_generate_cpu_usage();
    (void)exec_cmd_test("rm -rf /tmp/test && /home/generate_cpu_usage.sh");
    (void)exec_cmd_test("rm -rf /etc/sysmonitor/cpu && mv /etc/sysmonitor/cpu-bak /etc/sysmonitor/cpu");
}

static void test_cpu_reportcmd_fun_002(void)
{
    int ret;

    (void)exec_cmd_test("mv /etc/sysmonitor/cpu /etc/sysmonitor/cpu-bak");
    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    (void)exec_cmd_test("echo 'MONITOR_PERIOD=\"1\"' > /etc/sysmonitor/cpu");
    (void)exec_cmd_test("echo 'STAT_PERIOD=\"1\"' >> /etc/sysmonitor/cpu");
    (void)exec_cmd_test("echo 'DOMAIN=\"0\" ALARM=\"0.05\" RESUME=\"0.01\"' >> /etc/sysmonitor/cpu");
    (void)exec_cmd_test("echo 'REPORT_COMMAND=\"/home/report_cmd.sh\"' >> /etc/sysmonitor/cpu");
    (void)exec_cmd_test("echo '#! /bin/bash' > /home/report_cmd.sh");
    (void)exec_cmd_test("echo 'echo report >> /tmp/test' >> /home/report_cmd.sh");
    (void)exec_cmd_test("chmod +x /home/report_cmd.sh");
    init_generate_cpu_usage();
    (void)exec_cmd_test("taskset -c 0 sh /home/generate_cpu_usage.sh &");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | egrep 'execute REPORT_COMMAND.* successfully'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /tmp/test | grep 'report'");
    CU_ASSERT(ret == 0);

    clear_generate_cpu_usage();
    (void)exec_cmd_test("rm -rf /tmp/test && /home/generate_cpu_usage.sh");
    (void)exec_cmd_test("rm -rf /etc/sysmonitor/cpu && mv /etc/sysmonitor/cpu-bak /etc/sysmonitor/cpu");
}

static void test_memory_monitor_fun_001()
{
    int ret;

    (void)exec_cmd_test("mv /etc/sysmonitor/memory /etc/sysmonitor/memory-bak");
    (void)sys_resources_monitor_parse("CPU_MONITOR", "OFF", CPU, true);
    (void)sys_resources_monitor_parse("MEM_MONITOR", "OFF", MEM, true);
    (void)sys_resources_monitor_parse("PSCNT_MONITOR", "OFF", PSCNT, true);
    (void)sys_resources_monitor_parse("FDCNT_MONITOR", "OFF", SYSTEM_FDCNT, true);
    (void)exec_cmd_test("echo 'ALARM=\"90\"' > /etc/sysmonitor/memory");
    (void)exec_cmd_test("echo 'RESUME=\"80\"' >> /etc/sysmonitor/memory");
    (void)exec_cmd_test("echo 'PERIOD=\"1\"' >> /etc/sysmonitor/memory");
    sys_resources_item_init();
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'memory monitor starting up'");
    CU_ASSERT(ret != 0);
    (void)sys_resources_monitor_parse("MEM_MONITOR", "ON", MEM, true);
    sys_resources_item_init();
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'memory monitor starting up'");
    CU_ASSERT(ret == 0);
}

static void test_memory_monitor_fun_002()
{
    int ret;

    (void)exec_cmd_test("rm -rf /etc/sysmonitor/memory");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'open /etc/sysmonitor/memory error'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("echo 'TESTLONGITEMTESTLONGITEMTESTLONGITEMTESTLONGITEMTESTLONGITEM=\"123\"' "
                        "> /etc/sysmonitor/memory");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'parse_line: item length(60) too long(>50)'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'memory monitor: configuration illegal'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    (void)exec_cmd_test("echo 'ALARM=\"80\"' > /etc/sysmonitor/memory");
    (void)exec_cmd_test("echo 'RESUME=\"90\"' >> /etc/sysmonitor/memory");
    (void)exec_cmd_test("echo 'PERIOD=\"1\"' >> /etc/sysmonitor/memory");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'memory monitor: configuration illegal'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("echo 'ALARM=\"90\"' > /etc/sysmonitor/memory");
    (void)exec_cmd_test("echo 'RESUME=\"80\"' >> /etc/sysmonitor/memory");
    (void)exec_cmd_test("echo 'PERIOD=\"1\"' >> /etc/sysmonitor/memory");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'memory monitor starting up'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'system resource monitor period: 1'");
    CU_ASSERT(ret == 0);
}

static void test_memory_monitor_fun_003()
{
    int ret;

    (void)exec_cmd_test("echo 'ALARM=\"2\"' > /etc/sysmonitor/memory");
    (void)exec_cmd_test("echo 'RESUME=\"1\"' >> /etc/sysmonitor/memory");
    (void)exec_cmd_test("echo 'PERIOD=\"1\"' >> /etc/sysmonitor/memory");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'memory usage alarm:'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    (void)exec_cmd_test("echo 'ALARM=\"90\"' > /etc/sysmonitor/memory");
    (void)exec_cmd_test("echo 'RESUME=\"80\"' >> /etc/sysmonitor/memory");
    (void)exec_cmd_test("echo 'PERIOD=\"1\"' >> /etc/sysmonitor/memory");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP + 1);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'memory usage resume:'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("rm -rf /etv/sysmonitor/memory && mv /etc/sysmonitor/memory-bak /etc/sysmonitor/memory");
}

static void test_pscnt_monitor_fun_001()
{
    int ret;

    (void)exec_cmd_test("mv /etc/sysmonitor/pscnt /etc/sysmonitor/pscnt-bak");
    (void)sys_resources_monitor_parse("CPU_MONITOR", "OFF", CPU, true);
    (void)sys_resources_monitor_parse("MEM_MONITOR", "OFF", MEM, true);
    (void)sys_resources_monitor_parse("PSCNT_MONITOR", "OFF", PSCNT, true);
    (void)sys_resources_monitor_parse("FDCNT_MONITOR", "OFF", SYSTEM_FDCNT, true);
    (void)exec_cmd_test("echo 'ALARM=\"2\"' > /etc/sysmonitor/pscnt");
    (void)exec_cmd_test("echo 'RESUME=\"1\"' >> /etc/sysmonitor/pscnt");
    (void)exec_cmd_test("echo 'PERIOD=\"1\"' >> /etc/sysmonitor/pscnt");
    sys_resources_item_init();
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'process count monitor starting up'");
    CU_ASSERT(ret != 0);
    (void)sys_resources_monitor_parse("PSCNT_MONITOR", "ON", PSCNT, true);
    sys_resources_item_init();
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'process count monitor starting up'");
    CU_ASSERT(ret == 0);
}

static void test_pscnt_monitor_fun_002()
{
    int ret;

    (void)exec_cmd_test("rm -rf /etc/sysmonitor/pscnt");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'open /etc/sysmonitor/pscnt error'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("echo 'TESTLONGITEMTESTLONGITEMTESTLONGITEMTESTLONGITEMTESTLONGITEM=\"123\"' "
                        "> /etc/sysmonitor/pscnt");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'parse_line: item length(60) too long(>50)'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'process count monitor: configuration illegal'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    (void)exec_cmd_test("echo 'ALARM=\"1500\"' > /etc/sysmonitor/pscnt");
    (void)exec_cmd_test("echo 'RESUME=\"1600\"' >> /etc/sysmonitor/pscnt");
    (void)exec_cmd_test("echo 'PERIOD=\"1\"' >> /etc/sysmonitor/pscnt");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'process count monitor: configuration illegal'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("echo 'ALARM=\"1600\"' > /etc/sysmonitor/pscnt");
    (void)exec_cmd_test("echo 'RESUME=\"1500\"' >> /etc/sysmonitor/pscnt");
    (void)exec_cmd_test("echo 'PERIOD=\"1\"' >> /etc/sysmonitor/pscnt");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'process count monitor starting up'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'system resource monitor period: 1'");
    CU_ASSERT(ret == 0);
}

static void test_monitor_process_count()
{
    int ret;
    int i;

    for (i = 0; i < MAX_PSCNT_TEST; i++) {
        (void)exec_cmd_test("sleep 1024 &");
    }

    (void)exec_cmd_test("echo 'ALARM=\"2\"' > /etc/sysmonitor/pscnt");
    (void)exec_cmd_test("echo 'RESUME=\"1\"' >> /etc/sysmonitor/pscnt");
    (void)exec_cmd_test("echo 'PERIOD=\"1\"' >> /etc/sysmonitor/pscnt");
    (void)exec_cmd_test("echo 'ALARM_RATIO=\"0.1\"' >> /etc/sysmonitor/pscnt");
    (void)exec_cmd_test("echo 'RESUME_RATIO=\"0.01\"' >> /etc/sysmonitor/pscnt");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP + 1);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'process count alarm:'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'process count alarm, show sys fd count'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'process count alarm, show mem info'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("kill -9 $(ps aux | grep \"sleep 1024\" | grep -v grep | awk '{print $2}')");
    (void)exec_cmd_test("echo 'ALARM=\"1600\"' > /etc/sysmonitor/pscnt");
    (void)exec_cmd_test("echo 'RESUME=\"1500\"' >> /etc/sysmonitor/pscnt");
    (void)exec_cmd_test("echo 'PERIOD=\"1\"' >> /etc/sysmonitor/pscnt");
    (void)exec_cmd_test("echo 'ALARM_RATIO=\"90\"' >> /etc/sysmonitor/pscnt");
    (void)exec_cmd_test("echo 'RESUME_RATIO=\"80\"' >> /etc/sysmonitor/pscnt");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP + 1);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'process count resume:'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("rm -rf /etv/sysmonitor/pscnt && mv /etc/sysmonitor/pscnt-bak /etc/sysmonitor/pscnt");
}

static void test_sysfd_monitor_fun_001()
{
    int ret;

    (void)exec_cmd_test("mv /etc/sysmonitor/sys_fd_conf /etc/sysmonitor/sys_fd_conf-bak");
    (void)exec_cmd_test("mv /etc/sysmonitor/memory /etc/sysmonitor/memory-bak");
    (void)exec_cmd_test("echo 'SYS_FD_ALARM=\"90\"' > /etc/sysmonitor/memory");
    (void)exec_cmd_test("echo 'SYS_FD_RESUME=\"80\"' >> /etc/sysmonitor/memory");
    (void)exec_cmd_test("echo 'SYS_FD_PERIOD=\"1\"' >> /etc/sysmonitor/memory");
    (void)sys_resources_monitor_parse("CPU_MONITOR", "OFF", CPU, true);
    (void)sys_resources_monitor_parse("MEM_MONITOR", "ON", MEM, true);
    (void)sys_resources_monitor_parse("PSCNT_MONITOR", "OFF", PSCNT, true);
    (void)sys_resources_monitor_parse("FDCNT_MONITOR", "OFF", SYSTEM_FDCNT, true);
    (void)exec_cmd_test("echo 'SYS_FD_ALARM=\"2\"' > /etc/sysmonitor/sys_fd_conf");
    (void)exec_cmd_test("echo 'SYS_FD_RESUME=\"1\"' >> /etc/sysmonitor/sys_fd_conf");
    (void)exec_cmd_test("echo 'SYS_FD_PERIOD=\"1\"' >> /etc/sysmonitor/sys_fd_conf");
    sys_resources_item_init();
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'system fd num monitor starting up'");
    CU_ASSERT(ret != 0);
    (void)sys_resources_monitor_parse("FDCNT_MONITOR", "ON", SYSTEM_FDCNT, true);
    sys_resources_item_init();
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'system fd num monitor starting up'");
    CU_ASSERT(ret == 0);
}

static void test_sysfd_monitor_fun_002()
{
    int ret;

    (void)exec_cmd_test("rm -rf /etc/sysmonitor/sys_fd_conf");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'open /etc/sysmonitor/sys_fd_conf error'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("echo 'TESTLONGITEMTESTLONGITEMTESTLONGITEMTESTLONGITEMTESTLONGITEM=\"123\"' "
                        "> /etc/sysmonitor/sys_fd_conf");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'parse_line: item length(60) too long(>50)'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_res.log | "
                        "grep 'system fd num monitor: configuration illegal,use default value'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    (void)exec_cmd_test("echo 'SYS_FD_ALARM=\"80\"' > /etc/sysmonitor/sys_fd_conf");
    (void)exec_cmd_test("echo 'SYS_FD_RESUME=\"90\"' >> /etc/sysmonitor/sys_fd_conf");
    (void)exec_cmd_test("echo 'SYS_FD_PERIOD=\"1\"' >> /etc/sysmonitor/sys_fd_conf");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | "
                        "grep 'system fd num monitor: configuration illegal,use default value'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    (void)exec_cmd_test("echo 'SYS_FD_ALARM=\"90\"' > /etc/sysmonitor/sys_fd_conf");
    (void)exec_cmd_test("echo 'SYS_FD_RESUME=\"80\"' >> /etc/sysmonitor/sys_fd_conf");
    (void)exec_cmd_test("echo 'SYS_FD_PERIOD=\"1\"' >> /etc/sysmonitor/sys_fd_conf");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'system fd num monitor starting up'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'system resource monitor period: 1'");
    CU_ASSERT(ret == 0);
}

static void generate_fd(void)
{
    int i;
    char temp[MAX_TEMPSTR] = {0};
    float num;

    (void)monitor_popen("cat /proc/sys/fs/file-max", temp, sizeof(temp) - 1, 0, NULL);
    num = strtof(temp, NULL) * FD_ALARM_RATIO / GENERATE_FD_NUM;
    if (num <= 0) {
        num = GENERATE_NUM_DEFAULT;
    }
    for (i = 0; i < (int)num; i++) {
        (void)exec_cmd_test("./sys_resources/generate_fd &");
    }
}

static void test_sysfd_monitor_fun_003()
{
    int ret;

    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    (void)exec_cmd_test("echo 'SYS_FD_ALARM=\"2\"' > /etc/sysmonitor/sys_fd_conf");
    (void)exec_cmd_test("echo 'SYS_FD_RESUME=\"1\"' >> /etc/sysmonitor/sys_fd_conf");
    (void)exec_cmd_test("echo 'SYS_FD_PERIOD=\"1\"' >> /etc/sysmonitor/sys_fd_conf");
    generate_fd();
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'sys fd count alarm:'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'open fd most three processes is:' | grep 'top1:pid'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'open fd most three processes is:' | grep 'top2:pid'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'open fd most three processes is:' | grep 'top3:pid'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("kill -9 $(ps aux | grep generate_fd | grep -v grep | awk '{print $2}')");
    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    (void)exec_cmd_test("echo 'SYS_FD_ALARM=\"90\"' > /etc/sysmonitor/sys_fd_conf");
    (void)exec_cmd_test("echo 'SYS_FD_RESUME=\"80\"' >> /etc/sysmonitor/sys_fd_conf");
    (void)exec_cmd_test("echo 'SYS_FD_PERIOD=\"1\"' >> /etc/sysmonitor/sys_fd_conf");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'sys fd count resume:'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("rm -rf /etv/sysmonitor/memory && mv /etc/sysmonitor/memory-bak /etc/sysmonitor/memory");
    (void)exec_cmd_test("rm -rf /etv/sysmonitor/sys_fd_conf &&"
                        " mv /etc/sysmonitor/sys_fd_conf-bak /etc/sysmonitor/sys_fd_conf");
}

static void test_sys_resources_period(void)
{
    int ret;

    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    (void)sys_resources_monitor_parse("CPU_MONITOR", "ON", CPU, true);
    (void)sys_resources_monitor_parse("MEM_MONITOR", "ON", MEM, true);
    (void)sys_resources_monitor_parse("PSCNT_MONITOR", "ON", PSCNT, true);
    (void)sys_resources_monitor_parse("FDCNT_MONITOR", "ON", SYSTEM_FDCNT, true);
    sys_resources_item_init();
    (void)exec_cmd_test("mv /etc/sysmonitor/cpu /etc/sysmonitor/cpu-bak");
    (void)exec_cmd_test("mv /etc/sysmonitor/memory /etc/sysmonitor/memory-bak");
    (void)exec_cmd_test("mv /etc/sysmonitor/pscnt /etc/sysmonitor/pscnt-bak");
    (void)exec_cmd_test("mv /etc/sysmonitor/sys_fd_conf /etc/sysmonitor/sys_fd_conf-bak");
    (void)exec_cmd_test("echo 'ALARM=\"90\"' > /etc/sysmonitor/cpu");
    (void)exec_cmd_test("echo 'RESUME=\"80\"' >> /etc/sysmonitor/cpu");
    (void)exec_cmd_test("echo 'MONITOR_PERIOD=\"5\"' >> /etc/sysmonitor/cpu");
    (void)exec_cmd_test("echo 'STAT_PERIOD=\"5\"' >> /etc/sysmonitor/cpu");
    (void)exec_cmd_test("echo 'ALARM=\"90\"' > /etc/sysmonitor/memory");
    (void)exec_cmd_test("echo 'RESUME=\"80\"' >> /etc/sysmonitor/memory");
    (void)exec_cmd_test("echo 'PERIOD=\"60\"' >> /etc/sysmonitor/memory");
    (void)exec_cmd_test("echo 'ALARM=\"1600\"' > /etc/sysmonitor/pscnt");
    (void)exec_cmd_test("echo 'RESUME=\"1500\"' >> /etc/sysmonitor/pscnt");
    (void)exec_cmd_test("echo 'PERIOD=\"1\"' >> /etc/sysmonitor/pscnt");
    (void)exec_cmd_test("echo 'SYS_FD_ALARM=\"80\"' > /etc/sysmonitor/sys_fd_conf");
    (void)exec_cmd_test("echo 'SYS_FD_RESUME=\"70\"' >> /etc/sysmonitor/sys_fd_conf");
    (void)exec_cmd_test("echo 'SYS_FD_PERIOD=\"600\"' >> /etc/sysmonitor/sys_fd_conf");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'cpu monitor starting up'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'memory monitor starting up'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'process count monitor starting up'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'system fd num monitor starting up'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'system resource monitor period: 1'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("mv /etc/sysmonitor/cpu-bak /etc/sysmonitor/cpu");
    (void)exec_cmd_test("mv /etc/sysmonitor/memory-bak /etc/sysmonitor/memory");
    (void)exec_cmd_test("mv /etc/sysmonitor/pscnt-bak /etc/sysmonitor/pscnt");
    (void)exec_cmd_test("mv /etc/sysmonitor/sys_fd_conf-bak /etc/sysmonitor/sys_fd_conf");
}

static void test_sys_resources_monitor_fun_001()
{
    int ret;

    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    (void)sys_resources_monitor_parse("CPU_MONITOR", "ON", CPU, true);
    (void)sys_resources_monitor_parse("MEM_MONITOR", "ON", MEM, true);
    (void)sys_resources_monitor_parse("PSCNT_MONITOR", "ON", PSCNT, true);
    (void)sys_resources_monitor_parse("FDCNT_MONITOR", "ON", SYSTEM_FDCNT, true);
    sys_resources_item_init();
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'cpu monitor starting up'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'memory monitor starting up'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'process count monitor starting up'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'system fd num monitor starting up'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'system resource monitor period: 60'");
    CU_ASSERT(ret == 0);
    (void)sys_resources_monitor_parse("CPU_MONITOR", "OFF", CPU, true);
    (void)sys_resources_monitor_parse("MEM_MONITOR", "OFF", MEM, true);
    (void)sys_resources_monitor_parse("PSCNT_MONITOR", "OFF", PSCNT, true);
    (void)sys_resources_monitor_parse("FDCNT_MONITOR", "OFF", SYSTEM_FDCNT, true);
    sys_resources_item_init();
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP_TEST);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'calculate for g_sys_res_period failed, use default 1'");
    CU_ASSERT(ret == 0);
    test_sys_resources_period();
}

static void pscnt_set_conf_file(void)
{
    (void)exec_cmd_test("echo 'ALARM=\"1600\"' > /etc/sysmonitor/pscnt");
    (void)exec_cmd_test("echo 'RESUME=\"1500\"' >> /etc/sysmonitor/pscnt");
    (void)exec_cmd_test("echo 'PERIOD=\"1\"' >> /etc/sysmonitor/pscnt");
    (void)exec_cmd_test("echo 'ALARM_RATIO=\"90\"' >> /etc/sysmonitor/pscnt");
    (void)exec_cmd_test("echo 'RESUME_RATIO=\"80\"' >> /etc/sysmonitor/pscnt");
}

static void test_parse_and_check_threads_top_num()
{
    int ret;

    (void)exec_cmd_test("mv /etc/sysmonitor/pscnt /etc/sysmonitor/pscnt-bak");
    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    pscnt_set_conf_file();
    (void)exec_cmd_test("echo 'SHOW_TOP_PROC_NUM=\"-1\"' >> /etc/sysmonitor/pscnt");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP_PSCNT);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'process count monitor: configuration illegal'");
    CU_ASSERT(ret == 0);

    /* test for SHOW_TOP_PROC_NUM = 1025 */
    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    (void)exec_cmd_test("sed -i 's/SHOW_TOP_PROC_NUM=\"0\"/SHOW_TOP_PROC_NUM=\"1025\"/g' /etc/sysmonitor/pscnt");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP_PSCNT);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'process count monitor: configuration illegal'");
    CU_ASSERT(ret == 0);

    /* test for SHOW_TOP_PROC_NUM = 1 */
    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    pscnt_set_conf_file();
    (void)exec_cmd_test("echo 'SHOW_TOP_PROC_NUM=\"1\"' >> /etc/sysmonitor/pscnt");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP_PSCNT);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'process count monitor starting up'");
    CU_ASSERT(ret == 0);

    /* test for SHOW_TOP_PROC_NUM = 10 */
    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    pscnt_set_conf_file();
    (void)exec_cmd_test("echo 'SHOW_TOP_PROC_NUM=\"10\"' >> /etc/sysmonitor/pscnt");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP_PSCNT);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'process count monitor starting up'");
    CU_ASSERT(ret == 0);

    /* test for SHOW_TOP_PROC_NUM = 1024 */
    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    pscnt_set_conf_file();
    (void)exec_cmd_test("echo 'SHOW_TOP_PROC_NUM=\"1024\"' >> /etc/sysmonitor/pscnt");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP_PSCNT);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'process count monitor starting up'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("rm -rf /etv/sysmonitor/pscnt && mv /etc/sysmonitor/pscnt-bak /etc/sysmonitor/pscnt");
}

static void test_monitor_threads_top_num_resume(void)
{
    int ret;

    pscnt_set_conf_file();
    (void)exec_cmd_test("echo 'SHOW_TOP_PROC_NUM=\"10\"' >> /etc/sysmonitor/pscnt");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP_PSCNT);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'threads count resume'");
    CU_ASSERT(ret == 0);
}
void *create_pthreads_func(void *arg)
{
    (void)sleep(TIME_SLEEP_THREADS);
    return NULL;
}

static void create_pthreads(unsigned int num)
{
    unsigned int i;
    pthread_t tid;

    for (i = 0; i < num; i++) {
        (void)pthread_create(&tid, NULL, create_pthreads_func, NULL);
    }
}

static void test_monitor_threads_top_num_min()
{
    int ret;

    /* test for min SHOW_TOP_PROC_NUM = 1 */
    (void)exec_cmd_test("mv /etc/sysmonitor/pscnt /etc/sysmonitor/pscnt-bak");
    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    (void)exec_cmd_test("echo 'ALARM=\"2\"' > /etc/sysmonitor/pscnt");
    (void)exec_cmd_test("echo 'RESUME=\"1\"' >> /etc/sysmonitor/pscnt");
    (void)exec_cmd_test("echo 'PERIOD=\"1\"' >> /etc/sysmonitor/pscnt");
    (void)exec_cmd_test("echo 'ALARM_RATIO=\"0.02\"' >> /etc/sysmonitor/pscnt");
    (void)exec_cmd_test("echo 'RESUME_RATIO=\"0.01\"' >> /etc/sysmonitor/pscnt");
    (void)exec_cmd_test("echo 'SHOW_TOP_PROC_NUM=\"1\"' >> /etc/sysmonitor/pscnt");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP_PSCNT);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'open threads most 1 processes is'");
    CU_ASSERT(ret == 0);
    test_monitor_threads_top_num_resume();
    (void)exec_cmd_test("rm -rf /etv/sysmonitor/pscnt && mv /etc/sysmonitor/pscnt-bak /etc/sysmonitor/pscnt");
}


static void test_monitor_threads_top_num_zero()
{
    int ret;

    /* test for min SHOW_TOP_PROC_NUM = 1 */
    (void)exec_cmd_test("mv /etc/sysmonitor/pscnt /etc/sysmonitor/pscnt-bak");
    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    (void)exec_cmd_test("echo 'ALARM=\"2\"' > /etc/sysmonitor/pscnt");
    (void)exec_cmd_test("echo 'RESUME=\"1\"' >> /etc/sysmonitor/pscnt");
    (void)exec_cmd_test("echo 'PERIOD=\"1\"' >> /etc/sysmonitor/pscnt");
    (void)exec_cmd_test("echo 'ALARM_RATIO=\"0.02\"' >> /etc/sysmonitor/pscnt");
    (void)exec_cmd_test("echo 'RESUME_RATIO=\"0.01\"' >> /etc/sysmonitor/pscnt");
    (void)exec_cmd_test("echo 'SHOW_TOP_PROC_NUM=\"0\"' >> /etc/sysmonitor/pscnt");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP_PSCNT);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'open threads most 1 processes is'");
    CU_ASSERT(ret != 0);
    (void)exec_cmd_test("rm -rf /etv/sysmonitor/pscnt && mv /etc/sysmonitor/pscnt-bak /etc/sysmonitor/pscnt");
}

static void test_monitor_threads_top_num_max()
{
    int ret;

    create_pthreads(TEST_THREADS_NUM_MAX);

    /* test for max SHOW_TOP_PROC_NUM = 1024 */
    (void)exec_cmd_test("mv /etc/sysmonitor/pscnt /etc/sysmonitor/pscnt-bak");
    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    (void)exec_cmd_test("echo 'ALARM=\"1000\"' > /etc/sysmonitor/pscnt");
    (void)exec_cmd_test("echo 'RESUME=\"900\"' >> /etc/sysmonitor/pscnt");
    (void)exec_cmd_test("echo 'PERIOD=\"1\"' >> /etc/sysmonitor/pscnt");
    (void)exec_cmd_test("echo 'ALARM_RATIO=\"0.02\"' >> /etc/sysmonitor/pscnt");
    (void)exec_cmd_test("echo 'RESUME_RATIO=\"0.01\"' >> /etc/sysmonitor/pscnt");
    (void)exec_cmd_test("echo 'SHOW_TOP_PROC_NUM=\"1024\"' >> /etc/sysmonitor/pscnt");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP);
    (void)exec_cmd_test("cat /home/sys_res.log");
    (void)exec_cmd_test("cat /etc/sysmonitor/pscnt");
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'open threads most 1024 processes is'");
    CU_ASSERT(ret == 0);
    test_monitor_threads_top_num_resume();
    (void)exec_cmd_test("rm -rf /etv/sysmonitor/pscnt && mv /etc/sysmonitor/pscnt-bak /etc/sysmonitor/pscnt");
}

static void test_monitor_threads_top_num_mid()
{
    int ret;
    create_pthreads(TEST_THREADS_NUM_MID);
    (void)exec_cmd_test("mv /etc/sysmonitor/pscnt /etc/sysmonitor/pscnt-bak");
    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    (void)exec_cmd_test("echo 'ALARM=\"200\"' > /etc/sysmonitor/pscnt");
    (void)exec_cmd_test("echo 'RESUME=\"100\"' >> /etc/sysmonitor/pscnt");
    (void)exec_cmd_test("echo 'PERIOD=\"1\"' >> /etc/sysmonitor/pscnt");
    (void)exec_cmd_test("echo 'ALARM_RATIO=\"0.02\"' >> /etc/sysmonitor/pscnt");
    (void)exec_cmd_test("echo 'RESUME_RATIO=\"0.01\"' >> /etc/sysmonitor/pscnt");
    (void)exec_cmd_test("echo 'SHOW_TOP_PROC_NUM=\"900\"' >> /etc/sysmonitor/pscnt");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP_PSCNT);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'open threads most 900 processes is'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'print top threads: total set num'");
    CU_ASSERT(ret == 0);
    test_monitor_threads_top_num_resume();
    (void)exec_cmd_test("rm -rf /etv/sysmonitor/pscnt && mv /etc/sysmonitor/pscnt-bak /etc/sysmonitor/pscnt");
}

static void test_monitor_threads_top_num()
{
    int ret;
    int i;

    for (i = 0; i < TEST_THREADS_NUM_DEFAULT; i++) {
        (void)exec_cmd_test("sleep 1024 &");
    }

    /* test for default SHOW_TOP_PROC_NUM = 10 */
    (void)exec_cmd_test("mv /etc/sysmonitor/pscnt /etc/sysmonitor/pscnt-bak");
    (void)exec_cmd_test("rm -rf /home/sys_res.log");
    (void)exec_cmd_test("echo 'ALARM=\"2\"' > /etc/sysmonitor/pscnt");
    (void)exec_cmd_test("echo 'RESUME=\"1\"' >> /etc/sysmonitor/pscnt");
    (void)exec_cmd_test("echo 'PERIOD=\"1\"' >> /etc/sysmonitor/pscnt");
    (void)exec_cmd_test("echo 'ALARM_RATIO=\"0.02\"' >> /etc/sysmonitor/pscnt");
    (void)exec_cmd_test("echo 'RESUME_RATIO=\"0.01\"' >> /etc/sysmonitor/pscnt");
    (void)exec_cmd_test("echo 'SHOW_TOP_PROC_NUM=\"10\"' >> /etc/sysmonitor/pscnt");
    g_sysres_info->reload = true;
    (void)sleep(TIME_SLEEP_PSCNT);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'threads count alarm:'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'open threads most 10 processes is'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'threads count alarm, show process count'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'threads count alarm, show sys fd count'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/sys_res.log | grep 'threads count alarm, show mem info'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("kill -9 $(ps aux | grep \"sleep 1024\" | grep -v grep | awk '{print $2}')");
    test_monitor_threads_top_num_resume();
    (void)exec_cmd_test("rm -rf /etv/sysmonitor/pscnt && mv /etc/sysmonitor/pscnt-bak /etc/sysmonitor/pscnt");
}

static void test_set_sys_resources()
{
    int ret;
    ret = set_sys_resources_max("/proc/sys/kernel/pid_max", g_pid_max, PID_MAX);
    ret += set_sys_resources_max("/proc/sys/kernel/threads-max", g_threads_max, THREADS_MAX);
    ret += set_sys_resources_max("/proc/sys/fs/file-max", g_file_max, FILE_MAX);
    CU_ASSERT(ret == 0);
}

static void test_revocer_sys_resources()
{
    int ret;
    ret = recover_sys_resources_max("/proc/sys/kernel/pid_max", g_pid_max);
    ret += recover_sys_resources_max("/proc/sys/kernel/threads-max", g_threads_max);
    ret += recover_sys_resources_max("/proc/sys/fs/file-max", g_file_max);
    CU_ASSERT(ret == 0);
}

typedef enum {
    CUNIT_SCREEN = 0,
    CUNIT_XMLFILE,
    CUNIT_CONSOLE
} cu_run_mode;

static void add_test(CU_pSuite suite)
{
    (void)CU_ADD_TEST(suite, test_set_sys_resources);
    (void)CU_ADD_TEST(suite, test_mem_show_alarm_info_001);
    (void)CU_ADD_TEST(suite, test_mem_show_alarm_info_002);
    (void)CU_ADD_TEST(suite, test_cpu_monitor_fun_001);
    (void)CU_ADD_TEST(suite, test_cpu_monitor_fun_002);
    (void)CU_ADD_TEST(suite, test_cpu_monitor_fun_003);
    (void)CU_ADD_TEST(suite, test_cpu_domain_loadconf_abn_001);
    (void)CU_ADD_TEST(suite, test_cpu_domain_loadconf_abn_002);
    (void)CU_ADD_TEST(suite, test_cpu_domain_loadconf_abn_003);
    (void)CU_ADD_TEST(suite, test_cpu_domain_loadconf_abn_004);
    (void)CU_ADD_TEST(suite, test_cpu_domain_loadconf_abn_005);
    (void)CU_ADD_TEST(suite, test_cpu_domain_loadconf_abn_006);
    (void)CU_ADD_TEST(suite, test_cpu_domain_loadconf_abn_007);
    (void)CU_ADD_TEST(suite, test_cpu_domain_monitor_fun_001);
    (void)CU_ADD_TEST(suite, test_cpu_domain_monitor_fun_002);
    (void)CU_ADD_TEST(suite, test_cpu_domain_monitor_fun_003);
    (void)CU_ADD_TEST(suite, test_cpu_reportcmd_abn_001);
    (void)CU_ADD_TEST(suite, test_cpu_reportcmd_abn_002);
    (void)CU_ADD_TEST(suite, test_cpu_reportcmd_fun_001);
    (void)CU_ADD_TEST(suite, test_cpu_reportcmd_fun_002);
    (void)CU_ADD_TEST(suite, test_memory_monitor_fun_001);
    (void)CU_ADD_TEST(suite, test_memory_monitor_fun_002);
    (void)CU_ADD_TEST(suite, test_memory_monitor_fun_003);
    (void)CU_ADD_TEST(suite, test_pscnt_monitor_fun_001);
    (void)CU_ADD_TEST(suite, test_pscnt_monitor_fun_002);
    (void)CU_ADD_TEST(suite, test_monitor_process_count);
    (void)CU_ADD_TEST(suite, test_parse_and_check_threads_top_num);
    (void)CU_ADD_TEST(suite, test_monitor_threads_top_num);
    (void)CU_ADD_TEST(suite, test_monitor_threads_top_num_min);
    (void)CU_ADD_TEST(suite, test_monitor_threads_top_num_mid);
    (void)CU_ADD_TEST(suite, test_monitor_threads_top_num_max);
    (void)CU_ADD_TEST(suite, test_monitor_threads_top_num_zero);
    (void)CU_ADD_TEST(suite, test_sysfd_monitor_fun_001);
    (void)CU_ADD_TEST(suite, test_sysfd_monitor_fun_002);
    (void)CU_ADD_TEST(suite, test_sysfd_monitor_fun_003);
    (void)CU_ADD_TEST(suite, test_sys_resources_monitor_fun_001);
    (void)CU_ADD_TEST(suite, test_revocer_sys_resources);
}

int main(int argc, char **argv)
{
    CU_pSuite suite;
    unsigned int num_failures;
    cu_run_mode cunit_mode = CUNIT_SCREEN;

    if (argc > 1) {
        cunit_mode = (cu_run_mode)strtol(argv[1], NULL, STRTOL_NUMBER_BASE);
    }

    if (CU_initialize_registry() != CUE_SUCCESS) {
        return CU_get_error();
    }

    suite = CU_add_suite("sys_resources.c", init_before_test_mem, cleanup_after_test_mem);
    if (suite == NULL) {
        goto ERROR;
    }

    add_test(suite);
    switch (cunit_mode) {
        case CUNIT_SCREEN:
            CU_basic_set_mode(CU_BRM_VERBOSE);
            CU_basic_run_tests();
            break;
        case CUNIT_XMLFILE:
            CU_set_output_filename("sys_resources");
            CU_automated_run_tests();
            break;
        case CUNIT_CONSOLE:
            CU_console_run_tests();
            break;
        default:
            (void)printf("not suport cunit mode, only suport: 0 or 1\n");
            goto ERROR;
    }

    num_failures = CU_get_number_of_failures();
    CU_cleanup_registry();
    return num_failures;

ERROR:
    CU_cleanup_registry();
    return CU_get_error();
}
