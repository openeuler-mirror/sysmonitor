/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * sysmonitor licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Description: testcase for sysmonitor
 * Author: zhangguangzhi
 * Create: 2020-04-03
 */

#include <CUnit/Basic.h>
#include <CUnit/Automated.h>
#include <CUnit/Console.h>
#include <unistd.h>
#include <securec.h>
#include "common.h"
#include "../common_interface/common_interface.h"

#define SLEEP_INTERVAL 2

typedef enum {
    CUNIT_SCREEN = 0,
    CUNIT_XMLFILE,
    CUNIT_CONSOLE
} cu_run_mode;

static int init_before_test(void)
{
    init_sysmonitor();
    return 0;
}

static void test_reload_sysmonitor(void)
{
    int ret;

    ret = lovs_system("systemctl reload sysmonitor &> /dev/null");
    CU_ASSERT(ret == 0);
}

static void test_sysmonitor_pidlock(void)
{
    int ret;

    (void)exec_cmd_test("cat /dev/null > /var/log/sysmonitor.log");
    ret = exec_cmd_test("./sysmonitor/sysmonitor_test --normal &> /dev/null");
    CU_ASSERT(ret != 0);
    ret = exec_cmd_test("cat /var/log/sysmonitor.log | grep 'lock /var/run/sysmonitor.pid'");
    CU_ASSERT(ret == 0);
}

static void test_sysmonitor_abn_usage(void)
{
    int ret;

    (void)lovs_system("systemctl stop sysmonitor &> /dev/null");
    ret = exec_cmd_test("./sysmonitor/sysmonitor_test --test");
    CU_ASSERT(ret != 0);
    ret = exec_cmd_test("./sysmonitor/sysmonitor_test &> /dev/null");
    CU_ASSERT(ret != 0);
}

static void test_sysmonitor_config(void)
{
    int ret;

    (void)exec_cmd_test("mv /etc/sysconfig/sysmonitor /etc/sysconfig/sysmonitor.bak");
    (void)exec_cmd_test("echo 'PROCESS_MONITOR=\"test\"' > /etc/sysconfig/sysmonitor");
    (void)exec_cmd_test("echo 'PROCESS_MONITOR_PERIOD=\"-1\"' >> /etc/sysconfig/sysmonitor");
    (void)exec_cmd_test("echo 'DISK_MONITOR_PERIOD=\"-1\"' >> /etc/sysconfig/sysmonitor");
    (void)exec_cmd_test("echo 'INODE_MONITOR_PERIOD=\"-1\"' >> /etc/sysconfig/sysmonitor");
    (void)exec_cmd_test("echo '123456789012345678901234567890123456789012345678901=\"on\"'"
                        ">> /etc/sysconfig/sysmonitor");
    (void)exec_cmd_test("echo 'CHECK_THREAD_MONITOR=\"test\"' >> /etc/sysconfig/sysmonitor");
    (void)exec_cmd_test("echo 'CHECK_THREAD_FAILURE_NUM=\"-1\"' >> /etc/sysconfig/sysmonitor");
    (void)exec_cmd_test("echo 'FILESYSTEM_ALARM=\"on\"' >> /etc/sysconfig/sysmonitor");
    (void)exec_cmd_test("echo 'CHECK_THREAD_MONITOR=\"off\"' >> /etc/sysconfig/sysmonitor");
    (void)exec_cmd_test("cat /dev/null > /var/log/sysmonitor.log");
    (void)lovs_system("systemctl restart sysmonitor &> /dev/null");
    (void)sleep(SLEEP_INTERVAL + 1);
    ret = exec_cmd_test("cat /var/log/sysmonitor.log | grep 'PROCESS_MONITOR set error'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /var/log/sysmonitor.log | grep 'PROCESS_MONITOR_PERIOD set error'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /var/log/sysmonitor.log | grep 'DISK_MONITOR_PERIOD set error'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /var/log/sysmonitor.log | grep 'INODE_MONITOR_PERIOD set error'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /var/log/sysmonitor.log | grep 'sysmonitor parse_line: item length(51) too long(>50).'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /var/log/sysmonitor.log | grep 'item:\\[CHECK_THREAD_MONITOR\\] set value error\'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /var/log/sysmonitor.log | grep 'set check_thread_failure_num error'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("mv /etc/sysconfig/sysmonitor.bak /etc/sysconfig/sysmonitor");
}

static void test_sysmonitor_normal_log(void)
{
    int ret;

    (void)exec_cmd_test("cp /etc/sysconfig/sysmonitor /etc/sysconfig/sysmonitor.bak");
    (void)exec_cmd_test("mv /etc/sysmonitor/w_log_conf /etc/sysmonitor/w_log_conf.bak");
    (void)exec_cmd_test("rm -rf /home/sysmonitor-normal.log");
    (void)exec_cmd_test("echo ' WRITE_LOG_PATH=\"/home/sysmonitor-normal.log\"' > /etc/sysmonitor/w_log_conf");
    (void)exec_cmd_test("echo 'UTC_TIME=\"on\"' >> /etc/sysmonitor/w_log_conf");
    (void)exec_cmd_test("sed -i '/IO_DELAY_MONITOR/c\\ IO_DELAY_MONITOR=\"on\"' /etc/sysconfig/sysmonitor");
    (void)exec_cmd_test("echo 'NAME=test' > /etc/sysmonitor/process/test");
    (void)exec_cmd_test("echo 'MONITOR_COMMAND=echo 1' >> /etc/sysmonitor/process/test");
    (void)exec_cmd_test("echo 'MONITOR_MODE=parallel' >> /etc/sysmonitor/process/test");
    (void)exec_cmd_test("echo 'MONITOR_PERIOD=1' >> /etc/sysmonitor/process/test");
    (void)exec_cmd_test("systemctl stop sysmonitor &> /dev/null");
    (void)exec_cmd_test("./sysmonitor/sysmonitor_test --normal &> /dev/null &");
    (void)sleep(SLEEP_INTERVAL + SLEEP_INTERVAL);
    (void)exec_cmd_test("kill -9  $(ps aux | grep 'sysmonitor_test --normal' | grep -v grep | awk '{print $2}')");
    (void)sleep(SLEEP_INTERVAL);
    ret = exec_cmd_test("cat /home/sysmonitor-normal.log | grep 'sysmonitor starting up' ");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("mv /etc/sysmonitor/w_log_conf.bak /etc/sysmonitor/w_log_conf");
    (void)exec_cmd_test("mv /etc/sysconfig/sysmonitor.bak /etc/sysconfig/sysmonitor");
    (void)exec_cmd_test("rm -rf /home/sysmonitor-normal.log");
    (void)exec_cmd_test("rm -rf /etc/sysmonitor/process/test");
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

    suite = CU_add_suite("sysmonitor", init_before_test, NULL);
    if (suite == NULL) {
        goto err;
    }

    (void)CU_ADD_TEST(suite, test_reload_sysmonitor);
    (void)CU_ADD_TEST(suite, test_sysmonitor_pidlock);
    (void)CU_ADD_TEST(suite, test_sysmonitor_abn_usage);
    (void)CU_ADD_TEST(suite, test_sysmonitor_config);
    (void)CU_ADD_TEST(suite, test_sysmonitor_normal_log);

    if (!CU_ADD_TEST(suite, recover_sysmonitor)) {
        goto err;
    }

    switch (g_cunit_mode) {
        case CUNIT_SCREEN:
            CU_basic_set_mode(CU_BRM_VERBOSE);
            CU_basic_run_tests();
            break;
        case CUNIT_XMLFILE:
            CU_set_output_filename("sysmonitor");
            CU_list_tests_to_file();
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
