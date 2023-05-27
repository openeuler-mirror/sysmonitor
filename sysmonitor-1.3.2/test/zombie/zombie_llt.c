/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * sysmonitor licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Description: testcase for zombie monitor
 * Author: xietangxin
 * Create: 2021-11-29
 */
#include <CUnit/Basic.h>
#include <CUnit/Automated.h>
#include <CUnit/Console.h>
#include <unistd.h>
#include <securec.h>
#include "zombie.h"
#include "common.h"
#include "../common_interface/common_interface.h"

typedef enum {
    CUNIT_SCREEN = 0,
    CUNIT_XMLFILE,
    CUNIT_CONSOLE
} cu_run_mode;

#define ZOMBIE_TEST_LOG "/home/zombie.log"
#define ZOMBIE_NUM 3
#define SLEEP_INTERVAL 1

static monitor_thread *g_zombie_info = NULL;

static int init_before_test(void)
{
    init_log_for_test(ZOMBIE_TEST_LOG);
    (void)exec_cmd_test("mv /etc/sysmonitor/zombie /etc/sysmonitor/zombie.bak");
    g_zombie_info = get_thread_item_info(ZOMBIE_ITEM);
    if (g_zombie_info == NULL) {
        return 1;
    }
    return 0;
}

static int clean_after_test(void)
{
    (void)exec_cmd_test("mv /etc/sysmonitor/zombie.bak /etc/sysmonitor/zombie");
    clear_log_config(ZOMBIE_TEST_LOG);
    return 0;
}

static void wait_for_reload(void)
{
    int ret;

    (void)exec_cmd_test("rm -rf /home/zombie.log");
    g_zombie_info->reload = true;
    for (;;) {
        ret = exec_cmd_test("cat /home/zombie.log | grep 'zombie monitor, start reload'");
        if (ret == 0) {
            break;
        }
        (void)sleep(SLEEP_INTERVAL);
    }
}

static void test_zombie_monitor_fun_001(void)
{
    int ret;

    (void)exec_cmd_test("echo 'ALARM=\"500\"' > /etc/sysmonitor/zombie");
    (void)exec_cmd_test("echo 'RESUME=\"400\"' >> /etc/sysmonitor/zombie");
    (void)exec_cmd_test("echo 'PERIOD=\"1\"' >> /etc/sysmonitor/zombie");
    zombie_monitor_init();
    ret = exec_cmd_test("cat /home/zombie.log | grep 'zombie monitor starting up'");
    CU_ASSERT(ret == 0);
}

static void test_zombie_monitor_fun_002(void)
{
    int ret;

    (void)exec_cmd_test("rm -rf /home/zombie.log");
    (void)exec_cmd_test("echo 'ALARM=\"3\"' > /etc/sysmonitor/zombie");
    (void)exec_cmd_test("echo 'RESUME=\"2\"' >> /etc/sysmonitor/zombie");
    (void)exec_cmd_test("echo 'PERIOD=\"1\"' >> /etc/sysmonitor/zombie");
    (void)exec_cmd_test("./zombie/generate_zombie &");
    wait_for_reload();
    (void)sleep(ZOMBIE_NUM * SLEEP_INTERVAL);
    ret = exec_cmd_test("cat /home/zombie.log | grep 'zombie process count alarm'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("kill -9 $(ps aux | grep 'generate_zombie' | grep -v grep | awk '{print $2}')");
    (void)sleep((unsigned int)g_zombie_info->period);
    ret = exec_cmd_test("cat /home/zombie.log | grep 'zombie process count resume'");
    CU_ASSERT(ret == 0);
}

static void test_zombie_loadconf_abn_001()
{
    int ret;

    (void)exec_cmd_test("rm -rf /home/zombie.log");
    (void)exec_cmd_test("echo ' ALARM=\"-500\"' > /etc/sysmonitor/zombie");
    (void)exec_cmd_test("echo 'RESUME=\"-400\"' >> /etc/sysmonitor/zombie");
    (void)exec_cmd_test("echo 'PERIOD=\"-1\"' >> /etc/sysmonitor/zombie");
    wait_for_reload();
    ret = exec_cmd_test("cat /home/zombie.log | grep 'zombie process monitor: configuration illegal'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/zombie.log | grep 'ALARM config illegal, check -500'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/zombie.log | grep 'RESUME config illegal, check -400'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/zombie.log | grep 'PERIOD config illegal, check -1'");
    CU_ASSERT(ret == 0);
}

static void test_zombie_loadconf_abn_002()
{
    int ret;

    (void)exec_cmd_test("rm -rf /home/zombie.log");
    (void)exec_cmd_test("echo 'ALARM=\"400\"' > /etc/sysmonitor/zombie");
    (void)exec_cmd_test("echo 'RESUME=\"500\"' >> /etc/sysmonitor/zombie");
    (void)exec_cmd_test("echo 'PERIOD=\"1\"' >> /etc/sysmonitor/zombie");
    wait_for_reload();
    ret = exec_cmd_test("cat /home/zombie.log | grep 'zombie process monitor: configuration illegal'");
    CU_ASSERT(ret == 0);
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

    suite = CU_add_suite("zombie", init_before_test, clean_after_test);
    if (suite == NULL) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    (void)CU_ADD_TEST(suite, test_zombie_monitor_fun_001);
    (void)CU_ADD_TEST(suite, test_zombie_monitor_fun_002);
    (void)CU_ADD_TEST(suite, test_zombie_loadconf_abn_001);
    (void)CU_ADD_TEST(suite, test_zombie_loadconf_abn_002);

    switch (g_cunit_mode) {
        case CUNIT_SCREEN:
            CU_basic_set_mode(CU_BRM_VERBOSE);
            CU_basic_run_tests();
            break;
        case CUNIT_XMLFILE:
            CU_set_output_filename("zombie");
            CU_list_tests_to_file();
            CU_automated_run_tests();
            break;
        case CUNIT_CONSOLE:
            CU_console_run_tests();
            break;
        default:
            (void)printf("not suport cunit mode, only suport: 0 or 1\n");
            CU_cleanup_registry();
            return CU_get_error();
    }

    num_failures = CU_get_number_of_failures();
    CU_cleanup_registry();
    return num_failures;
}
