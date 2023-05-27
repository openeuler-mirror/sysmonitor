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
 * Description: testcase for disk monitor
 * Author: xuchunmei
 * Create: 2019-10-10
 */
#define _GNU_SOURCE
#include <CUnit/Basic.h>
#include <CUnit/Automated.h>
#include <CUnit/Console.h>
#include <unistd.h>
#include "disk.h"
#include "common.h"
#include "../common_interface/common_interface.h"

#define DISK_TEST_LOG "/home/disk.log"
#define USLEEP_INTERVAL (500 * 1000)

typedef enum {
    CUNIT_SCREEN = 0,
    CUNIT_XMLFILE,
    CUNIT_CONSOLE
} cu_run_mode;

static monitor_thread *g_disk_info = NULL;

static int init_before_test(void)
{
    g_disk_info = get_thread_item_info(DISK_ITEM);
    if (g_disk_info == NULL) {
        return 1;
    }
    init_log_for_test(DISK_TEST_LOG);
    (void)exec_cmd_test("mv /etc/sysmonitor/disk /etc/sysmonitor/disk-bak");
    g_disk_info->period = 1;
    g_disk_info->reload = true;
    disk_monitor_init();
    return 0;
}

static int clean_after_test(void)
{
    (void)exec_cmd_test("rm -rf /etc/sysmonitor/disk");
    (void)exec_cmd_test("mv /etc/sysmonitor/disk-bak /etc/sysmonitor/disk");
    clear_log_config(DISK_TEST_LOG);
    return 0;
}

static void test_disk_monitor_init_fun_001()
{
    int ret;

    ret = exec_cmd_test("cat /home/disk.log | grep 'open /etc/sysmonitor/disk error'");
    CU_ASSERT(ret == 0);
}

static void wait_for_reload(void)
{
    (void)exec_cmd_test("rm -rf /home/disk.log");
    g_disk_info->reload = true;
    for (;;) {
        if (!g_disk_info->reload) {
            break;
        }
        (void)usleep(USLEEP_INTERVAL);
    }
}

static void test_disk_monitor_init_fun_002(void)
{
    int ret;

    (void)exec_cmd_test("echo ' DISK=\"/\" ALARM=\"80\" RESUME=\"70\"' > /etc/sysmonitor/disk");
    (void)exec_cmd_test("echo 'DISK=\"/var/log\"' >> /etc/sysmonitor/disk");
    g_disk_info->period = 1;
    disk_monitor_init();
    wait_for_reload();
    ret = exec_cmd_test("cat /home/disk.log | grep 'reload disk monitor configuration failed'");
    CU_ASSERT(ret != 0);
}

static void test_disk_monitor_reload(void)
{
    int ret;

    (void)exec_cmd_test("echo ' DISK=\"/\" ALARM=\"90\" RESUME=\"70\"' > /etc/sysmonitor/disk");
    (void)exec_cmd_test("echo 'DISK=\"/var/log\"' >> /etc/sysmonitor/disk");
    (void)exec_cmd_test("echo 'DISK=\"/dev\"' >> /etc/sysmonitor/disk");
    wait_for_reload();
    ret = exec_cmd_test("cat /home/disk.log | grep 'reload disk monitor configuration failed'");
    CU_ASSERT(ret != 0);
}

static void test_disk_loadconf_abn_001(void)
{
    int ret;

    (void)exec_cmd_test("echo 'DISK1=\"/var\"' > /etc/sysmonitor/disk");
    wait_for_reload();
    ret = exec_cmd_test("cat /home/disk.log | grep 'parse_diskline error'");
    CU_ASSERT(ret == 0);
}

static void test_disk_loadconf_abn_002(void)
{
    int ret;

    (void)exec_cmd_test("echo 'DISK=\"/var\" ALARM=\"70\" RESUME=\"80\"' > /etc/sysmonitor/disk");
    wait_for_reload();
    ret = exec_cmd_test("cat /home/disk.log | grep 'alarm:70 or resume:80 invalided'");
    CU_ASSERT(ret == 0);
}

static void test_disk_loadconf_abn_003(void)
{
    int ret;

    (void)exec_cmd_test("rm -rf /home/test");
    (void)exec_cmd_test("echo 'DISK=\"/home/test\"' > /etc/sysmonitor/disk");
    wait_for_reload();
    ret = exec_cmd_test("cat /home/disk.log | grep 'get_mount:/home/test failed'");
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

    suite = CU_add_suite("disk", init_before_test, clean_after_test);
    if (suite == NULL) {
        goto err;
    }

    (void)CU_ADD_TEST(suite, test_disk_monitor_init_fun_001);
    (void)CU_ADD_TEST(suite, test_disk_monitor_init_fun_002);
    (void)CU_ADD_TEST(suite, test_disk_monitor_reload);
    (void)CU_ADD_TEST(suite, test_disk_loadconf_abn_001);
    (void)CU_ADD_TEST(suite, test_disk_loadconf_abn_002);
    (void)CU_ADD_TEST(suite, test_disk_loadconf_abn_003);

    switch (g_cunit_mode) {
        case CUNIT_SCREEN:
            CU_basic_set_mode(CU_BRM_VERBOSE);
            CU_basic_run_tests();
            break;
        case CUNIT_XMLFILE:
            CU_set_output_filename("disk");
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
