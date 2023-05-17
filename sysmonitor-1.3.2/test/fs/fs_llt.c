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
 * Description: testcase for fs monitor
 * Author: xietangxin
 * Create: 2021-12-06
 */
#include <CUnit/Basic.h>
#include <CUnit/Automated.h>
#include <CUnit/Console.h>
#include <unistd.h>
#include <securec.h>
#include "fsmonitor.h"
#include "common.h"
#include "../common_interface/common_interface.h"

typedef enum {
    MOUNT_RO = 0,
    MOUNT_DEF = 1,
} mount_type;

typedef enum {
    CUNIT_SCREEN = 0,
    CUNIT_XMLFILE,
    CUNIT_CONSOLE
} cu_run_mode;

#define FS_TEST_LOG "/home/fs.log"

static monitor_thread *g_fs_info = NULL;

static int init_before_test(void)
{
    init_log_for_test(FS_TEST_LOG);
    g_fs_info = get_thread_item_info(FS_ITEM);
    if (g_fs_info == NULL) {
        return 1;
    }
    fs_monitor_init();
    return 0;
}

static int clean_after_test(void)
{
    (void)exec_cmd_test("umount -l /home/mnt/mpoint");
    (void)exec_cmd_test("rm -rf /home/mnt");
    clear_log_config(FS_TEST_LOG);
    return 0;
}

#if 0
static void create_fs_err(mount_type type)
{
    (void)exec_cmd_test("umount -l /home/mnt/mpoint");
    (void)exec_cmd_test("rm -rf /home/mnt");
    (void)exec_cmd_test("mkdir -p /home/mnt/mpoint");
    (void)exec_cmd_test("dd  if=/dev/zero of=/home/mnt/disk bs=1M count=10");
    (void)exec_cmd_test("echo y | mkfs.ext4 /home/mnt/disk");
    (void)exec_cmd_test("mount /home/mnt/disk /home/mnt/mpoint");
    if (type == MOUNT_RO) {
        (void)exec_cmd_test("mount -o remount,errors=remount-ro /home/mnt/mpoint");
    }
    (void)exec_cmd_test("dd if=/dev/zero of=/home/mnt/disk bs=1M count=1");
    (void)exec_cmd_test("touch /home/mnt/mpoint/file");
}
#endif

static void test_fs_monitor_fun(void)
{
#if 0
    int ret;

    (void)exec_cmd_test("rm -rf /home/fs.log");
    create_fs_err(MOUNT_RO);
    ret = exec_cmd_test("cat /home/fs.log | grep 'filesystem error. Remount filesystem read-only'");
    CU_ASSERT(ret == 0);
    create_fs_err(MOUNT_DEF);
    ret = exec_cmd_test("cat /home/fs.log | grep 'filesystem error. flag is'");
    CU_ASSERT(ret == 0);
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

    suite = CU_add_suite("fs", init_before_test, clean_after_test);
    if (suite == NULL) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    (void)CU_ADD_TEST(suite, test_fs_monitor_fun);

    switch (g_cunit_mode) {
        case CUNIT_SCREEN:
            CU_basic_set_mode(CU_BRM_VERBOSE);
            CU_basic_run_tests();
            break;
        case CUNIT_XMLFILE:
            CU_set_output_filename("fs");
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
