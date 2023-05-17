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
 * Description: testcase for file monitor
 * Author: xuchunmei
 * Create: 2019-10-10
 */
#define _GNU_SOURCE
#include <CUnit/Basic.h>
#include <CUnit/Automated.h>
#include <CUnit/Console.h>
#include <securec.h>
#include <unistd.h>
#include "filemonitor.h"
#include "common.h"
#include "../common_interface/common_interface.h"

#define FILE_TEST_LOG "/home/file.log"

typedef enum {
    CUNIT_SCREEN = 0,
    CUNIT_XMLFILE,
    CUNIT_CONSOLE
} cu_run_mode;

#define FILE_WATCH_SELECT_TIMEOUT 1
static int init_before_test(void)
{
    init_log_for_test(FILE_TEST_LOG);
    set_file_monitor_select_timeout(FILE_WATCH_SELECT_TIMEOUT);
    (void)exec_cmd_test("systemctl stop sysmonitor");
    (void)exec_cmd_test("mv /etc/sysmonitor/file /etc/sysmonitor/file-bak");
    file_monitor_init();
    return 0;
}

static int clean_after_test(void)
{
    (void)exec_cmd_test("rm -rf /etc/sysmonitor/file");
    (void)exec_cmd_test("mv /etc/sysmonitor/file-bak /etc/sysmonitor/file");
    clear_log_config(FILE_TEST_LOG);
    return 0;
}

static void check_load_config_result(void)
{
    int ret;

    ret = exec_cmd_test("cat /home/file.log | grep 'Config file line len is invalid'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/file.log | "
        "grep \"The path can't be recognised. The path length should be less than 4096 characters. error.\"");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/file.log | grep 'Mask is 0x500, it is more than add and delete, error.'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/file.log | grep '(/proc /sys /dev)file /proc no need to monitor'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/file.log | grep '(/proc /sys /dev)file /sys no need to monitor'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/file.log | grep '(/proc /sys /dev)file /dev no need to monitor'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/file.log | grep '/lib should be absolute path'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/file.log | grep 'Watch path is in /var/log, watch /var/log for only delete event'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/file.log | grep 'File path /home/ is already configed, ignore this conf item.'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/file.log | "
                        "grep 'File path /home/11.log is already configed, ignore this conf item.'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/file.log | "
                        "grep '/run/dbus/system_bus_socket is not a directory or regular file, can not watch it.'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/file.log | grep 'file monitor:config file name is too long'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/file.log | grep '/etc/sysmonitor/file.d/test: bad file mode'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/file.log | grep 'file name is \"/home/22.log\", watch event is 0x200'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/file.log | "
                        "grep 'File path /home/22.log is already configed, ignore this conf item.'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/file.log | grep 'Cannot add watch for \"/home/33.log\" with event mask 0x200'");
    CU_ASSERT(ret == 0);
}

static void test_file_load_config_fun_001()
{
    int ret;
    char temp[MAX_LINE_LEN + 1] = {0};
    char cmd[MAX_LINE_LEN + MAX_TEMPSTR] = {0};

    ret = exec_cmd_test("cat /home/file.log | grep '/etc/sysmonitor/file.d/ not exist'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/file.log | grep 'No watcher add to FD'");
    CU_ASSERT(ret == 0);

    (void)memset_s(temp, sizeof(temp), '1', sizeof(temp) - 1);
    (void)snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "echo %s > /etc/sysmonitor/file", temp);
    (void)exec_cmd_test(cmd);
    (void)exec_cmd_test("cat /etc/sysmonitor/file");
    (void)memset_s(temp, sizeof(temp), 0, sizeof(temp));
    (void)memset_s(temp, sizeof(temp), '1', MAX_PATH_LEN);
    (void)snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "echo %s >> /etc/sysmonitor/file", temp);
    (void)exec_cmd_test(cmd);
    (void)exec_cmd_test("echo '/home 0x500' >> /etc/sysmonitor/file");
    (void)exec_cmd_test("echo '/proc 0x300' >> /etc/sysmonitor/file");
    (void)exec_cmd_test("echo '/sys 0x300' >> /etc/sysmonitor/file");
    (void)exec_cmd_test("echo '/dev 0x300' >> /etc/sysmonitor/file");
    (void)exec_cmd_test("echo '/lib 0x300' >> /etc/sysmonitor/file");
    (void)exec_cmd_test("echo '/var/log 0x300' >> /etc/sysmonitor/file");
    (void)exec_cmd_test("echo '/home' >> /etc/sysmonitor/file");
    (void)exec_cmd_test("echo '/home/' >> /etc/sysmonitor/file");
    (void)exec_cmd_test("touch /home/11.log");
    (void)exec_cmd_test("echo ' //home/11.log' >> /etc/sysmonitor/file");
    (void)exec_cmd_test("echo '/home/11.log' >> /etc/sysmonitor/file");
    (void)exec_cmd_test("echo '/run/dbus/system_bus_socket' >> /etc/sysmonitor/file");
    (void)exec_cmd_test("mkdir -p /etc/sysmonitor/file.d");
    (void)memset_s(temp, sizeof(temp), 0, sizeof(temp));
    (void)memset_s(temp, sizeof(temp), 'a', FM_MAX_CFG_NAME_LEN);
    (void)snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "touch /etc/sysmonitor/file.d/%s", temp);
    (void)exec_cmd_test(cmd);
    (void)snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "chmod 700 /etc/sysmonitor/file.d/%s", temp);
    (void)exec_cmd_test(cmd);
    (void)exec_cmd_test("touch /etc/sysmonitor/file.d/test && chmod 777 /etc/sysmonitor/file.d/test");
    (void)exec_cmd_test("touch /etc/sysmonitor/file.d/test1 && chmod 700 /etc/sysmonitor/file.d/test1");
    (void)exec_cmd_test("touch /etc/sysmonitor/file.d/test2 && chmod 700 /etc/sysmonitor/file.d/test2");
    (void)exec_cmd_test("touch /home/22.log");
    (void)exec_cmd_test("echo '/home/22.log' > /etc/sysmonitor/file.d/test1");
    (void)exec_cmd_test("echo '/home/22.log' > /etc/sysmonitor/file.d/test2");
    (void)exec_cmd_test("echo '/home/33.log' >> /etc/sysmonitor/file");

    set_thread_item_reload_flag(FILE_ITEM, true);
    (void)sleep(FILE_WATCH_SELECT_TIMEOUT + 1);
    check_load_config_result();
    (void)exec_cmd_test("rm -rf /etc/sysmonitor/file.d && rm -rf /home/11.log && rm -rf /home/22.log");
    (void)exec_cmd_test("rm -rf /etc/sysmonitor/file");
}

static void test_file_reload_config_fun_001()
{
    int ret;

    (void)exec_cmd_test("rm -rf /home/file.log");
    (void)exec_cmd_test("echo /home > /etc/sysmonitor/file");
    set_thread_item_reload_flag(FILE_ITEM, true);
    (void)sleep(FILE_WATCH_SELECT_TIMEOUT + 1);
    ret = exec_cmd_test("cat /home/file.log | grep 'file name is \"/home\", watch event is 0x200'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("echo > /etc/sysmonitor/file");
    set_thread_item_reload_flag(FILE_ITEM, true);
    (void)sleep(FILE_WATCH_SELECT_TIMEOUT + 1);
    ret = exec_cmd_test("cat /home/file.log | grep 'Conf file is modified, reload conf and watch again.'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/file.log | grep 'No watcher add to FD.'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("rm -rf /home/file.log");
    (void)exec_cmd_test("echo /home > /etc/sysmonitor/file");
    set_thread_item_reload_flag(FILE_ITEM, true);
    (void)sleep(FILE_WATCH_SELECT_TIMEOUT + 1);
    ret = exec_cmd_test("cat /home/file.log | grep 'file name is \"/home\", watch event is 0x200'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("rm -rf /etc/sysmonitor/file");
    set_thread_item_reload_flag(FILE_ITEM, true);
    (void)sleep(FILE_WATCH_SELECT_TIMEOUT + 1);
    ret = exec_cmd_test("cat /home/file.log | grep 'Conf file is modified, reload conf and watch again.'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/file.log | grep 'No watcher add to FD.'");
    CU_ASSERT(ret == 0);
}

static void test_file_event_handle_fun_001()
{
#if 0
    int ret;

    (void)exec_cmd_test("touch /home/testfile");
    (void)exec_cmd_test("touch /home/testingore");
    (void)exec_cmd_test("echo '/home 0x300' > /etc/sysmonitor/file");
    (void)exec_cmd_test("echo '/home/testfile 0x100' >> /etc/sysmonitor/file");
    (void)exec_cmd_test("echo '/home/testingore 0x300' >> /etc/sysmonitor/file");
    (void)exec_cmd_test("echo 111 > /home/testingore");
    (void)exec_cmd_test("echo 222 >> /home/testingore");
    (void)exec_cmd_test("echo ggwxjddZZ > /home/test.keys");
    set_thread_item_reload_flag(FILE_ITEM, true);
    (void)sleep(FILE_WATCH_SELECT_TIMEOUT + 1);
    (void)exec_cmd_test("touch /home/test111");
    (void)exec_cmd_test("rm -rf /home/test111");
    (void)exec_cmd_test("mkdir /home/test222");
    (void)exec_cmd_test("rm -rf /home/test222");
    (void)exec_cmd_test("rm -rf /home/testfile");
    (void)exec_cmd_test("vim -s /home/test.keys /home/testingore");
    ret = exec_cmd_test("cat /home/file.log | grep 'Subfile \"test111\" under \"/home\" was added' | grep 'comm'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/file.log | grep 'Subfile \"test111\" under \"/home\" was deleted' | grep 'comm'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/file.log | grep 'Subdir \"test222\" under \"/home\" was added' | grep 'comm'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/file.log | grep 'Subdir \"test222\" under \"/home\" was deleted' | grep 'comm'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/file.log | grep 'Subfile \"testfile\" under \"/home\" was deleted' | grep 'comm'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/file.log | grep 'File \"/home/testfile\" was deleted' | grep 'comm'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/file.log | "
                        "grep 'File \"/home/testingore\" was deleted.' | grep \"It's maybe changed\" | grep 'comm'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("rm -rf /home/test.keys");
    (void)exec_cmd_test("rm -rf /home/testingore");
    (void)exec_cmd_test("rm -rf /etc/sysmonitor/file");
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

    suite = CU_add_suite("filemonitor", init_before_test, clean_after_test);
    if (suite == NULL) {
        goto err;
    }
    (void)CU_ADD_TEST(suite, test_file_load_config_fun_001);
    (void)CU_ADD_TEST(suite, test_file_reload_config_fun_001);
    (void)CU_ADD_TEST(suite, test_file_event_handle_fun_001);

    switch (g_cunit_mode) {
        case CUNIT_SCREEN:
            CU_basic_set_mode(CU_BRM_VERBOSE);
            CU_basic_run_tests();
            break;
        case CUNIT_XMLFILE:
            CU_set_output_filename("filemonitor");
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
