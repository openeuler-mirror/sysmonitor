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
 * Description: testcase for custom daemon and periodic monitor
 * Author: xuchunmei
 * Create: 2019-9-28
 */
#define _GNU_SOURCE
#include <CUnit/Basic.h>
#include <CUnit/Automated.h>
#include <CUnit/Console.h>
#include <unistd.h>
#include <securec.h>
#include "custom.h"
#include "../common_interface/common_interface.h"

typedef enum {
    CUNIT_SCREEN = 0,
    CUNIT_XMLFILE,
    CUNIT_CONSOLE
} cu_run_mode;

#define CUSTOM_TEST_LOG "/home/custom.log"
#define TEST_MAX_TEMPSTR 1024
#define SLEEP_INTERVAL 3

static monitor_thread *g_daemon_info = NULL;
static monitor_thread *g_periodic_info = NULL;

static int init_before_test(void)
{
    init_log_for_test(CUSTOM_TEST_LOG);
    (void)exec_cmd_test("mv /etc/sysmonitor.d /etc/sysmonitor.d-bak");
    g_daemon_info = get_thread_item_info(CUSTOM_DAEMON_ITEM);
    g_periodic_info = get_thread_item_info(CUSTOM_PERIODIC_ITEM);
    if (g_daemon_info == NULL || g_periodic_info == NULL) {
        return 1;
    }
    g_daemon_info->period = 1;
    custom_daemon_monitor_init();
    return 0;
}

static int clean_after_test(void)
{
    (void)exec_cmd_test("rm -rf /etc/sysmonitor.d");
    (void)exec_cmd_test("mv /etc/sysmonitor.d-bak /etc/sysmonitor.d");
    clear_log_config(CUSTOM_TEST_LOG);
    return 0;
}

static void wait_for_reload(void)
{
    g_daemon_info->reload = true;
    while (g_daemon_info->reload) {
        (void)sleep(1);
    }
}

static void test_custom_load_file_fun_001()
{
    int ret;
    char temp[MAX_CFG_NAME_LEN + 1] = {0};
    char str[TEST_MAX_TEMPSTR] = {0};

    ret = monitor_cmd(DEFAULT_USER_ID, "cat /home/custom.log | grep \"/etc/sysmonitor.d/ not exist\"", 0, NULL, true);
    CU_ASSERT(ret == 0);

    (void)exec_cmd_test("mkdir /etc/sysmonitor.d");
    (void)memset_s(temp, MAX_CFG_NAME_LEN, 'a', MAX_CFG_NAME_LEN);
    (void)snprintf_s(str, TEST_MAX_TEMPSTR, TEST_MAX_TEMPSTR - 1, "touch /etc/sysmonitor.d/%s", temp);
    (void)exec_cmd_test(str);
    (void)exec_cmd_test("touch /etc/sysmonitor.d/aaa && chmod 777 /etc/sysmonitor.d/aaa");
    wait_for_reload();

    ret = monitor_cmd(DEFAULT_USER_ID, "cat /home/custom.log | grep \"load_task: config file"
                                       " name should be less than 128, file: \"", 0, NULL, true);
    CU_ASSERT(ret == 0);
    ret = monitor_cmd(DEFAULT_USER_ID,
        "cat /home/custom.log | grep \"/etc/sysmonitor.d/aaa: bad file mode\"", 0, NULL, true);
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("rm -rf /etc/sysmonitor.d/aaa*");
}

static void check_parse_config_fun_test(void)
{
    int ret;

    ret = exec_cmd_test("cat /home/custom.log | grep \"parse config-test1 error\"");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/custom.log | grep "
                        "'ERROR: \"(MONITOR_SWITCH)=\"on\"\" include nonsecure character!'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/custom.log | grep \"custom parse_line: item length(60) too long(>50)\"");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/custom.log | grep \"custom monitor: size should be less than 160, error!\"");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/custom.log | grep \"custom monitor: monitor switch configuration error!\"");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/custom.log | grep \"custom monitor: type configuration error!\"");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/custom.log | grep \"custom monitor: period configuration error!\"");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/custom.log | grep \"custom monitor: enviromentfile configuration error!\"");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/custom.log | grep"
                        " \"custom monitor: enviromentfile path should be less than 128, error!\"");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/custom.log | grep \"custom monitor: execstart configuration error!\"");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/custom.log | grep \"UNKNOWN not support\"");
    CU_ASSERT(ret == 0);
}

static void check_long_name_config(void)
{
    char temp[TEST_MAX_TEMPSTR] = {0};
    char name[MAX_CFG_NAME_LEN + 1] = {0};
    int ret;

    (void)exec_cmd_test("echo 'MONITOR_SWITCH=\"on\"' > /etc/sysmonitor.d/daemon-test1");
    (void)exec_cmd_test("echo 'TYPE=\"daemon\"' >> /etc/sysmonitor.d/daemon-test1");
    (void)exec_cmd_test("echo 'EXECSTART=\"sleep 600\"' >> /etc/sysmonitor.d/daemon-test1");
    wait_for_reload();
    ret = exec_cmd_test("cat /home/custom.log | grep 'is added to monitor list' | grep daemon-test1");
    CU_ASSERT(ret == 0);

    (void)exec_cmd_test("echo 'MONITOR_SWITCH=\"off\"' > /etc/sysmonitor.d/daemon-test1");
    (void)memset_s(temp, TEST_MAX_TEMPSTR, 0, TEST_MAX_TEMPSTR);
    (void)memset_s(name, MAX_CFG_NAME_LEN, '1', MAX_CFG_NAME_LEN);
    (void)snprintf_s(temp, TEST_MAX_TEMPSTR, TEST_MAX_TEMPSTR - 1, "echo test > /etc/sysmonitor.d/config-test%s", name);
    (void)exec_cmd_test(temp);
    wait_for_reload();
    ret = exec_cmd_test("cat /home/custom.log | grep "
                        "'reload_task: config file name should be less than 128, file: config-test111'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("rm -rf /etc/sysmonitor.d");
    wait_for_reload();
    ret = exec_cmd_test("cat /home/custom.log | grep 'reload_task: /etc/sysmonitor.d/ not exist'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("mkdir -p /etc/sysmonitor.d");
}

static void test_custom_parse_config_fun_001()
{
    char temp[TEST_MAX_TEMPSTR] = {0};
    char str[MAX_CUSTOM_CMD_LEN + 1] = {0};
    char name[MAX_CFG_NAME_LEN + 1] = {0};
    int ret;

    (void)exec_cmd_test("touch /etc/sysmonitor.d/config-test1"
                        " && echo \"   #12345\" > /etc/sysmonitor.d/config-test1");
    (void)exec_cmd_test("touch /etc/sysmonitor.d/config-test2"
                        " && echo '(MONITOR_SWITCH)=\"on\"' > /etc/sysmonitor.d/config-test2");
    (void)exec_cmd_test("touch /etc/sysmonitor.d/config-test3"
                        "&& echo '123456789012345678901234567890123456789012345678901234567890=\"on\"'"
                        " > /etc/sysmonitor.d/config-test3");
    (void)exec_cmd_test("touch /etc/sysmonitor.d/config-test4");
    (void)memset_s(str, MAX_CUSTOM_CMD_LEN, '1', MAX_CUSTOM_CMD_LEN);
    (void)snprintf_s(temp, TEST_MAX_TEMPSTR, TEST_MAX_TEMPSTR - 1,
                     "echo 'EXECSTART=\"%s\"' > /etc/sysmonitor.d/config-test4", str);
    (void)exec_cmd_test(temp);
    (void)exec_cmd_test("touch /etc/sysmonitor.d/config-test5"
                        " && echo 'MONITOR_SWITCH=\"On\"' > /etc/sysmonitor.d/config-test5");
    (void)exec_cmd_test("touch /etc/sysmonitor.d/config-test6"
                        " && echo 'TYPE=\"unknown\"' > /etc/sysmonitor.d/config-test6");
    (void)exec_cmd_test("touch /etc/sysmonitor.d/config-test7"
                        " && echo 'PERIOD=\"abc\"' > /etc/sysmonitor.d/config-test7");
    (void)exec_cmd_test("touch /etc/sysmonitor.d/config-test8"
                        " && echo 'ENVIROMENTFILE=\"\"' > /etc/sysmonitor.d/config-test8");
    (void)exec_cmd_test("touch /etc/sysmonitor.d/config-test9");
    (void)memset_s(temp, TEST_MAX_TEMPSTR, 0, TEST_MAX_TEMPSTR);
    (void)memset_s(name, MAX_CFG_NAME_LEN, '1', MAX_CFG_NAME_LEN);
    (void)snprintf_s(temp, TEST_MAX_TEMPSTR, TEST_MAX_TEMPSTR - 1,
                     "echo 'ENVIROMENTFILE=\"%s\"' > /etc/sysmonitor.d/config-test9", name);
    (void)exec_cmd_test(temp);
    (void)exec_cmd_test("touch /etc/sysmonitor.d/config-test10"
                        " && echo 'EXECSTART=\"\"' > /etc/sysmonitor.d/config-test10");
    (void)exec_cmd_test("touch /etc/sysmonitor.d/config-test11"
                        " && echo 'UNKNOWN=\"ON\"' > /etc/sysmonitor.d/config-test11");
    (void)exec_cmd_test("touch /etc/sysmonitor.d/config-test12"
                        " && echo 'EXECSTARTPRE=\"\"' > /etc/sysmonitor.d/config-test12");
    wait_for_reload();
    check_parse_config_fun_test();
    ret = exec_cmd_test("rm -rf /etc/sysmonitor.d/config-test*");
    CU_ASSERT(ret == 0);
    check_long_name_config();
}

#define MAX_ENVFILE_LINES 260
static void test_custom_parse_config_fun_002()
{
    int ret;
    int i;

    (void)exec_cmd_test("echo 'MONITOR_SWITCH=\"on\"' > /etc/sysmonitor.d/daemon-test1");
    (void)exec_cmd_test("echo 'TYPE=\"daemon\"' >> /etc/sysmonitor.d/daemon-test1");
    (void)exec_cmd_test("echo 'EXECSTART=\"sleep 600\"' >> /etc/sysmonitor.d/daemon-test1");
    (void)exec_cmd_test("echo 'ENVIROMENTFILE=\"/home/envfile\"' >> /etc/sysmonitor.d/daemon-test1");
    wait_for_reload();
    ret = exec_cmd_test("cat /home/custom.log | grep 'access /home/envfile failed'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("touch /home/test1 && ln -s /home/test1 /home/envfile");
    wait_for_reload();
    ret = exec_cmd_test("cat /home/custom.log | grep '/home/envfile should be absolute path'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("rm -rf /home/test1 && rm -rf /home/envfile");
    (void)exec_cmd_test("echo \"   	\" > /home/envfile");
    (void)exec_cmd_test("echo >> /home/envfile");
    (void)exec_cmd_test("echo \"#test\" >> /home/envfile");
    for (i = 0; i < MAX_ENVFILE_LINES; i++) {
        (void)exec_cmd_test("echo 111 >> /home/envfile");
    }
    wait_for_reload();
    ret = exec_cmd_test("cat /home/custom.log | grep \"is added to monitor list\" | grep daemon-test1");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("rm -rf /home/envfile && rm -rf /etc/sysmonitor.d/daemon-test1");
    wait_for_reload();
}

static void wait_for_periodic_reload(void)
{
    g_periodic_info->reload = true;
    while (g_periodic_info->reload) {
        (void)sleep(1);
    }
}

static void test_custom_parse_config_fun_003()
{
    int ret;

    (void)exec_cmd_test("echo 'MONITOR_SWITCH=\"on\"' > /etc/sysmonitor.d/periodic-test");
    (void)exec_cmd_test("echo 'TYPE=\"periodic\"' >> /etc/sysmonitor.d/periodic-test");
    (void)exec_cmd_test("echo 'EXECSTART=\"sleep 10\"' >> /etc/sysmonitor.d/periodic-test");
    (void)exec_cmd_test("echo 'MONITOR_SWITCH=\"off\"' > /etc/sysmonitor.d/periodic-test1");
    (void)exec_cmd_test("echo 'TYPE=\"periodic\"' >> /etc/sysmonitor.d/periodic-test1");
    (void)exec_cmd_test("echo 'EXECSTART=\"sleep 10\"' >> /etc/sysmonitor.d/periodic-test1");
    (void)exec_cmd_test("echo 'PERIOD=\"20\"' >> /etc/sysmonitor.d/periodic-test1");
    (void)exec_cmd_test("echo 'MONITOR_SWITCH=\"on\"' > /etc/sysmonitor.d/periodic-test2");
    (void)exec_cmd_test("echo 'TYPE=\"periodic\"' >> /etc/sysmonitor.d/periodic-test2");
    (void)exec_cmd_test("echo 'EXECSTART=\"sleep 10\"' >> /etc/sysmonitor.d/periodic-test2");
    (void)exec_cmd_test("echo 'PERIOD=\"20\"' >> /etc/sysmonitor.d/periodic-test2");
    custom_periodic_monitor_init();
    ret = exec_cmd_test("cat /home/custom.log | grep \"parse periodic-test error\"");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/custom.log | grep \"is added to monitor list\" | grep periodic-test1");
    CU_ASSERT(ret != 0);
    ret = exec_cmd_test("cat /home/custom.log | grep \"is added to monitor list\" | grep periodic-test2");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("rm -rf /etc/sysmonitor.d/periodic-test*");
    wait_for_periodic_reload();
}

static void test_custom_monitor_daemon_fun_001_3(void)
{
    int ret;
    unsigned int period = (unsigned int)g_daemon_info->period;

    (void)exec_cmd_test("echo 'MONITOR_SWITCH=\"on\"' > /etc/sysmonitor.d/daemon6");
    (void)exec_cmd_test("echo 'TYPE=\"daemon\"' >> /etc/sysmonitor.d/daemon6");
    (void)exec_cmd_test("echo 'EXECSTART=\"sleep 1\"' >> /etc/sysmonitor.d/daemon6");
    g_daemon_info->reload = true;
    (void)sleep(period + 1);
    ret = exec_cmd_test("cat /home/custom.log | grep 'is added to monitor list' | grep daemon6");
    CU_ASSERT(ret == 0);
    /* test daemon process exit, and reload single config, parse env file */
    (void)exec_cmd_test("echo '/home;/root' >> /home/env.log");
    (void)exec_cmd_test("echo 'ENVIROMENTFILE=\"/home/env.log\"' >> /etc/sysmonitor.d/daemon6");
    (void)sleep(period + 1);
    ret = exec_cmd_test("cat /home/custom.log | grep 'custom daemon monitor: child process' | grep daemon6| grep exit");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("echo 'MONITOR_SWITCH=\"on\"' > /etc/sysmonitor.d/daemon6");
    (void)exec_cmd_test("echo 'TYPE=\"daemon\"' >> /etc/sysmonitor.d/daemon6");
    (void)exec_cmd_test("echo 'EXECSTART=\"sleep 1\"' >> /etc/sysmonitor.d/daemon6");
    (void)sleep(period + 1);
    (void)exec_cmd_test("rm -rf /etc/sysmonitor.d/daemon6 && rm -rf /home/env.log");
}

static void test_custom_monitor_daemon_fun_001_2(void)
{
    int ret;
    unsigned int period = (unsigned int)g_daemon_info->period;

    (void)exec_cmd_test("echo 'MONITOR_SWITCH=\"on\"' > /etc/sysmonitor.d/daemon3");
    (void)exec_cmd_test("echo 'TYPE=\"daemon\"' >> /etc/sysmonitor.d/daemon3");
    (void)exec_cmd_test("echo 'EXECSTART=\"     \"' >> /etc/sysmonitor.d/daemon3");
    g_daemon_info->reload = true;
    (void)sleep(period + 1);
    ret = exec_cmd_test("cat /home/custom.log | grep 'get_exec_and_args, exec and args is empty'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("rm -rf /etc/sysmonitor.d/daemon3");

    (void)exec_cmd_test("echo 'MONITOR_SWITCH=\"on\"' > /etc/sysmonitor.d/daemon4");
    (void)exec_cmd_test("echo 'TYPE=\"daemon\"' >> /etc/sysmonitor.d/daemon4");
    (void)exec_cmd_test("echo 'EXECSTART=\"1 2 3 4 5 6 7 8 9 0 "
                        "1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 "
                        "0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 "
                        "9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 "
                        "8 9 0\"' >> /etc/sysmonitor.d/daemon4");
    g_daemon_info->reload = true;
    (void)sleep(period + 1);
    ret = exec_cmd_test("cat /home/custom.log | grep 'save_args: too many args'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("rm -rf /etc/sysmonitor.d/daemon4");

    (void)exec_cmd_test("cp ./common/process_exit_test /home");
    (void)exec_cmd_test("echo 'MONITOR_SWITCH=\"on\"' > /etc/sysmonitor.d/daemon5");
    (void)exec_cmd_test("echo 'TYPE=\"daemon\"' >> /etc/sysmonitor.d/daemon5");
    (void)exec_cmd_test("echo 'EXECSTART=\"/home/process_exit_test\"' >> /etc/sysmonitor.d/daemon5");
    g_daemon_info->reload = true;
    (void)sleep(period + 1);
    ret = exec_cmd_test("cat /home/custom.log | grep 'name daemon5 started'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("echo 'MONITOR_SWITCH=\"off\"' > /etc/sysmonitor.d/daemon5");
    (void)exec_cmd_test("echo 'TYPE=\"daemon\"' >> /etc/sysmonitor.d/daemon5");
    (void)exec_cmd_test("echo 'EXECSTART=\"/home/process_exit_test\"' >> /etc/sysmonitor.d/daemon5");
    g_daemon_info->reload = true;
    (void)sleep(period + 1);
    ret = exec_cmd_test("cat /home/custom.log | grep 'process SIGTERM timeout, use SIGKILL'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("rm -rf /home/process_exit_test && rm -rf /etc/sysmonitor.d/daemon5");
}

static void test_custom_monitor_daemon_fun_001()
{
    int ret;
    unsigned int period = (unsigned int)g_daemon_info->period;

    (void)exec_cmd_test("echo 'MONITOR_SWITCH=\"on\"' > /etc/sysmonitor.d/daemon1");
    (void)exec_cmd_test("echo 'TYPE=\"daemon\"' >> /etc/sysmonitor.d/daemon1");
    (void)exec_cmd_test("echo 'EXECSTART=\"sleep 2\"' >> /etc/sysmonitor.d/daemon1");
    g_daemon_info->reload = true;
    (void)sleep(period + 1);
    ret = exec_cmd_test("cat /home/custom.log | grep 'is added to monitor list' | grep conf_name | grep daemon1");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/custom.log | grep 'name daemon1 started'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("rm -rf /etc/sysmonitor.d/daemon1");
    (void)sleep(SLEEP_INTERVAL);
    ret = exec_cmd_test("cat /home/custom.log | grep "
                        "'custom daemon monitor: child process' | grep 'name daemon1 exit code'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/custom.log | grep 'open /etc/sysmonitor.d/daemon1 error'");
    CU_ASSERT(ret == 0);

    (void)exec_cmd_test("echo 'MONITOR_SWITCH=\"on\"' > /etc/sysmonitor.d/daemon2");
    (void)exec_cmd_test("echo 'TYPE=\"daemon\"' >> /etc/sysmonitor.d/daemon2");
    (void)exec_cmd_test("echo 'EXECSTART=\"sleep 3\"' >> /etc/sysmonitor.d/daemon2");
    g_daemon_info->reload = true;
    (void)sleep(period + 1);
    ret = exec_cmd_test("cat /home/custom.log | grep 'is added to monitor list' | grep conf_name | grep daemon2");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/custom.log | grep 'name daemon2 started'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("echo 'MONITOR_SWITCH=\"off\"' > /etc/sysmonitor.d/daemon2");
    (void)exec_cmd_test("echo 'TYPE=\"periodic\"' >> /etc/sysmonitor.d/daemon2");
    (void)exec_cmd_test("echo 'EXECSTART=\"sleep 3\"' >> /etc/sysmonitor.d/daemon2");
    (void)exec_cmd_test("echo 'PERIOD=\"20\"' >> /etc/sysmonitor.d/daemon2");
    (void)sleep(SLEEP_INTERVAL);
    ret = exec_cmd_test("cat /home/custom.log | grep 'reload single config: parse daemon2 error'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/custom.log | grep 'single custom type is changed, reload sysmonitor'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/custom.log | grep 'single custom monitor is switched off'");
    CU_ASSERT(ret == 0);

    (void)exec_cmd_test("rm -rf /etc/sysmonitor.d/daemon2");
    test_custom_monitor_daemon_fun_001_2();
    test_custom_monitor_daemon_fun_001_3();
}

static void test_check_periodic_monitor_fun_001_2(void)
{
    int ret;
    unsigned int period = (unsigned int)g_periodic_info->period;

    (void)exec_cmd_test("rm -rf /home/custom.log");
    (void)exec_cmd_test("echo 'MONITOR_SWITCH=\"on\"' > /etc/sysmonitor.d/periodic");
    (void)exec_cmd_test("echo 'TYPE=\"periodic\"' >> /etc/sysmonitor.d/periodic");
    (void)exec_cmd_test("cp ./common/process_exit_test /home");
    (void)exec_cmd_test("echo 'EXECSTART=\"/home/process_exit_test\"' >> /etc/sysmonitor.d/periodic");
    (void)exec_cmd_test("echo 'PERIOD=\"3\"' >> /etc/sysmonitor.d/periodic");
    g_periodic_info->reload = true;
    (void)sleep(period + 1);
    (void)sleep(WORKER_TASK_TIMEOUT);
    g_periodic_info->reload = true;
    (void)sleep(period + 1);
    ret = exec_cmd_test("cat /home/custom.log | grep 'process SIGTERM timeout, use SIGKILL'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("rm -rf /home/process_exit_test && rm -rf /etc/sysmonitor.d/periodic");
    g_periodic_info->reload = true;
    (void)sleep(period + 1);

    (void)exec_cmd_test("echo 'MONITOR_SWITCH=\"on\"' > /etc/sysmonitor.d/periodic1");
    (void)exec_cmd_test("echo 'TYPE=\"periodic\"' >> /etc/sysmonitor.d/periodic1");
    (void)exec_cmd_test("echo 'EXECSTART=\"122   \"' >> /etc/sysmonitor.d/periodic1");
    (void)exec_cmd_test("echo 'PERIOD=\"3\"' >> /etc/sysmonitor.d/periodic1");
    set_log_interface_flag(DAEMON_SYSLOG);
    g_periodic_info->reload = true;
    (void)sleep(period + 2);
    ret = exec_cmd_test("cat /var/log/messages | grep -a 'worker_routine: periodic pid' | grep -v 'cat'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("rm -rf /etc/sysmonitor.d/periodic1");
    g_periodic_info->reload = true;
    (void)sleep(period + 1);
    set_log_interface_flag(NORMAL_WRITE);
}

static void create_periodic_config(int num)
{
    char temp[MAX_TEMPSTR] = {0};
    int i;

    (void)exec_cmd_test("echo 'MONITOR_SWITCH=\"on\"' > /etc/sysmonitor.d/periodic-test1");
    (void)exec_cmd_test("echo 'TYPE=\"periodic\"' >> /etc/sysmonitor.d/periodic-test1");
    (void)exec_cmd_test("echo 'EXECSTART=\"sleep 3\"' >> /etc/sysmonitor.d/periodic-test1");
    (void)exec_cmd_test("echo 'PERIOD=\"3\"' >> /etc/sysmonitor.d/periodic-test1");

    (void)exec_cmd_test("echo 'MONITOR_SWITCH=\"on\"' > /etc/sysmonitor.d/periodic-test");
    (void)exec_cmd_test("echo 'TYPE=\"periodic\"' >> /etc/sysmonitor.d/periodic-test");
    (void)exec_cmd_test("echo 'EXECSTART=\"sleep 15\"' >> /etc/sysmonitor.d/periodic-test");
    (void)exec_cmd_test("echo 'PERIOD=\"3\"' >> /etc/sysmonitor.d/periodic-test");
    for (i = 0; i < num; i++) {
        (void)snprintf_s(temp, MAX_TEMPSTR, MAX_TEMPSTR - 1,
                         "cp /etc/sysmonitor.d/periodic-test /etc/sysmonitor.d/test%d", i);
        (void)exec_cmd_test(temp);
    }
    (void)exec_cmd_test("rm -rf /etc/sysmonitor.d/periodic-test");
}

#define TEST_PERIODIC_NUM 120
#define TEST_PERIODIC_TIMEOUT 15
#define TEST_PERIODIC_RELOAD 5
static void test_check_periodic_monitor_fun_001_3(void)
{
    int ret;

    create_periodic_config(TEST_PERIODIC_NUM);
    g_periodic_info->reload = true;
    (void)sleep(TEST_PERIODIC_TIMEOUT);
    ret = exec_cmd_test("cat /home/custom.log | grep 'task queue is full! no index!'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/custom.log | grep 'custom_periodic_monitor_start: index' | grep error");
    CU_ASSERT(ret == 0);
    g_periodic_info->reload = true;
    (void)sleep(TEST_PERIODIC_RELOAD);
    g_periodic_info->reload = true;
    (void)sleep(TEST_PERIODIC_RELOAD);
    ret = exec_cmd_test("cat /home/custom.log | grep 'process_worker_task: index' | grep error");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("rm -rf /etc/sysmonitor.d/test*");
    (void)exec_cmd_test("rm -rf /etc/sysmonitor.d/periodic-test1");
    wait_for_periodic_reload();
}

static void test_check_periodic_monitor_fun_001()
{
    int ret;
    pthread_t worker_tid;
    unsigned int period;

    g_periodic_info->period = 1;
    period = (unsigned int)g_periodic_info->period;
    (void)exec_cmd_test("echo 'MONITOR_SWITCH=\"on\"' > /etc/sysmonitor.d/periodic");
    (void)exec_cmd_test("echo 'TYPE=\"periodic\"' >> /etc/sysmonitor.d/periodic");
    (void)exec_cmd_test("echo 'EXECSTART=\"/bin/bash /home/test.sh\"' >> /etc/sysmonitor.d/periodic");
    (void)exec_cmd_test("echo 'PERIOD=\"1\"' >> /etc/sysmonitor.d/periodic");
    (void)exec_cmd_test("echo '#! /bin/bash' > /home/test.sh");
    (void)exec_cmd_test("echo 'echo 11111 >> /home/1.log' >> /home/test.sh");
    g_periodic_info->reload = true;
    (void)sleep(period + period + period);
    ret = exec_cmd_test("cat /home/1.log | grep 11111");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("rm -rf /etc/sysmonitor.d/periodic");
    g_periodic_info->reload = true;
    (void)sleep(period + 1);
    (void)exec_cmd_test("rm -rf /home/test.sh && rm -rf /home/1.log");
    (void)exec_cmd_test("echo 'MONITOR_SWITCH=\"on\"' > /etc/sysmonitor.d/periodic");
    (void)exec_cmd_test("echo 'TYPE=\"periodic\"' >> /etc/sysmonitor.d/periodic");
    (void)exec_cmd_test("cp ./common/process_exit_test /home");
    (void)exec_cmd_test("echo 'EXECSTART=\"/home/process_exit_test\"' >> /etc/sysmonitor.d/periodic");
    (void)exec_cmd_test("echo 'PERIOD=\"1\"' >> /etc/sysmonitor.d/periodic");
    (void)worker_task_struct_init();
    g_periodic_info->monitor = true;
    (void)worker_thread_init(&worker_tid);
    g_periodic_info->reload = true;
    (void)sleep(period + 1);
    (void)sleep(WORKER_TASK_TIMEOUT + 2);
    ret = exec_cmd_test("cat /home/custom.log | grep 'execute periodic monitoring timeout'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/custom.log | grep 'process SIGTERM timeout, use SIGKILL'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("rm -rf /home/process_exit_test && rm -rf /etc/sysmonitor.d/periodic");
    g_periodic_info->reload = true;
    (void)sleep(period + 1);

    test_check_periodic_monitor_fun_001_2();
    test_check_periodic_monitor_fun_001_3();
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

    suite = CU_add_suite("custom", init_before_test, clean_after_test);
    if (suite == NULL) {
        goto err;
    }
    (void)CU_ADD_TEST(suite, test_custom_load_file_fun_001);
    (void)CU_ADD_TEST(suite, test_custom_parse_config_fun_001);
    (void)CU_ADD_TEST(suite, test_custom_parse_config_fun_002);
    (void)CU_ADD_TEST(suite, test_custom_parse_config_fun_003);
    (void)CU_ADD_TEST(suite, test_custom_monitor_daemon_fun_001);
    (void)CU_ADD_TEST(suite, test_check_periodic_monitor_fun_001);

    switch (g_cunit_mode) {
        case CUNIT_SCREEN:
            CU_basic_set_mode(CU_BRM_VERBOSE);
            CU_basic_run_tests();
            break;
        case CUNIT_XMLFILE:
            CU_set_output_filename("custom");
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
