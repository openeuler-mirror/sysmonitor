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
 * Description: testcase for process monitor
 * Author: xuchunmei
 * Create: 2019-9-28
 */
#define _GNU_SOURCE
#include <CUnit/Basic.h>
#include <CUnit/Automated.h>
#include <CUnit/Console.h>
#include <unistd.h>
#include <securec.h>
#include "process.h"
#include "../common_interface/common_interface.h"
#include "monitor_thread.h"

typedef enum {
    CUNIT_SCREEN = 0,
    CUNIT_XMLFILE,
    CUNIT_CONSOLE
} cu_run_mode;

#define PROCESS_TEST_LOG "/home/process.log"
#define PROCESS_TIMEOUT 2
#define PROCESS_ALARM_COUNT 5
#define MULTI_PARALLEL_THREAD_TIMEOUT 10

static monitor_thread *g_process_info = NULL;

static int init_before_test(void)
{
    init_log_for_test(PROCESS_TEST_LOG);
    (void)exec_cmd_test("mv /etc/sysmonitor/process /etc/sysmonitor/process-bak");
    g_process_info = get_thread_item_info(PS_ITEM);
    if (g_process_info == NULL) {
        return 1;
    }
    g_process_info->period = 1;
    /* need to init head before test */
    init_ps_parallel_head();
    ps_monitor_init();
    return 0;
}

static int clean_after_test(void)
{
    (void)exec_cmd_test("rm -rf /etc/sysmonitor/process");
    (void)exec_cmd_test("mv /etc/sysmonitor/process-bak /etc/sysmonitor/process");
    clear_log_config(PROCESS_TEST_LOG);
    return 0;
}

static void test_process_load_file_fun_001()
{
    int ret;
    unsigned int period = (unsigned int)g_process_info->period;

    ret = exec_cmd_test("cat /home/process.log | grep 'process monitor starting up'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/process.log | grep 'process monitor started'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/process.log | grep '/etc/sysmonitor/process not exist'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("mkdir -p /etc/sysmonitor && mkdir /etc/sysmonitor/process");
    (void)exec_cmd_test("chmod -R 777 /etc/sysmonitor/process");
    g_process_info->reload = true;
    (void)sleep(period);
    ret = exec_cmd_test("cat /home/process.log | grep '/etc/sysmonitor/process: bad file mode'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("chmod -R 700 /etc/sysmonitor/process");
    (void)exec_cmd_test("touch /etc/sysmonitor/process/test1 && chmod 777 /etc/sysmonitor/process/test1");
    g_process_info->reload = true;
    (void)sleep(period);
    ret = exec_cmd_test("cat /home/process.log | grep 'test1: bad file mode'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("rm -rf /etc/sysmonitor/process/test1");
}

static void test_process_load_file_fun_002_2(void)
{
    int ret;
    unsigned int period = (unsigned int)g_process_info->period;

    (void)exec_cmd_test("echo 'MONITOR_COMMAND=/home/monitor.sh' > /etc/sysmonitor/process/test4");
    (void)exec_cmd_test("echo 'RECOVER_COMMAND=systemctl restart sshd' >> /etc/sysmonitor/process/test4");
    (void)exec_cmd_test("echo 'STOP_COMMAND=systemctl stop sshd' >> /etc/sysmonitor/process/test4");
    (void)exec_cmd_test("echo 'MONITOR_MODE=serial' >> /etc/sysmonitor/process/test4");
    (void)exec_cmd_test("echo 'CHECK_AS_PARAM   =off' >> /etc/sysmonitor/process/test4");
    g_process_info->reload = true;
    (void)sleep(period + 1);
    ret = exec_cmd_test("cat /home/process.log | grep 'someitems is empty on process monitor! "
                        "\"NAME:;USER:root.\"'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/process.log | grep 'parse test4 error'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("rm -rf /etc/sysmonitor/process/test4");

    (void)exec_cmd_test("echo 'NAME=sshd666' > /etc/sysmonitor/process/test6");
    (void)exec_cmd_test("echo 'USER=root' >> /etc/sysmonitor/process/test6");
    (void)exec_cmd_test("echo 'RECOVER_COMMAND=systemctl restart sshd' >> /etc/sysmonitor/process/test6");
    (void)exec_cmd_test("echo 'MONITOR_COMMAND=/home/monitor.sh' >> /etc/sysmonitor/process/test6");
    (void)exec_cmd_test("echo 'STOP_COMMAND=systemctl stop sshd' >> /etc/sysmonitor/process/test6");
    (void)exec_cmd_test("echo 'MONITOR_MODE=parallel' >> /etc/sysmonitor/process/test6");
    (void)exec_cmd_test("echo 'MONITOR_PERIOD=0' >> /etc/sysmonitor/process/test6");
    g_process_info->reload = true;
    (void)sleep(period + 1);
    ret = exec_cmd_test("cat /home/process.log | grep "
                        "'ps_check_config_illegal: MONITOR_PERIOD should not be 0 when MONITOR_MODE is parallel.'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/process.log | grep 'parse test6 error'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("rm -rf /etc/sysmonitor/process/test6");
}

static void test_process_load_file_fun_002_3(void)
{
    int ret;
    unsigned int period = (unsigned int)g_process_info->period;

    (void)exec_cmd_test("echo 'NAME=0123456789012345678901234567890123456789012345678901234567890123456789"
                        "012345678901234567890123456789012345678901234567890123456789012345678901234567890"
                        "1234567890123456789012345678901234567890123456789' > /etc/sysmonitor/process/test10");
    g_process_info->reload = true;
    (void)sleep(period + 1);
    ret = exec_cmd_test("cat /home/process.log | grep 'get_value_from_config: config size should be less than 200'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/process.log | grep 'parse test10 error'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("rm -rf /etc/sysmonitor/process/test10");

    (void)exec_cmd_test("echo 'NAME=!@#$%^&*()' > /etc/sysmonitor/process/test11");
    g_process_info->reload = true;
    (void)sleep(period + 1);
    ret = exec_cmd_test("cat /home/process.log | grep 'include nonsecure character!' | grep '!@#' | grep '()'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/process.log | grep 'parse test11 error'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("rm -rf /etc/sysmonitor/process/test11");
}

static void test_process_load_file_fun_002_4(void)
{
    int ret;
    unsigned int period = (unsigned int)g_process_info->period;

    (void)exec_cmd_test("echo 'USER=root' > /etc/sysmonitor/process/test7");
    (void)exec_cmd_test("echo 'RECOVER_COMMAND=systemctl restart sshd' >> /etc/sysmonitor/process/test7");
    (void)exec_cmd_test("echo 'MONITOR_COMMAND=/home/monitor.sh' >> /etc/sysmonitor/process/test7");
    (void)exec_cmd_test("echo 'STOP_COMMAND=systemctl stop sshd' >> /etc/sysmonitor/process/test7");
    (void)exec_cmd_test("echo 'MONITOR_MODE=unknown' >> /etc/sysmonitor/process/test7");
    g_process_info->reload = true;
    (void)sleep(period + 1);
    ret = exec_cmd_test("cat /home/process.log | grep 'MONITOR_MODE config illegal, check unknown'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/process.log | grep 'parse test7 error'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("rm -rf /etc/sysmonitor/process/test7");

    (void)exec_cmd_test("echo 'USER=root' > /etc/sysmonitor/process/test8");
    (void)exec_cmd_test("echo 'NAME=sshd888' >> /etc/sysmonitor/process/test8");
    (void)exec_cmd_test("echo 'RECOVER_COMMAND=systemctl restart sshd' >> /etc/sysmonitor/process/test8");
    (void)exec_cmd_test("echo 'MONITOR_COMMAND=/home/monitor.sh' >> /etc/sysmonitor/process/test8");
    (void)exec_cmd_test("echo 'STOP_COMMAND=systemctl stop sshd' >> /etc/sysmonitor/process/test8");
    g_process_info->reload = true;
    (void)sleep(period + 1);
    ret = exec_cmd_test("cat /home/process.log | grep 'add sshd888 to process monitor list'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("rm -rf /etc/sysmonitor/process/test8");

    (void)exec_cmd_test("echo 'NAME=sshd999' > /etc/sysmonitor/process/test9");
    (void)exec_cmd_test("echo 'RECOVER_COMMAND=/home/recover.sh' >> /etc/sysmonitor/process/test9");
    (void)exec_cmd_test("echo 'MONITOR_COMMAND=/home/test.sh' >> /etc/sysmonitor/process/test9");
    (void)exec_cmd_test("echo 'STOP_COMMAND=/home/stop.sh' >> /etc/sysmonitor/process/test9");
    g_process_info->reload = true;
    (void)sleep(period + 1);
    ret = exec_cmd_test("cat /home/process.log | grep "
                        "'The executable file sshd999 may not exist in PATH, please check'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/process.log | grep 'add sshd999 to process monitor list'");
    CU_ASSERT(ret != 0);
    (void)exec_cmd_test("rm -rf /etc/sysmonitor/process/test9");
}

static void test_process_load_file_fun_002_5(void)
{
    int ret;
    unsigned int period = (unsigned int)g_process_info->period;

    (void)exec_cmd_test("echo 'RECOVER_COMMAND=systemctl restart sshd' > /etc/sysmonitor/process/test111");
    (void)exec_cmd_test("echo 'STOP_COMMAND=systemctl stop sshd' >> /etc/sysmonitor/process/test111");
    (void)exec_cmd_test("echo 'NAME=sshd-test' >> /etc/sysmonitor/process/test111");
    g_process_info->reload = true;
    (void)sleep(period + 1);
    ret = exec_cmd_test("cat /home/process.log | grep "
                        "'The executable file sshd-test may not exist in PATH, please check'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("rm -rf /etc/sysmonitor/process/test111");

    (void)exec_cmd_test("echo 'RECOVER_COMMAND=systemctl restart sshd-test1' > /etc/sysmonitor/process/test222");
    (void)exec_cmd_test("echo 'MONITOR_COMMAND=systemctl status sshd-test1' >> /etc/sysmonitor/process/test222");
    (void)exec_cmd_test("echo 'STOP_COMMAND=systemctl stop sshd-test1' >> /etc/sysmonitor/process/test222");
    (void)exec_cmd_test("echo 'NAME=sshd-test1' >> /etc/sysmonitor/process/test222");
    g_process_info->reload = true;
    (void)sleep(period + 1);
    ret = exec_cmd_test("cat /home/process.log | grep "
                        "'The service sshd-test1 may not exist, please check'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("rm -rf /etc/sysmonitor/process/test222");

    (void)exec_cmd_test("echo 'RECOVER_COMMAND=sleep 1' > /etc/sysmonitor/process/test333");
    (void)exec_cmd_test("echo 'MONITOR_COMMAND=sleep 35' >> /etc/sysmonitor/process/test333");
    (void)exec_cmd_test("echo 'STOP_COMMAND=sleep 1' >> /etc/sysmonitor/process/test333");
    (void)exec_cmd_test("echo 'NAME=test333' >> /etc/sysmonitor/process/test333");
    g_process_info->reload = true;
    (void)sleep(POPEN_TIMEOUT + POPEN_TIMEOUT + 10); /* twice for exec timeout and 10s to wait for results */
    ret = exec_cmd_test("cat /home/process.log | grep 'execute sleep 35 error'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/process.log | grep 'add test333 to process monitor list failed'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("rm -rf /etc/sysmonitor/process/test333");
}

static void test_process_load_file_fun_002()
{
    int ret;
    unsigned int period = (unsigned int)g_process_info->period;

    (void)exec_cmd_test("echo '#! /bin/bash' > /home/monitor.sh");
    (void)exec_cmd_test("echo 'exit 0' >> /home/monitor.sh");
    (void)exec_cmd_test("chmod a+x /home/monitor.sh");
    (void)exec_cmd_test("echo '#test process monitor' > /etc/sysmonitor/process/test1");
    (void)exec_cmd_test("echo '    NAME=sshd111' >> /etc/sysmonitor/process/test1");
    (void)exec_cmd_test("echo 'MONITOR_COMMAND=/home/monitor.sh' >> /etc/sysmonitor/process/test1");
    (void)exec_cmd_test("echo 'RECOVER_COMMAND=systemctl restart sshd' >> /etc/sysmonitor/process/test1");
    (void)exec_cmd_test("echo 'STOP_COMMAND=   systemctl restart sshd' >> /etc/sysmonitor/process/test1");
    g_process_info->reload = true;
    (void)sleep(period + 1);
    ret = exec_cmd_test("cat /home/process.log | grep 'add sshd111 to process monitor list'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("rm -rf /etc/sysmonitor/process/test1");

    (void)exec_cmd_test("userdel test");
    (void)exec_cmd_test("echo 'NAME=sshd111' > /etc/sysmonitor/process/test2");
    (void)exec_cmd_test("echo 'USER=test' >> /etc/sysmonitor/process/test2");
    (void)exec_cmd_test("echo 'MONITOR_COMMAND=/home/monitor.sh' >> /etc/sysmonitor/process/test2");
    (void)exec_cmd_test("echo 'RECOVER_COMMAND=systemctl restart sshd' >> /etc/sysmonitor/process/test2");
    (void)exec_cmd_test("echo 'STOP_COMMAND=systemctl stop sshd' >> /etc/sysmonitor/process/test2");
    (void)exec_cmd_test("echo 'MONITOR_MODE=parallel' >> /etc/sysmonitor/process/test2");
    (void)exec_cmd_test("echo 'MONITOR_PERIOD=10' >> /etc/sysmonitor/process/test2");
    g_process_info->reload = true;
    (void)sleep(period + 1);
    ret = exec_cmd_test("cat /home/process.log | grep 'error: user test not exsit in system'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("cat /home/process.log");
    (void)exec_cmd_test("rm -rf /etc/sysmonitor/process/test2");

    (void)exec_cmd_test("echo 'NAME=sshd222' > /etc/sysmonitor/process/test3");
    (void)exec_cmd_test("echo 'USER=test' >> /etc/sysmonitor/process/test3");
    (void)exec_cmd_test("echo 'MONITOR_COMMAND=/home/monitor.sh' >> /etc/sysmonitor/process/test3");
    (void)exec_cmd_test("echo 'RECOVER_COMMAND=systemctl restart sshd' >> /etc/sysmonitor/process/test3");
    (void)exec_cmd_test("echo 'STOP_COMMAND=systemctl stop sshd' >> /etc/sysmonitor/process/test3");
    (void)exec_cmd_test("useradd test");
    g_process_info->reload = true;
    (void)sleep(period + 1);
    ret = exec_cmd_test("cat /home/process.log | grep 'add sshd222 to process monitor list'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("rm -rf /etc/sysmonitor/process/test3");
    (void)exec_cmd_test("userdel test");

    test_process_load_file_fun_002_2();
    test_process_load_file_fun_002_3();
    test_process_load_file_fun_002_4();
    test_process_load_file_fun_002_5();
    (void)exec_cmd_test("rm -rf /home/monitor.sh");
}

static void wait_for_reload(void)
{
    int ret;

    (void)exec_cmd_test("rm -rf /home/process.log");
    g_process_info->reload = true;
    for (;;) {
        ret = exec_cmd_test("cat /home/process.log | grep 'reload process monitor end'");
        if (ret == 0) {
            break;
        }
        (void)sleep(1);
    }
}

static void test_process_check_task_fun_001()
{
    int ret;
    unsigned int period = (unsigned int)g_process_info->period;

    (void)exec_cmd_test("echo 'NAME=/home/test.sh' > /etc/sysmonitor/process/test");
    (void)exec_cmd_test("echo 'MONITOR_COMMAND=/home/monitor.sh' >> /etc/sysmonitor/process/test");
    (void)exec_cmd_test("echo 'RECOVER_COMMAND=/home/recover.sh' >> /etc/sysmonitor/process/test");
    (void)exec_cmd_test("echo 'STOP_COMMAND=/home/stop.sh' >> /etc/sysmonitor/process/test");
    (void)exec_cmd_test("echo 'CHECK_AS_PARAM=on' >> /etc/sysmonitor/process/test");
    (void)exec_cmd_test("echo '#! /bin/bash' > /home/test.sh");
    (void)exec_cmd_test("echo 'sleep 60' >> /home/test.sh");
    (void)exec_cmd_test("echo '#! /bin/bash' > /home/monitor.sh");
    (void)exec_cmd_test("echo 'exit 0' >> /home/monitor.sh");
    (void)exec_cmd_test("echo '#! /bin/bash' > /home/recover.sh");
    (void)exec_cmd_test("echo 'exit 1' >> /home/recover.sh");
    (void)exec_cmd_test("echo '#! /bin/bash' > /home/stop.sh");
    (void)exec_cmd_test("echo 'exit 0' >> /home/stop.sh");
    (void)exec_cmd_test("chmod a+x /home/*.sh");

    wait_for_reload();
    ret = exec_cmd_test("cat /home/process.log | grep 'add /home/test.sh to process monitor list'");
    CU_ASSERT(ret == 0);

    (void)exec_cmd_test("echo '#! /bin/bash' > /home/monitor.sh");
    (void)exec_cmd_test("echo 'sleep 35' >> /home/monitor.sh");
    (void)sleep(period + POPEN_TIMEOUT + PROCESS_TIMEOUT);
    ret = exec_cmd_test("cat /home/process.log | grep 'execute MONITOR_COMMAND' | "
                        "grep '/home/monitor.sh'| grep '[-4]'");
    CU_ASSERT(ret == 0);

    (void)exec_cmd_test("echo '#! /bin/bash' > /home/monitor.sh");
    (void)exec_cmd_test("echo 'exit 1' >> /home/monitor.sh");
    (void)sleep(POPEN_TIMEOUT + (period + 1) * FAIL_NUM);
    ret = exec_cmd_test("cat /home/process.log | "
                        "grep '/home/test.sh is abnormal, check cmd return 1, use \"/home/recover.sh\" to recover'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/process.log | grep 'use \"/home/recover.sh 1\" recover failed,errno 1'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("echo '#! /bin/bash' > /home/monitor.sh");
    (void)exec_cmd_test("echo 'exit 0' >> /home/monitor.sh");
    (void)sleep(period + 1);
    ret = exec_cmd_test("cat /home/process.log | grep '/home/test.sh is recovered'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("rm -rf /home/test.sh && rm -rf /home/monitor.sh");
    (void)exec_cmd_test("rm -rf /home/recover.sh && rm -rf /home/stop.sh && rm -rf /etc/sysmonitor/process/test");
}

static void create_process_config_alarm(void)
{
    (void)exec_cmd_test("echo 'NAME=/home/test.sh' > /etc/sysmonitor/process/test");
    (void)exec_cmd_test("echo 'MONITOR_COMMAND=/home/monitor.sh' >> /etc/sysmonitor/process/test");
    (void)exec_cmd_test("echo 'RECOVER_COMMAND=/home/recover.sh' >> /etc/sysmonitor/process/test");
    (void)exec_cmd_test("echo 'USE_CMD_ALARM=on' >> /etc/sysmonitor/process/test");
    (void)exec_cmd_test("echo '#! /bin/bash' > /home/test.sh");
    (void)exec_cmd_test("echo 'sleep 60' >> /home/test.sh");
    (void)exec_cmd_test("echo '#! /bin/bash' > /home/monitor.sh");
    (void)exec_cmd_test("echo 'exit 1' >> /home/monitor.sh");
    (void)exec_cmd_test("echo '#! /bin/bash' > /home/recover.sh");
    (void)exec_cmd_test("echo 'exit 0' >> /home/recover.sh");
    (void)exec_cmd_test("chmod a+x /home/*.sh");
}

static void test_process_check_task_recover(void)
{
    int ret;
    unsigned int period = (unsigned int)g_process_info->period;

    (void)exec_cmd_test("echo '#! /bin/bash' > /home/monitor.sh");
    (void)exec_cmd_test("echo 'exit 0' >> /home/monitor.sh");
    (void)sleep(period + 1);
    ret = exec_cmd_test("cat /home/process.log | grep "
                        "'/home/test.sh is recovered, But recover-cmd is null,will not alarm'");
    CU_ASSERT(ret == 0);

    (void)exec_cmd_test("echo 'ALARM_RECOVER_COMMAND=/home/alarm_recover.sh' >> /etc/sysmonitor/process/test");
    (void)exec_cmd_test("echo '#! /bin/bash' > /home/alarm_recover.sh");
    (void)exec_cmd_test("echo 'echo alarm_recover_failed > /home/recover.log' >> /home/alarm_recover.sh");
    (void)exec_cmd_test("echo 'exit 1' >> /home/alarm_recover.sh");
    (void)exec_cmd_test("chmod a+x /home/alarm_recover.sh");
    wait_for_reload();
    (void)sleep(period + 1);
    ret = exec_cmd_test("cat /home/process.log | grep "
                        "'/home/test.sh is recovered, use \"/home/alarm_recover.sh\" to alarm faied, errno'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/recover.log | grep alarm_recover_failed");
    CU_ASSERT(ret == 0);

    (void)exec_cmd_test("echo '#! /bin/bash' > /home/alarm_recover.sh");
    (void)exec_cmd_test("echo 'echo alarm_recover_success > /home/recover.log' >> /home/alarm_recover.sh");
    (void)exec_cmd_test("echo 'exit 0' >> /home/alarm_recover.sh");
    (void)exec_cmd_test("rm -rf /home/process.log");
    (void)sleep(period + 1);
    ret = exec_cmd_test("cat /home/process.log | grep "
                        "'/home/test.sh is recovered, use \"/home/alarm_recover.sh\" to alarm'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/recover.log | grep alarm_recover_success");
    CU_ASSERT(ret == 0);
}

static void test_process_check_task_fun_002()
{
    int ret;
    unsigned int period = (unsigned int)g_process_info->period;

    create_process_config_alarm();
    wait_for_reload();
    (void)sleep(period + 1);
    ret = exec_cmd_test("cat /home/process.log | grep 'add /home/test.sh to process monitor list'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/process.log | grep "
                        "'/home/test.sh is abnormal, check cmd return 1, use \"/home/recover.sh\" to recover'");
    CU_ASSERT(ret == 0);
    (void)sleep(period * PROCESS_ALARM_COUNT + 1);
    ret = exec_cmd_test("cat /home/process.log | grep "
                        "'/home/test.sh is abnormal 5 times, But alarm-cmd is null,will not alarm'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("echo 'ALARM_COMMAND=/home/alarm.sh' >> /etc/sysmonitor/process/test");
    (void)exec_cmd_test("echo '#! /bin/bash' > /home/alarm.sh");
    (void)exec_cmd_test("echo 'echo alarm > /home/alarm.log' >> /home/alarm.sh");
    (void)exec_cmd_test("echo 'exit 0' >> /home/alarm.sh");
    (void)exec_cmd_test("chmod a+x /home/alarm.sh");
    wait_for_reload();

    (void)sleep(period + 1);
    ret = exec_cmd_test("cat /home/process.log | grep 'add /home/test.sh to process monitor list'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/process.log | grep "
                        "'/home/test.sh is abnormal, check cmd return 1, use \"/home/recover.sh\" to recover'");
    CU_ASSERT(ret == 0);
    (void)sleep(period * PROCESS_ALARM_COUNT + 1);
    ret = exec_cmd_test("cat /home/process.log | grep "
                        "'/home/test.sh is abnormal 5 times, use cmd \"/home/alarm.sh\" to alarm'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/alarm.log | grep alarm");
    CU_ASSERT(ret == 0);

    (void)exec_cmd_test("echo '#! /bin/bash' > /home/alarm.sh");
    (void)exec_cmd_test("echo 'echo alarm_failed > /home/alarm.log' >> /home/alarm.sh");
    (void)exec_cmd_test("echo 'exit 1' >> /home/alarm.sh");
    (void)sleep(period * PROCESS_ALARM_COUNT + 1);
    ret = exec_cmd_test("cat /home/process.log | grep "
                        "'/home/test.sh is abnormal 5 times, use cmd \"/home/alarm.sh\" to alarm failed,errno'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/alarm.log | grep alarm_failed");
    CU_ASSERT(ret == 0);

    test_process_check_task_recover();
    (void)exec_cmd_test("rm -rf /home/test.sh && rm -rf /home/monitor.sh && rm -rf /home/recover.sh");
    (void)exec_cmd_test("rm -rf /home/alarm.sh && rm -rf /home/alarm.log");
    (void)exec_cmd_test("rm -rf /home/alarm_recover.sh && rm -rf /home/recover.log");
    (void)exec_cmd_test("rm -rf /etc/sysmonitor/process/test");
}

static void create_test_process_config(void)
{
    (void)exec_cmd_test("echo 'NAME=/home/test.sh' > /etc/sysmonitor/process/test");
    (void)exec_cmd_test("echo 'MONITOR_COMMAND=/home/monitor.sh' >> /etc/sysmonitor/process/test");
    (void)exec_cmd_test("echo 'RECOVER_COMMAND=/home/recover.sh' >> /etc/sysmonitor/process/test");
    (void)exec_cmd_test("echo 'STOP_COMMAND=/home/stop.sh' >> /etc/sysmonitor/process/test");
    (void)exec_cmd_test("echo 'MONITOR_MODE=parallel' >> /etc/sysmonitor/process/test");
    (void)exec_cmd_test("echo 'MONITOR_PERIOD=1' >> /etc/sysmonitor/process/test");

    (void)exec_cmd_test("echo '#! /bin/bash' > /home/test.sh");
    (void)exec_cmd_test("echo 'sleep 60' >> /home/test.sh");
    (void)exec_cmd_test("echo '#! /bin/bash' > /home/monitor.sh");
    (void)exec_cmd_test("echo 'echo 111 >> /home/monitor.log' >> /home/monitor.sh");
    (void)exec_cmd_test("echo 'exit 0' >> /home/monitor.sh");
    (void)exec_cmd_test("echo '#! /bin/bash' > /home/recover.sh");
    (void)exec_cmd_test("echo 'exit 0' >> /home/recover.sh");
    (void)exec_cmd_test("echo '#! /bin/bash' > /home/stop.sh");
    (void)exec_cmd_test("echo 'exit 0' >> /home/stop.sh");
    (void)exec_cmd_test("chmod a+x /home/*.sh");
}

static void test_process_check_task_fun_003()
{
    int ret;
    unsigned int period = (unsigned int)g_process_info->period;

    create_test_process_config();
    wait_for_reload();
    (void)sleep(period + 1);
    ret = exec_cmd_test("cat /home/monitor.log | grep 111");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("echo '#! /bin/bash' > /home/monitor.sh");
    (void)exec_cmd_test("echo 'exit 1' >> /home/monitor.sh");
    (void)sleep(period + 1);
    ret = exec_cmd_test("cat /home/process.log | grep "
                        "'/home/test.sh is abnormal, check cmd return 1, use \"/home/recover.sh\" to recover'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("rm -rf /home/test.sh && rm -rf /home/monitor.sh && rm -rf /home/recover.sh");
    (void)exec_cmd_test("rm -rf /home/stop.sh && rm -rf /home/monitor.log && rm -rf /etc/sysmonitor/process/test");
}

static void test_process_check_task_fun_004_2(void)
{
    int ret;
    unsigned int period = (unsigned int)g_process_info->period;

    (void)exec_cmd_test("echo 'USE_CMD_ALARM=on' >> /etc/sysmonitor/process/test");
    (void)exec_cmd_test("echo 'ALARM_COMMAND=/home/alarm.sh' >> /etc/sysmonitor/process/test");
    (void)exec_cmd_test("echo '#! /bin/bash' > /home/alarm.sh");
    (void)exec_cmd_test("echo 'echo alarm > /home/alarm.log' >> /home/alarm.sh");
    (void)exec_cmd_test("echo 'exit 0' >> /home/alarm.sh");
    (void)exec_cmd_test("chmod a+x /home/alarm.sh");
    (void)exec_cmd_test("echo 'ALARM_RECOVER_COMMAND=/home/alarm_recover.sh' >> /etc/sysmonitor/process/test");
    (void)exec_cmd_test("echo '#! /bin/bash' > /home/alarm_recover.sh");
    (void)exec_cmd_test("echo 'echo alarm_recover_success > /home/recover.log' >> /home/alarm_recover.sh");
    (void)exec_cmd_test("echo 'exit 0' >> /home/alarm_recover.sh");
    (void)exec_cmd_test("chmod a+x /home/alarm_recover.sh");

    wait_for_reload();
    (void)sleep(period + 1);
    ret = exec_cmd_test("cat /home/process.log | grep 'add /home/test.sh to process monitor list'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/process.log | grep "
                        "'/home/test.sh is recovered, use \"/home/alarm_recover.sh\" to alarm'");
    CU_ASSERT(ret == 0);

    (void)exec_cmd_test("echo '#! /bin/bash' > /home/monitor.sh");
    (void)exec_cmd_test("echo 'exit 1' >> /home/monitor.sh");
    (void)sleep(period + 1);
    ret = exec_cmd_test("cat /home/process.log | "
                        "grep '/home/test.sh is abnormal, check cmd return 1, recover cmd is null, will not recover'");
    CU_ASSERT(ret == 0);
    (void)sleep(period * PROCESS_ALARM_COUNT + 1);
    ret = exec_cmd_test("cat /home/process.log | grep "
                        "'/home/test.sh is abnormal 5 times, use cmd \"/home/alarm.sh\" to alarm'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/alarm.log | grep alarm");
    CU_ASSERT(ret == 0);

    (void)exec_cmd_test("echo '#! /bin/bash' > /home/monitor.sh");
    (void)exec_cmd_test("echo 'exit 0' >> /home/monitor.sh");
    (void)sleep(period + 1);
    ret = exec_cmd_test("cat /home/process.log | grep "
                        "'/home/test.sh is recovered, use \"/home/alarm_recover.sh\" to alarm'");
    CU_ASSERT(ret == 0);
    ret = exec_cmd_test("cat /home/recover.log | grep alarm_recover_success");
    CU_ASSERT(ret == 0);
}

/* test functions when RECOVER_COMMAND is null */
static void test_process_check_task_fun_004(void)
{
    int ret;
    unsigned int period = (unsigned int)g_process_info->period;

    (void)exec_cmd_test("echo 'NAME=/home/test.sh' > /etc/sysmonitor/process/test");
    (void)exec_cmd_test("echo 'MONITOR_COMMAND=/home/monitor.sh' >> /etc/sysmonitor/process/test");
    (void)exec_cmd_test("echo '#! /bin/bash' > /home/monitor.sh");
    (void)exec_cmd_test("echo 'exit 0' >> /home/monitor.sh");
    (void)exec_cmd_test("chmod a+x /home/*.sh");

    /* USE_CMD_ALARM is off */
    wait_for_reload();
    (void)sleep(period + 1);
    ret = exec_cmd_test("cat /home/process.log | grep 'add /home/test.sh to process monitor list'");
    CU_ASSERT(ret == 0);

    (void)exec_cmd_test("echo '#! /bin/bash' > /home/monitor.sh");
    (void)exec_cmd_test("echo 'exit 1' >> /home/monitor.sh");
    (void)sleep(period * FAIL_NUM + period + 1);
    ret = exec_cmd_test("cat /home/process.log | "
                        "grep '/home/test.sh is abnormal, check cmd return 1, recover cmd is null, will not recover'");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("echo '#! /bin/bash' > /home/monitor.sh");
    (void)exec_cmd_test("echo 'exit 0' >> /home/monitor.sh");
    (void)sleep(period + 1);
    ret = exec_cmd_test("cat /home/process.log | grep '/home/test.sh is recovered'");
    CU_ASSERT(ret == 0);

    /* USE_CMD_ALARM is on */
    test_process_check_task_fun_004_2();

    (void)exec_cmd_test("rm -rf /home/monitor.sh");
    (void)exec_cmd_test("rm -rf /home/alarm.sh && rm -rf /home/alarm.log");
    (void)exec_cmd_test("rm -rf /home/alarm_recover.sh && rm -rf /home/recover.log");
    (void)exec_cmd_test("rm -rf /etc/sysmonitor/process/test");
}

static void test_process_check_task_fun_005(void)
{
    int ret;

    (void)exec_cmd_test("rm -f /etc/sysmonitor/process/*");
    (void)exec_cmd_test("echo 'USER=root' > /etc/sysmonitor/process/testdbus");
    (void)exec_cmd_test("echo 'NAME=testdbus' >> /etc/sysmonitor/process/testdbus");
    (void)exec_cmd_test("echo 'MONITOR_MODE=parallel' >> /etc/sysmonitor/process/testdbus");
    (void)exec_cmd_test("echo 'MONITOR_PERIOD=3' >> /etc/sysmonitor/process/testdbus");
    (void)exec_cmd_test("echo 'MONITOR_COMMAND=/home/test_dbus.sh' >> /etc/sysmonitor/process/testdbus");
    (void)exec_cmd_test("echo '#!/bin/bash' > /home/test_dbus.sh");
    (void)exec_cmd_test("echo 'DBUS_STRING=\":1\"' >> /home/test_dbus.sh");
    (void)exec_cmd_test("echo 'function can_dbus_process()' >> /home/test_dbus.sh");
    (void)exec_cmd_test("echo '{' >> /home/test_dbus.sh");
    (void)exec_cmd_test("echo '        which busctl > /dev/null 2>&1' >> /home/test_dbus.sh");
    (void)exec_cmd_test("echo '        if [ $? -ne 0 ]; then' >> /home/test_dbus.sh");
    (void)exec_cmd_test("echo '                return 0' >> /home/test_dbus.sh");
    (void)exec_cmd_test("echo '        fi' >> /home/test_dbus.sh");
    (void)exec_cmd_test("echo '        result=$(timeout 26s busctl call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus GetNameOwner \"s\" \"org.freedesktop.systemd1\" 2>&1)' >> /home/test_dbus.sh");
    (void)exec_cmd_test("echo '        if [[ $result =~ $DBUS_STRING ]]; then' >> /home/test_dbus.sh");
    (void)exec_cmd_test("echo '                return 0' >> /home/test_dbus.sh");
    (void)exec_cmd_test("echo '        fi' >> /home/test_dbus.sh");
    (void)exec_cmd_test("echo '        return 1' >> /home/test_dbus.sh");
    (void)exec_cmd_test("echo '}' >> /home/test_dbus.sh");
    (void)exec_cmd_test("echo 'can_dbus_process' >> /home/test_dbus.sh");
    (void)exec_cmd_test("echo 'exit $?' >> /home/test_dbus.sh");
    (void)exec_cmd_test("chmod a+x /home/*.sh");

    ret = exec_cmd_test("systemctl start dbus dbus.socket");
    CU_ASSERT(ret == 0);

    wait_for_reload();

    ret = exec_cmd_test("systemctl stop dbus dbus.socket");
    CU_ASSERT(ret == 0);
    (void)sleep(4);
    ret = exec_cmd_test("cat /home/process.log | grep 'testdbus is abnormal' | grep 'sysmonitor'");
    CU_ASSERT(ret == 0);

    (void)exec_cmd_test("systemctl start dbus dbus.socket");
    (void)exec_cmd_test("rm -f /home/test_dbus.sh");
    (void)exec_cmd_test("rm -f /etc/sysmonitor/process/testdbus");
}

static void test_process_check_task_fun_006(void)
{
    int ret;

    (void)exec_cmd_test("rm -f /etc/sysmonitor/process/*");
    (void)exec_cmd_test("echo 'USER=root' > /etc/sysmonitor/process/testdbus");
    (void)exec_cmd_test("echo 'NAME=testdbus' >> /etc/sysmonitor/process/testdbus");
    (void)exec_cmd_test("echo 'MONITOR_MODE=parallel' >> /etc/sysmonitor/process/testdbus");
    (void)exec_cmd_test("echo 'MONITOR_PERIOD=3' >> /etc/sysmonitor/process/testdbus");
    (void)exec_cmd_test("echo 'MONITOR_COMMAND=/home/test_dbus.sh' >> /etc/sysmonitor/process/testdbus");
    (void)exec_cmd_test("echo '#!/bin/bash' > /home/test_dbus.sh");
    (void)exec_cmd_test("echo 'DBUS_STRING=\":1\"' >> /home/test_dbus.sh");
    (void)exec_cmd_test("echo 'function can_dbus_process()' >> /home/test_dbus.sh");
    (void)exec_cmd_test("echo '{' >> /home/test_dbus.sh");
    (void)exec_cmd_test("echo '        which busctl > /dev/null 2>&1' >> /home/test_dbus.sh");
    (void)exec_cmd_test("echo '        if [ $? -ne 0 ]; then' >> /home/test_dbus.sh");
    (void)exec_cmd_test("echo '                return 0' >> /home/test_dbus.sh");
    (void)exec_cmd_test("echo '        fi' >> /home/test_dbus.sh");
    (void)exec_cmd_test("echo '        result=$(timeout 26s busctl call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus GetNameOwner \"s\" \"org.freedesktop.systemd1\" 2>&1)' >> /home/test_dbus.sh");
    (void)exec_cmd_test("echo '        if [[ $result =~ $DBUS_STRING ]]; then' >> /home/test_dbus.sh");
    (void)exec_cmd_test("echo '                return 0' >> /home/test_dbus.sh");
    (void)exec_cmd_test("echo '        fi' >> /home/test_dbus.sh");
    (void)exec_cmd_test("echo '        return 1' >> /home/test_dbus.sh");
    (void)exec_cmd_test("echo '}' >> /home/test_dbus.sh");
    (void)exec_cmd_test("echo 'can_dbus_process' >> /home/test_dbus.sh");
    (void)exec_cmd_test("echo 'exit $?' >> /home/test_dbus.sh");
    (void)exec_cmd_test("chmod a+x /home/*.sh");

    ret = exec_cmd_test("systemctl start dbus dbus.socket");
    CU_ASSERT(ret == 0);

    wait_for_reload();

    ret = exec_cmd_test("mv /usr/bin/busctl /usr/bin/busctl.bak");
    CU_ASSERT(ret == 0);
    (void)sleep(4);
    ret = exec_cmd_test("cat /home/process.log | grep 'testdbus is abnormal' | grep 'sysmonitor'");
    CU_ASSERT(ret != 0);

    (void)exec_cmd_test("mv /usr/bin/busctl.bak /usr/bin/busctl");
    (void)exec_cmd_test("systemctl start dbus dbus.socket");
    (void)exec_cmd_test("rm -f /home/test_dbus.sh");
    (void)exec_cmd_test("rm -f /etc/sysmonitor/process/testdbus");
}

static void test_process_reload_file_fun_001()
{
    int ret;
    unsigned int period = (unsigned int)g_process_info->period;

    create_test_process_config();
    wait_for_reload();
    (void)sleep(period + 1);
    ret = exec_cmd_test("cat /home/monitor.log | grep 111");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("echo '#! /bin/bash' > /home/monitor.sh");
    (void)exec_cmd_test("echo 'echo 222 >> /home/monitor111.log' >> /home/monitor.sh");
    (void)exec_cmd_test("echo 'exit 0' >> /home/monitor.sh");
    wait_for_reload();
    (void)sleep(period + 1);
    ret = exec_cmd_test("cat /home/monitor111.log | grep 222");
    CU_ASSERT(ret == 0);
    (void)exec_cmd_test("rm -rf /home/test.sh && rm -rf /home/monitor.sh && rm -rf /home/recover.sh");
    (void)exec_cmd_test("rm -rf /home/stop.sh && rm -rf /home/monitor.log && rm -rf /home/monitor111.log");
    (void)exec_cmd_test("rm -rf /etc/sysmonitor/process/test");
}

static void create_multiple_parallel_config(void)
{
    (void)exec_cmd_test("echo '#!/bin/bash' > /home/prepare.sh");
    (void)exec_cmd_test("echo 'for i in $(seq 1000) ; do' >> /home/prepare.sh");
    (void)exec_cmd_test("echo 'cat >/etc/sysmonitor/process/paral${i} <<EOF' >> /home/prepare.sh");
    (void)exec_cmd_test("echo 'NAME=paral${i}' >> /home/prepare.sh");
    (void)exec_cmd_test("echo 'MONITOR_COMMAND=/home/monitor${i}.sh' >> /home/prepare.sh");
    (void)exec_cmd_test("echo 'MONITOR_MODE=parallel' >> /home/prepare.sh");
    (void)exec_cmd_test("echo 'MONITOR_PERIOD=60' >> /home/prepare.sh");
    (void)exec_cmd_test("echo 'EOF' >> /home/prepare.sh");
    (void)exec_cmd_test("echo 'cat >/home/monitor${i}.sh <<EOF' >> /home/prepare.sh");
    (void)exec_cmd_test("echo '#!/bin/bash' >> /home/prepare.sh");
    (void)exec_cmd_test("echo 'echo para111 > /home/monitor${i}.log' >> /home/prepare.sh");
    (void)exec_cmd_test("echo 'EOF' >> /home/prepare.sh");
    (void)exec_cmd_test("echo 'done' >> /home/prepare.sh");

    (void)exec_cmd_test("sh /home/prepare.sh");
    (void)exec_cmd_test("chmod a+x /home/monitor*.sh");
    (void)exec_cmd_test("rm -rf /home/prepare.sh");
}

static void test_process_multiple_parellel_fun_001(void)
{
    int ret;

    create_multiple_parallel_config();
    wait_for_reload();
    /* it takes a bit long time for all parallel threads to be created */
    (void)sleep(MULTI_PARALLEL_THREAD_TIMEOUT);
    ret = exec_cmd_test("grep -l para111 /home/monitor*.log");
    CU_ASSERT_TRUE(ret == 0);
    (void)exec_cmd_test("rm -rf /etc/sysmonitor/process/paral* /home/monitor*.sh /home/monitor*.log");
}

static void test_process_parse_md_fun_001()
{
    bool ret = false;

    ret = parse_process_monitor_delay("PROCESS_MONITOR_DELAY", "off");
    CU_ASSERT(ret == true);
    ret = parse_process_monitor_delay("PROCESS_MONITOR_DELAY", "on");
    CU_ASSERT(ret == true);
    ret = parse_process_monitor_delay("PROCESS_MONITOR_DELAY", "ON");
    CU_ASSERT(ret == false);
}

static void test_process_parse_as_fun_001()
{
    bool ret = false;

    ret = parse_process_alarm_supress("-1");
    CU_ASSERT(ret == false);
    ret = parse_process_alarm_supress("a");
    CU_ASSERT(ret == false);
    ret = parse_process_alarm_supress("5");
    CU_ASSERT(ret == true);
}

static void test_process_parse_rt_fun_001()
{
    bool ret = false;

    ret = parse_process_restart_tiemout("-1");
    CU_ASSERT(ret == false);
    ret = parse_process_restart_tiemout("a");
    CU_ASSERT(ret == false);
    ret = parse_process_restart_tiemout("29");
    CU_ASSERT(ret == false);
    ret = parse_process_restart_tiemout("301");
    CU_ASSERT(ret == false);
    ret = parse_process_restart_tiemout("30");
    CU_ASSERT(ret == true);
    ret = parse_process_restart_tiemout("300");
    CU_ASSERT(ret == true);
    ret = parse_process_restart_tiemout("");
    CU_ASSERT(ret == false);
}

static void test_process_parse_rp_fun_001()
{
    bool ret = false;
    ret = parse_process_recall_period("-1");
    CU_ASSERT(ret == false);
    ret = parse_process_recall_period("a");
    CU_ASSERT(ret == false);
    ret = parse_process_recall_period("0");
    CU_ASSERT(ret == false);
    ret = parse_process_recall_period("1440");
    CU_ASSERT(ret == true);
    ret = parse_process_recall_period("5");
    CU_ASSERT(ret == true);
    ret = parse_process_recall_period("");
    CU_ASSERT(ret == false);
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

    suite = CU_add_suite("process", init_before_test, clean_after_test);
    if (suite == NULL) {
        goto err;
    }

    (void)CU_add_test(suite, "test_process_load_file_fun_001", test_process_load_file_fun_001);
    (void)CU_add_test(suite, "test_process_load_file_fun_002", test_process_load_file_fun_002);
    (void)CU_add_test(suite, "test_process_check_task_fun_001", test_process_check_task_fun_001);
    (void)CU_add_test(suite, "test_process_check_task_fun_002", test_process_check_task_fun_002);
    (void)CU_add_test(suite, "test_process_check_task_fun_003", test_process_check_task_fun_003);
    (void)CU_add_test(suite, "test_process_check_task_fun_004", test_process_check_task_fun_004);
    (void)CU_add_test(suite, "test_process_check_task_fun_005", test_process_check_task_fun_005);
    (void)CU_add_test(suite, "test_process_check_task_fun_006", test_process_check_task_fun_006);
    (void)CU_add_test(suite, "test_process_reload_file_fun_001", test_process_reload_file_fun_001);
    (void)CU_add_test(suite, "test_process_multiple_parellel_fun_001", test_process_multiple_parellel_fun_001);
    (void)CU_add_test(suite, "test_process_parse_md_fun_001", test_process_parse_md_fun_001);
    (void)CU_add_test(suite, "test_process_parse_as_fun_001", test_process_parse_as_fun_001);
    (void)CU_add_test(suite, "test_process_parse_rt_fun_001", test_process_parse_rt_fun_001);
    (void)CU_add_test(suite, "test_process_parse_rp_fun_001", test_process_parse_rp_fun_001);

    switch (g_cunit_mode) {
        case CUNIT_SCREEN:
            CU_basic_set_mode(CU_BRM_VERBOSE);
            CU_basic_run_tests();
            break;
        case CUNIT_XMLFILE:
            CU_set_output_filename("process");
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
