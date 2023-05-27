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
 * Description: testcase for common interface
 * Author: xuchunmei
 * Create: 2019-9-9
 */

#include <CUnit/Basic.h>
#include <CUnit/Automated.h>
#include <CUnit/Console.h>
#include <unistd.h>
#include <securec.h>
#include "common.h"
#include "../common_interface/common_interface.h"

typedef enum {
    CUNIT_SCREEN = 0,
    CUNIT_XMLFILE,
    CUNIT_CONSOLE
} cu_run_mode;

#define MIN_TEST_TEMP 2
#define TEST_TMP_LEN 10
#define MAX_FILE_MODE 0777
#define KB_SIZE 1024

static void test_monitor_popen_001()
{
    int ret;
    char buffer[MAX_CONFIG] = {0};
    char temp[MIN_TEST_TEMP] = {0};

    ret = monitor_popen("ls -al /home", buffer, sizeof(buffer), 0, NULL);
    CU_ASSERT(ret == 0);
    ret = monitor_popen("sleep 2", buffer, sizeof(buffer), 1, "ls -al /home > /dev/null");
    CU_ASSERT(ret == ERROR_TIMEOUT);
    ret = monitor_popen("ls -al /home", temp, sizeof(temp), 0, NULL);
    CU_ASSERT(ret == 0);
    (void)monitor_cmd(DEFAULT_USER_ID, "cp ./common/process_exit_test /home", 0, NULL, true);
    ret = monitor_popen("/home/process_exit_test", temp, sizeof(temp), MIN_TEST_TEMP, NULL);
    CU_ASSERT(ret == ERROR_TIMEOUT);
}

static void test_monitor_cmd_001()
{
    int ret;

    ret = monitor_cmd(DEFAULT_USER_ID, "ls -al /home", 0, NULL, false);
    CU_ASSERT(ret == 0);
    ret = monitor_cmd(DEFAULT_USER_ID, "ls -al /home > /dev/null", 0, NULL, false);
    CU_ASSERT(ret != 0);
    ret = monitor_cmd(DEFAULT_USER_ID, "ls -al /home > /dev/null", 0, NULL, true);
    CU_ASSERT(ret == 0);
    ret = monitor_cmd(0, "ls \"/home\"", 0, NULL, false);
    CU_ASSERT(ret == 0);
    ret = monitor_cmd(DEFAULT_USER_ID, "sleep 2", 1, NULL, false);
    CU_ASSERT(ret != 0);
    ret = monitor_cmd(DEFAULT_USER_ID, "sleep 2", 1, "ls /home", false);
    CU_ASSERT(ret != 0);
    ret = monitor_cmd(DEFAULT_USER_ID, "ls \"/home\" \"", 0, NULL, false);
    CU_ASSERT(ret != 0);
    ret = monitor_cmd(DEFAULT_USER_ID, "ls 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0\
                                        1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2\
                                        3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4\
                                        5 6 7 8 9 0", 0, NULL, false);
    CU_ASSERT(ret != 0);
    ret = monitor_cmd(DEFAULT_USER_ID, "ls \"/home\" \"/boot\"", 0, NULL, false);
    CU_ASSERT(ret == 0);
    ret = monitor_cmd(DEFAULT_USER_ID, "/bin/bash -c \"ls /home\"", 0, NULL, false);
    CU_ASSERT(ret == 0);
    ret = monitor_cmd(DEFAULT_USER_ID, "ls \"/home\" \" /boot\"", 0, NULL, false);
    CU_ASSERT(ret != 0);
    ret = monitor_cmd(DEFAULT_USER_ID, "ls \"1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0"
                                       "1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3"
                                       "4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6"
                                       "7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9"
                                       "0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2"
                                       "3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5"
                                       "6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8"
                                       "9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1"
                                       "2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4"
                                       "5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7"
                                       "8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0"
                                       "1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3"
                                       "4 5 6 7 8 9 0\"", 0, NULL, false);
    CU_ASSERT(ret != 0);
}

static void test_get_value_001()
{
    char value[MAX_TEMPSTR] = {0};
    char tmp[TEST_TMP_LEN] = {0};

    get_value("MONITOR_SWITCH=\"on\"", (unsigned int)strlen("MONITOR_SWITCH"), value, sizeof(value));
    CU_ASSERT(strcmp(value, "on") == 0);

    get_value("MONITOR_COMMAND=\"11111111111111\"", (unsigned int)strlen("MONITOR_COMMAND"), tmp, sizeof(tmp));
    CU_ASSERT(strcmp(tmp, "11111111111111") != 0);
    CU_ASSERT(strcmp(tmp, "111111111") == 0);
    (void)memset_s(tmp, sizeof(tmp), 0, sizeof(tmp));
    get_value("MONITOR_COMMAND=\"\"", (unsigned int)strlen("MONITOR_COMMAND"), tmp, sizeof(tmp));
    CU_ASSERT(strlen(tmp) == 0);
}

static void create_test_file(const char *name, const char *msg)
{
    int fd;
    ssize_t ret;

    fd = open(name, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, LOG_FILE_PERMISSION);
    if (fd < 0) {
        return;
    }

    lseek(fd, 0, SEEK_END);
    ret = write(fd, msg, strlen(msg));
    if (ret == -1) {
        (void)printf("write to %s failed.\n", name);
    }
    (void)close(fd);
    fd = -1;
}

/*
 * create large file for 1G=1024*1024*1024
 */
static void create_large_file(const char *name)
{
    int fd = -1;
    char temp[KB_SIZE] = {0};
    int i;
    ssize_t ret;

    fd = open(name, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, LOG_FILE_PERMISSION);
    if (fd < 0) {
        (void)printf("create file %s failed.", name);
        return;
    }

    (void)memset_s(temp, sizeof(temp), '@', sizeof(temp));
    for (i = 0; i < KB_SIZE * KB_SIZE; i++) {
        (void)lseek(fd, 0, SEEK_END);
        ret = write(fd, temp, sizeof(temp));
        if (ret < 0 || ret != sizeof(temp))
            (void)printf("write to %s failed.\n", name);
    }
    (void)close(fd);
    fd = -1;
}

static bool parse_line_ok(const char *line)
{
    return true;
}

static bool parse_line_fail(const char *line)
{
    return false;
}

static bool parse_line_check_valid(const char *line)
{
    if (check_conf_file_valid(line) == -1)
        return false;

    return true;
}

static void test_parse_config_001()
{
    bool ret = false;

    ret = parse_config("test_config", parse_line_ok);
    CU_ASSERT(ret == false);

    set_log_interface_flag(NORMAL_WRITE);
    set_flag_log_ok(false);
    ret = parse_config("test_config", parse_line_ok);
    CU_ASSERT(ret == false);

    create_test_file("test_config", "test parse config");
    ret = parse_config("test_config", parse_line_ok);
    CU_ASSERT(ret == true);
    ret = parse_config("test_config", parse_line_fail);
    CU_ASSERT(ret == false);
    (void)unlink("test_config");
    create_large_file("test_large");
    ret = parse_config("test_large", parse_line_ok);
    CU_ASSERT(ret == true);
    (void)unlink("test_large");

    create_test_file("test_valid", "!@$%^&*(");
    ret = parse_config("test_config", parse_line_check_valid);
    CU_ASSERT(ret == false);
    (void)unlink("test_valid");
}

static void test_open_cfgfile_001()
{
    int fd = -1;
    FILE *file = NULL;

    /* test file not exist */
    file = open_cfgfile("test_opencfg", &fd);
    CU_ASSERT(file == NULL);

    /* create test_opencfg and chmod mode to 700 */
    create_test_file("test_opencfg", "test open cfg");

    /* test open file */
    file = open_cfgfile("test_opencfg", &fd);
    CU_ASSERT(file != NULL);
    if (file != NULL) {
        (void)fclose(file);
        file = NULL;
    }
    if (fd >= 0) {
        fd = -1;
    }

    /* test file mode */
    (void)chmod("test_opencfg", MAX_FILE_MODE);
    file = open_cfgfile("test_opencfg", &fd);
    CU_ASSERT(file == NULL);
    if (file != NULL) {
        (void)fclose(file);
        file = NULL;
    }
    (void)unlink("test_opencfg");
}

static void test_check_int_001()
{
    CU_ASSERT(check_int(NULL) == false);
    CU_ASSERT(check_int("12345") == true);
    CU_ASSERT(check_int("a") == false);
    CU_ASSERT(check_int("-12345") == false);
    CU_ASSERT(check_int("123.45") == false);
}

static void test_check_decimal_001()
{
    CU_ASSERT(check_decimal(NULL) == false);
    CU_ASSERT(check_decimal("12345") == true);
    CU_ASSERT(check_decimal("123.45") == true);
    CU_ASSERT(check_decimal("a") == false);
    CU_ASSERT(check_decimal("-12345") == false);
    CU_ASSERT(check_decimal(".123") == true || check_decimal("123.") == true);
    CU_ASSERT(check_decimal("2.2.2") == true);
}

static void test_lvos_system_001()
{
    int ret;
    char out[MAX_TEMPSTR] = {0};

    CU_ASSERT(lovs_system(NULL) == -1);
    /* check if system is in running state, in obs build we cannot restart systemd service */
    ret = monitor_popen("systemctl is-system-running", out, sizeof(out), 0, NULL);
    if (ret < 0) {
        return;
    }
    if (strstr(out, "running") || strstr(out, "degraded")) {
        CU_ASSERT(lovs_system("systemctl restart crond") == 0);
    } else {
        CU_ASSERT(lovs_system("systemctl restart crond") != 0);
    }
    CU_ASSERT(lovs_system("ls /home > /dev/null") == 0);
}

static void test_check_conf_file_valid_001()
{
    CU_ASSERT(check_conf_file_valid(";") == -1);
    CU_ASSERT(check_conf_file_valid("|") == -1);
    CU_ASSERT(check_conf_file_valid("&") == -1);
    CU_ASSERT(check_conf_file_valid("$") == -1);
    CU_ASSERT(check_conf_file_valid(">") == -1);
    CU_ASSERT(check_conf_file_valid("<") == -1);
    CU_ASSERT(check_conf_file_valid("(") == -1);
    CU_ASSERT(check_conf_file_valid(")") == -1);
    CU_ASSERT(check_conf_file_valid("./") == -1);
    CU_ASSERT(check_conf_file_valid("/.") == -1);
    CU_ASSERT(check_conf_file_valid("?") == -1);
    CU_ASSERT(check_conf_file_valid("*") == -1);
    CU_ASSERT(check_conf_file_valid("`") == -1);
    CU_ASSERT(check_conf_file_valid("\\") == -1);
    CU_ASSERT(check_conf_file_valid("[") == -1);
    CU_ASSERT(check_conf_file_valid("]") == -1);
    CU_ASSERT(check_conf_file_valid("'") == -1);
    CU_ASSERT(check_conf_file_valid("!") == -1);
    CU_ASSERT(check_conf_file_valid("a") == 0);
    CU_ASSERT(check_conf_file_valid(".") == 0);
    CU_ASSERT(check_conf_file_valid("0") == 0);
    CU_ASSERT(check_conf_file_valid("-") == 0);
}

static void test_check_file_001()
{
    CU_ASSERT(check_file(NULL) == false);
    CU_ASSERT(check_file("") == false);
    CU_ASSERT(check_file("/var/run/test.pid") == false);
    CU_ASSERT(check_file("/bin/ls") == false);
    CU_ASSERT(check_file("/etc/profile") == true);
}

static void test_parse_value_int_001()
{
    unsigned int result;

    CU_ASSERT(parse_value_int("MONITOR_PERIOD", "a", &result) == false);
    CU_ASSERT(parse_value_int("MONITOR_PERIOD", "-1", &result) == false);
    CU_ASSERT(parse_value_int("MONITOR_PERIOD", "10", &result) == true);
}

static void test_parse_value_ulong_001()
{
    unsigned long result;

    CU_ASSERT(parse_value_ulong("MONITOR_PERIOD", "a", &result) == false);
    CU_ASSERT(parse_value_ulong("MONITOR_PERIOD", "-1", &result) == false);
    CU_ASSERT(parse_value_ulong("MONITOR_PERIOD", "600", &result) == true && result == 600);
}

static void test_parse_value_string_001()
{
    char temp[MAX_TEMPSTR] = {0};

    CU_ASSERT(parse_value_string("MONITOR_COMMAND", "0123456789", temp, MIN_TEST_TEMP) == false);
    CU_ASSERT(parse_value_string("MONITOR_COMMAND", "0123456789", temp, sizeof(temp)) == true);
}

static void test_parse_value_bool_001()
{
    bool result = false;

    CU_ASSERT(parse_value_bool("PROCESS_MONITOR", "ON", &result) == true);
    CU_ASSERT(result == true);
    CU_ASSERT(parse_value_bool("PROCESS_MONITOR", "on", &result) == true);
    CU_ASSERT(result == true);
    CU_ASSERT(parse_value_bool("PROCESS_MONITOR", "OFF", &result) == true);
    CU_ASSERT(result == false);
    CU_ASSERT(parse_value_bool("PROCESS_MONITOR", "off", &result) == true);
    CU_ASSERT(result == false);
    result = true;
    CU_ASSERT(parse_value_bool("PROCESS_MONITOR", "Off", &result) == false);
    CU_ASSERT(result == true);
}

static void test_parse_value_float_001()
{
    float result;

    CU_ASSERT(parse_value_float("ALARM", "11.22", &result) == true);
    CU_ASSERT(parse_value_float("ALARM", "a", &result) == false);
    CU_ASSERT(parse_value_float("ALARM", "-123", &result) == false);
}

static void test_check_log_path_001()
{
    CU_ASSERT(check_log_path("/var/log/test.log") == true);
    CU_ASSERT(check_log_path("/home/111/222") == false);
    CU_ASSERT(check_log_path("/bin/ls") == false);
}

/*static void set_proc_fdenable(const char *msg, const char *path)
{
    int ret;
    long num;
    long value;
    size_t len;
    char buf[MAX_LEN] = {0};
    char cmd[MAX_LEN] = {0};

    ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1,
        "cat %s", path);
    if (ret == -1) {
        (void)printf("snprintf_s cmd failed, ret: %d", ret);
        return;
    }

    ret = set_value_to_file(msg, path);
    CU_ASSERT(ret == 0);

    (void)monitor_popen(cmd, buf, sizeof(buf) - 1, 0, NULL);
    CU_ASSERT(ret == 0);
    len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') {
        buf[len - 1] = '\0';
    }
    num = strtol(buf, NULL, STRTOL_NUMBER_BASE);
    value = strtol(msg, NULL, STRTOL_NUMBER_BASE);
    CU_ASSERT(num == value);
}*/

static void test_set_value_to_file()
{
    /*int ret;

    set_proc_fdenable("1", RROC_FDENABLE);

    set_proc_fdenable("0", RROC_FDENABLE);

    ret = set_value_to_file("2", RROC_FDENABLE);
    CU_ASSERT(ret != 0);

    ret = set_value_to_file("1", "/proc/fdenable1");
    CU_ASSERT(ret != 0);*/
}

static bool add_test_parse_value(CU_pSuite suite)
{
    if (CU_add_test(suite, "test_parse_value_int_001", test_parse_value_int_001) == NULL ||
        CU_add_test(suite, "test_parse_value_ulong_001", test_parse_value_ulong_001) == NULL ||
        CU_add_test(suite, "test_parse_value_string_001", test_parse_value_string_001) == NULL ||
        CU_add_test(suite, "test_parse_value_bool_001", test_parse_value_bool_001) == NULL ||
        CU_add_test(suite, "test_parse_value_float_001", test_parse_value_float_001) == NULL) {
        return false;
    }
    return true;
}

static bool add_test_check(CU_pSuite suite)
{
    if (CU_add_test(suite, "test_check_int_001", test_check_int_001) == NULL ||
        CU_add_test(suite, "test_check_decimal_001", test_check_decimal_001) == NULL ||
        CU_add_test(suite, "test_check_conf_file_valid_001", test_check_conf_file_valid_001) == NULL ||
        CU_add_test(suite, "test_check_file_001", test_check_file_001) == NULL ||
        CU_add_test(suite, "test_check_log_path_001", test_check_log_path_001) == NULL) {
        return false;
    }
    return true;
}

static bool general_test(CU_pSuite suite)
{
    if (CU_add_test(suite, "test_set_value_to_file", test_set_value_to_file) == NULL) {
        return false;
    }
    return true;
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

    suite = CU_add_suite("common", NULL, NULL);
    if (suite == NULL) {
        goto err;
    }

    if (CU_add_test(suite, "test_monitor_popen_001", test_monitor_popen_001) == NULL ||
        CU_add_test(suite, "test_monitor_cmd_001", test_monitor_cmd_001) == NULL ||
        CU_add_test(suite, "test_get_value_001", test_get_value_001) == NULL ||
        CU_add_test(suite, "test_parse_config_001", test_parse_config_001) == NULL ||
        CU_add_test(suite, "test_open_cfgfile_001", test_open_cfgfile_001) == NULL ||
        CU_add_test(suite, "test_lvos_system_001", test_lvos_system_001) == NULL ||
        !add_test_parse_value(suite) || !add_test_check(suite) ||
        !general_test(suite)) {
        goto err;
    }

    switch (g_cunit_mode) {
        case CUNIT_SCREEN:
            CU_basic_set_mode(CU_BRM_VERBOSE);
            CU_basic_run_tests();
            break;
        case CUNIT_XMLFILE:
            CU_set_output_filename("common");
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
