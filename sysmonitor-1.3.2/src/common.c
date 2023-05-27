/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2016-2019. All rights reserved.
 * sysmonitor licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Description: common function
 * Author: xuchunmei
 * Create: 2016-1-1
 */

#include "common.h"

#include <time.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <linux/netlink.h>

#include <securec.h>

#define PFD_NUM 2

/*
 * process exit handle
 * first send SIGTERM to the process, then wait for most 10 second
 * if process is still alive after 10 second, send SIGKILL and wait
 */
static void process_exit(pid_t pid, int *status)
{
    int ret;
    int timeout = PROCESS_EXIT_TIMEOUT;

    (void)kill(-pid, SIGTERM);
    (void)sleep(1);
    while (timeout--) {
        ret = waitpid(pid, status, WNOHANG);
        if (ret > 0) {
            return;
        }
        (void)sleep(1);
    }
    log_printf(LOG_INFO, "task[%d] process SIGTERM timeout,use SIGKILL.", pid);
    (void)kill(-pid, SIGKILL);
    (void)waitpid(pid, status, 0);
}

static FILE *get_pfd_file(int pfd, int *ret)
{
    int flags;
    FILE *fp = NULL;

    flags = fcntl(pfd, F_GETFL, 0);
    if (flags < 0) {
        log_printf(LOG_ERR, "monitor_popen: fcntl F_GETFL error [%d]", errno);
        *ret = ERROR_FCNTL;
        return NULL;
    }

    flags = fcntl(pfd, F_SETFL, (unsigned int)flags | O_NONBLOCK);
    if (flags < 0) {
        log_printf(LOG_ERR, "monitor_popen: fcntl F_SETFL error [%d]", errno);
        *ret = ERROR_FCNTL;
        return NULL;
    }

    fp = fdopen(pfd, "r");
    if (fp == NULL) {
        *ret = ERROR_FDOPEN;
        return NULL;
    }

    return fp;
}

static int get_child_exit_code(int status)
{
    int ret = 0;

    if (WIFEXITED(status)) {
        ret = WEXITSTATUS(status);
        if (ret != 0) {
            log_printf(LOG_INFO, "get child exit code error ret[%d]", ret);
        }
    }
    return ret;
}

static int process_monitor_popen_timeout(const char *psz_cmd, const char *psz_stop_cmd, int pfd)
{
    int status;
    pid_t pid;
    pid_t child_pid;
    int ret;

    log_printf(LOG_INFO, "execute \"%s\" timeout", psz_cmd);
    if (psz_stop_cmd == NULL) {
        return ERROR_TIMEOUT;
    }

    pid = fork();
    if (pid < 0) {
        log_printf(LOG_ERR, "monitor_popen: timeout fork error [%d]", errno);
        return ERROR_FORK;
    } else if (pid == 0) {
        (void)close(pfd);
        (void)execl("/bin/sh", "sh", "-c", psz_stop_cmd, NULL);
        exit(errno);
    }

    child_pid = waitpid(pid, &status, 0);
    if (child_pid == pid) {
        ret = get_child_exit_code(status);
        if (ret != 0) {
            log_printf(LOG_WARNING, "monitor popen: psz_stop_cmd[%s] execl error[%d]", psz_stop_cmd, ret);
        }
    }
    return ERROR_TIMEOUT;
}

static void process_pfd_and_fd(int pfd)
{
    int fd = -1;

    if (pfd != STDOUT_FILENO) {
        (void)dup2(pfd, STDOUT_FILENO);
        (void)close(pfd);
    }

    fd = open("/dev/null", O_RDWR, 0);
    if (fd >= 0) {
        (void)dup2(fd, STDIN_FILENO);
        (void)dup2(fd, STDERR_FILENO);
        if (fd != STDERR_FILENO) {
            (void)close(fd);
        }
    }
}

static int process_timeout_waitpid(pid_t pid, int *status, long timeout, int *sec)
{
    if (waitpid(pid, status, WNOHANG) > 0) {
        return 0;
    } else if (timeout > 0) {
        (void)sleep(1);
        *sec = *sec + 1;
        return 1;
    } else {
        /* timeout is 0 */
        (void)waitpid(pid, status, 0);
        return 0;
    }
}

/*
 * exec psz_cmd and put the result of psz_cmd in psz_buffer
 * if timeout > 0, when timeout exec psz_stop_cmd
 */
int monitor_popen(const char *psz_cmd, char *psz_buffer, unsigned int size, long timeout, const char *psz_stop_cmd)
{
    int result = 0;
    FILE *fp = NULL;
    int pfd[PFD_NUM] = {0};
    pid_t pid;
    fd_set rfds;
    struct timeval tv;
    int retval;
    int status;
    char *stdout_str = psz_buffer;
    int sec = 0;
    int ret;
    unsigned int len;

    ret = memset_s(psz_buffer, size, 0, size);
    if (ret) {
        log_printf(LOG_ERR, "monitor_popen: memset_s psz_buffer failed, ret: %d", ret);
        return -1;
    }

    if (pipe(pfd) < 0) {
        log_printf(LOG_ERR, "pipe error [%d]", errno);
        return ERROR_PIPE;
    }

    pid = fork();
    if (pid < 0) {
        log_printf(LOG_ERR, "monitor_popen: fork error [%d]", errno);
        (void)close(pfd[0]);
        (void)close(pfd[1]);
        return ERROR_FORK;
    } else if (pid == 0) {
        (void)setpgrp();
        (void)prctl(PR_SET_PDEATHSIG, SIGTERM);

        (void)close(pfd[0]);

        process_pfd_and_fd(pfd[1]);

        (void)execl("/bin/sh", "sh", "-c", psz_cmd, NULL);
        exit(errno);
    }

    (void)close(pfd[1]);
    fp = get_pfd_file(pfd[0], &result);
    if (fp == NULL) {
        process_exit(pid, &status);
        (void)close(pfd[0]);
        return result;
    }

    for (;;) {
        /* Watch pfd[0] to see when it has input. */
        FD_ZERO(&rfds);
        FD_SET(pfd[0], &rfds);

        if (timeout > 0) {
            if (sec >= timeout) {
                result = process_monitor_popen_timeout(psz_cmd, psz_stop_cmd, pfd[0]);
                process_exit(pid, &status);
                break;
            }
            tv.tv_sec = 1;
            tv.tv_usec = 0;
            retval = select(pfd[0] + 1, &rfds, NULL, NULL, &tv);
        } else {
            retval = select(pfd[0] + 1, &rfds, NULL, NULL, NULL);
        }

        if (retval == -1) {
            log_printf(LOG_ERR, "select error [%d]", errno);
            result = ERROR_SELECT;
            process_exit(pid, &status);
            break;
        } else if (retval) {
            if (!FD_ISSET(pfd[0], &rfds)) {
                continue;
            }
            len = fread(stdout_str, 1, size, fp);
            /* Pipe is closed, which means the child process has already exited. */
            if (len == 0) {
                (void)waitpid(pid, &status, 0);
                break;
            }

            if (size > len) {
                stdout_str += len;
                size -= len;
                continue;
            }

            /* len is larger than size, so waitpid to exit */
            stdout_str += size;
            size = 0;
            ret = process_timeout_waitpid(pid, &status, timeout, &sec);
            if (ret == 0) {
                break;
            }
        } else {
            /* Grandson process could inherit the pipe fd. */
            if (waitpid(pid, &status, WNOHANG) > 0) {
                break;
            }
            sec++;
        }
    }

    if (WIFEXITED(status)) {
        result = WEXITSTATUS(status);
        if (result != 0) {
            log_printf(LOG_WARNING, "monitor popen: psz_cmd[%s] execl error[%d]", psz_cmd, result);
        }
    }

    (void)fclose(fp);

    return result;
}

/*
 * save info to dst[pos] from src
 * src and len is promissed by caller
 */
static int save_args(char ***dst, int pos, const char *src, int len)
{
    int ret;
    char **args = *dst;

    if (pos >= ARGS_MAX) {
        log_printf(LOG_INFO, "save_args: too many args.");
        return -1;
    }

    if (len >= EXEC_MAX) {
        log_printf(LOG_INFO, "save_args: args len is longer than %d.", EXEC_MAX);
        return -1;
    }

    args[pos] = malloc(sizeof(char) * EXEC_MAX);
    if (args[pos] == NULL) {
        log_printf(LOG_ERR, "save_args: malloc for args failed.");
        return -1;
    }

    ret = memset_s(args[pos], EXEC_MAX, 0, EXEC_MAX);
    if (ret != 0) {
        log_printf(LOG_ERR, "save_args: memset_s args[%d] failed.", pos);
        goto err;
    }

    ret = strncpy_s(args[pos], EXEC_MAX, src, (size_t)len);
    if (ret != 0) {
        log_printf(LOG_ERR, "save_args: strncpy_s dst failed.");
        goto err;
    }
    return 0;

err:
    free(args[pos]);
    args[pos] = NULL;
    return -1;
}

static void get_arg_begin_pos(int *arg_begin_pos, int i)
{
    if (*arg_begin_pos == -1) {
        *arg_begin_pos = i;
    }
}

static int parse_args_from_cmd(const char *cmd, char ***cmdline, int *args_count)
{
    int i = 0;
    int arg_begin_pos = -1;
    bool quota_flag = false;
    int count = 0;
    int ret;

    while (cmd[i] != '\0') {
        if (cmd[i] == '\"') {
            if (quota_flag == false) {
                quota_flag = true;
                goto next_cmd;
            }
            quota_flag = false;
            if (arg_begin_pos == -1) {
                goto next_cmd;
            }
            ret = save_args(cmdline, count, cmd + arg_begin_pos, i - arg_begin_pos);
            if (ret < 0) {
                goto err;
            }
            count++;
            arg_begin_pos = -1;
        } else if (cmd[i] == ' ') {
            if (quota_flag == true) {
                get_arg_begin_pos(&arg_begin_pos, i);
                goto next_cmd;
            }
            if (arg_begin_pos == -1) {
                goto next_cmd;
            }
            ret = save_args(cmdline, count, cmd + arg_begin_pos, i - arg_begin_pos);
            if (ret < 0) {
                goto err;
            }
            count++;
            arg_begin_pos = -1;
        } else {
            get_arg_begin_pos(&arg_begin_pos, i);
        }
next_cmd:
        i++;
    }

    if (quota_flag == true) {
        log_printf(LOG_ERR, "get_exec_and_args, cmd[%s] config illegal.", cmd);
        goto err;
    }

    if (arg_begin_pos != -1) {
        ret = save_args(cmdline, count, cmd + arg_begin_pos, i - arg_begin_pos);
        if (ret < 0) {
            goto err;
        }
        count++;
    }

    *args_count = count;
    return 0;

err:
    log_printf(LOG_ERR, "get_exec_and_args, parse cmd[%s] for exec and args failed.", cmd);
    *args_count = count;
    return -1;
}

/* parse args, split by spaces and "" */
int get_exec_and_args(const char *cmd, char *exec, char ***cmdline)
{
    char **args = NULL;
    int i;
    int count = 0;
    int ret;

    *cmdline = malloc(sizeof(char *) * ARGS_MAX);
    if (*cmdline == NULL) {
        log_printf(LOG_ERR, "get_exec_and_args: malloc for cmdline failed.");
        return -1;
    }

    args = *cmdline;
    for (i = 0; i < ARGS_MAX; i++) {
        args[i] = NULL;
    }

    ret = parse_args_from_cmd(cmd, cmdline, &count);
    if (ret < 0) {
        goto err;
    }

    if (count == 0) {
        log_printf(LOG_INFO, "get_exec_and_args, exec and args is empty, cmd[%s]", cmd);
        goto err;
    }
    /* the last of args[] should be NULL when use execvp */
    args[count] = NULL;

    if (count > 0) {
        ret = strncpy_s(exec, EXEC_MAX, args[0], strlen(args[0]));
        if (ret != 0) {
            log_printf(LOG_ERR, "get_exec_and_args, strncpy_s exec failed.");
            goto err;
        }
    }
    return count;

err:
    for (i = 0; i < count; i++) {
        if (args[i] != NULL) {
            free(args[i]);
        }
    }
    free(args);
    *cmdline = NULL;
    return -1;
}

/*
 * free memory for args
 */
void free_args(char **args, int args_num)
{
    int i;

    if (args == NULL) {
        return;
    }
    for (i = 0; i < args_num; i++) {
        if (args[i] != NULL) {
            free(args[i]);
        }
    }
    free(args);
    args = NULL;
}

/*
 * exec psz_cmd, when bash_cmd is true, use "/bin/bash sh -c" to exec psz_cmd
 * otherwise split psz_cmd to exec and args and use execvp to exec command.
 */
static pid_t exec_cmd(uid_t uid, const char *psz_cmd, bool bash_cmd)
{
    char exec[EXEC_MAX] = {0};
    char **args = NULL;
    int args_num = 0;
    pid_t pid;
    int fd = -1;

    if (!bash_cmd) {
        args_num = get_exec_and_args(psz_cmd, exec, &args);
        if (args_num < 0) {
            return -1;
        }
    }

    pid = fork();
    if (pid < 0) {
        log_printf(LOG_ERR, "exec_cmd: fork error [%d]", errno);
        goto err;
    } else if (pid == 0) {
        (void)setpgrp();
        (void)prctl(PR_SET_PDEATHSIG, SIGTERM);

        fd = open("/dev/null", O_RDWR, 0);
        if (fd >= 0) {
            (void)dup2(fd, STDIN_FILENO);
            (void)dup2(fd, STDERR_FILENO);
            if (fd != STDERR_FILENO) {
                (void)close(fd);
            }
        }

        if (uid != DEFAULT_USER_ID) {
            if (setuid(uid) != 0) {
                exit(ERROR_SETUID);
            }
        }
        if (bash_cmd) {
            (void)execl("/bin/sh", "sh", "-c", psz_cmd, NULL);
        } else {
            (void)execvp(exec, args);
        }
        exit(errno);
    }

err:
    if (!bash_cmd) {
        free_args(args, args_num);
    }
    return pid;
}

static void handle_monitor_cmd_timeout(uid_t uid, const char *stop_cmd, bool bash_cmd, int *status)
{
    pid_t pid;
    pid_t child_pid;
    int ret;

    if (stop_cmd == NULL) {
        return;
    }

    pid = exec_cmd(uid, stop_cmd, bash_cmd);
    if (pid > 0) {
        child_pid = waitpid(pid, status, 0);
        if (child_pid == pid) {
            ret = get_child_exit_code(*status);
            if (ret != 0) {
                log_printf(LOG_WARNING, "handle monitor cmd timeout: stop_cmd[%s] execl error[%d]", stop_cmd, ret);
            }
        }
    }
}

/*
 * process monitor: exec monitor cmd, when timeout and stop cmd is not NULL, exec stop cmd
 * return 0 means success, otherwise means exception
 */
int monitor_cmd(uid_t uid, const char *psz_cmd, long timeout, const char *psz_stop_cmd, bool bash_cmd)
{
    int result = 0;
    pid_t pid;
    int status = 0;
    int msec = 0;
    struct timespec ts = {0};

    pid = exec_cmd(uid, psz_cmd, bash_cmd);
    if (pid < 0) {
        return pid;
    }

    for (;;) {
        if (timeout > 0) {
            if (waitpid(pid, &status, WNOHANG) > 0) {
                break;
            }

            ts.tv_nsec = PROCESS_SLEEP_INTERVAL;
            ts.tv_sec = 0;
            (void)nanosleep(&ts, NULL);
            msec++;
            /* msec++ every 100ms, so divid 10 to compare with timeout */
            if (msec / 10 >= timeout) {
                log_printf(LOG_INFO, "execute \"%s\" timeout", psz_cmd);
                handle_monitor_cmd_timeout(uid, psz_stop_cmd, bash_cmd, &status);
                result = ERROR_TIMEOUT;
                process_exit(pid, &status);
                break;
            }
        } else {
            (void)waitpid(pid, &status, 0);
            break;
        }
    }

    if (WIFEXITED(status) && result != ERROR_TIMEOUT) {
        result = WEXITSTATUS(status);
        if (result != 0) {
            log_printf(LOG_WARNING, "monitor cmd: psz_cmd[%s] execl error[%d]", psz_cmd, result);
        }
    }

    return result;
}

/*
 * get value from config, the format is like this:
 * MONITOR_SWITCH="on"
 * value must be in ""
 */
void get_value(const char *config, unsigned int item_size, char *value, unsigned int value_len)
{
    char *ptr = NULL;
    unsigned int size;
    int ret;

    /* item="value", so here skip 2 to get value */
    config += item_size + 2;
    ptr = strchr(config, '\"');
    if (ptr != NULL) {
        size = (unsigned int)(ptr - config);
        size = size < value_len ? size : value_len - 1;
        ret = strncpy_s(value, value_len, config, size);
        if (ret) {
            log_printf(LOG_ERR, "get_value: strncpy_s value failed, ret: %d", ret);
            return;
        }
    }
}

/*
 * parse config specified by conf
 */
bool parse_config(const char *conf, bool (*parse_line)(const char *line))
{
    char config[MAX_CONFIG];
    bool ret = true;
    FILE *fp = NULL;

    fp = fopen(conf, "r");
    if (fp == NULL) {
        if (get_log_interface_flag() == NORMAL_WRITE && get_flag_log_ok() == false) {
            (void)printf("[sysmonitor] open '%s' failed, errno [%d]\n", conf, errno);
        } else {
            log_printf(LOG_ERR, "open %s error [%d]", conf, errno);
        }
        return false;
    }

    for (;;) {
        if (!fgets(config, MAX_CONFIG - 1, fp)) {
            break;
        }

        if (parse_line != NULL) {
            if (parse_line(config) == false) {
                ret = false;
            }
        }
    }

    (void)fclose(fp);
    return ret;
}

/*
 * open config file and check file mode
 */
FILE *open_cfgfile(const char *d_name, int *config_fd)
{
    struct stat sb;
    FILE *file = NULL;
    int ret;

    ret = memset_s(&sb, sizeof(sb), 0, sizeof(sb));
    if (ret) {
        log_printf(LOG_ERR, "open_cfgfile: memset_s sb failed, ret: %d", ret);
        return NULL;
    }
    *config_fd = open(d_name, O_RDONLY | O_NONBLOCK | O_CLOEXEC, 0);
    if (*config_fd < OK) {
        log_printf(LOG_ERR, "open %s error [%d]", d_name, errno);
        return NULL;
    }
    if (stat(d_name, &sb) || !S_ISREG(sb.st_mode)) {
        goto err;
    }
    /* config file mode should be 700 */
    if (sb.st_mode & (S_IRWXG | S_IRWXO)) {
        log_printf(LOG_ERR, "%s: bad file mode", d_name);
        goto err;
    }
    file = fdopen(*config_fd, "r");
    if (file == NULL) {
        log_printf(LOG_ERR, "fdopen %s error [%d]", d_name, errno);
        goto err;
    }
    return file;

err:
    (void)close(*config_fd);
    *config_fd = -1;
    return NULL;
}

/*
 * check if the input is only number
 */
bool check_int(const char *input)
{
    const char *p = input;

    if (p == NULL) {
        log_printf(LOG_ERR, "check_int failed, input is NULL.");
        return false;
    }

    do {
        /* also return false if empty, ie, the first character is '\0' */
        if (*p < '0' || *p > '9') {
            return false;
        }
        p++;
    } while (*p);

    return true;
}

/*
 * check if the input is only decimal
 */
bool check_decimal(const char *input)
{
    const char *p = input;

    if (p == NULL) {
        log_printf(LOG_ERR, "check_decimal failed, input is NULL.");
        return false;
    }

    do {
        /* also return false if empty, ie, the first character is '\0' */
        if ((*p < '0' || *p > '9') && *p != '.') {
            return false;
        }
        p++;
    } while (*p);

    return true;
}

/*
 * exec the cmdstring, used to restart sysalarm
 */
int lovs_system(const char *cmdstring)
{
    pid_t pid;
    int status = 0;

    if (cmdstring == NULL) {
        return -1;
    }

    pid = fork();
    if (pid < 0) {
        status = -1;
    } else if (pid == 0) {
        (void)execl("/bin/sh", "sh", "-c", cmdstring, (char *)0);
        exit(errno);
    } else {
        while (waitpid(pid, &status, 0) < 0) {
            if (errno != EINTR) {
                status = -1;
                break;
            }
        }
    }

    return status;
}

const char *g_invalid_string[] = { ";", "|", "&", "$", ">",
                                   "<", "(", ")", "./", "/.",
                                   "?", "*", "`", "\\", "[",
                                   "]", "'", "!" };

/*
 * check config with illegal parameter
 */
int check_conf_file_valid(const char *config)
{
    unsigned int i;

    for (i = 0; i < array_size(g_invalid_string); i++) {
        if (strstr(config, g_invalid_string[i])) {
            log_printf(LOG_INFO, "ERROR: \"%s\" include nonsecure character!", config);
            return -1;
        }
    }

    return 0;
}

/*
 * check realpath of file
 */
bool check_file(const char *file)
{
    char *real_path = NULL;

    if (file == NULL || strlen(file) == 0) {
        return false;
    }

    if (access(file, F_OK) != 0) {
        log_printf(LOG_INFO, "access %s failed, errno: %d.", file, errno);
        return false;
    }

    real_path = realpath(file, NULL);
    if (real_path == NULL) {
        log_printf(LOG_INFO, "realpath %s failed, errno: %d.", file, errno);
        return false;
    }

    if (strcmp(real_path, file) != 0) {
        log_printf(LOG_INFO, "%s should be absolute path.", file);
        free(real_path);
        return false;
    }

    free(real_path);
    return true;
}

/*
 * convert value to int
 */
bool parse_value_int(const char *item, const char *value, unsigned int *result)
{
    if (check_int(value) == false || strtol(value, NULL, STRTOL_NUMBER_BASE) < 0) {
        log_printf(LOG_INFO, "%s config illegal, check %s.", item, value);
        return false;
    }

    *result = (unsigned int)strtol(value, NULL, STRTOL_NUMBER_BASE);
    return true;
}

bool parse_value_ulong(const char *item, const char *value, unsigned long *result)
{
    if (check_int(value) == false) {
        log_printf(LOG_INFO, "%s config illegal, check %s.", item, value);
        return false;
    }
    *result = strtoul(value, NULL, 0);
    return true;
}

/*
 * save value to result
 * result and size are promissed by caller
 */
bool parse_value_string(const char *item, const char *value, char *result, unsigned int size)
{
    int ret;

    if (strlen(value) >= size) {
        log_printf(LOG_INFO, "parse %s failed, %s: too long (>%u)", item, value, size - 1);
        return false;
    }

    ret = strcpy_s(result, size, value);
    if (ret) {
        log_printf(LOG_ERR, "parse config failed, strcpy_s %s failed.", value);
        return false;
    }
    return true;
}

/*
 * parse value to bool
 * ON/on to true
 * OFF/off to false
 */
bool parse_value_bool(const char *item, const char *value, bool *result)
{
    if (strcmp(value, "on") == 0 || strcmp(value, "ON") == 0) {
        *result = true;
    } else if (strcmp(value, "off") == 0 || strcmp(value, "OFF") == 0) {
        *result = false;
    } else {
        log_printf(LOG_INFO, "%s config illegal, check %s.", item, value);
        return false;
    }
    return true;
}

/*
 * parse value to float
 * for cpu, memory, sysfd alarm_value and resume_value check
 */
bool parse_value_float(const char *item, const char *value, float *result)
{
    if (check_decimal(value) == false) {
        return false;
    }
    *result = strtof(value, NULL);
    return true;
}

bool check_log_path(const char *log_path)
{
    char tmp[LOG_FILE_LEN] = {0};
    char *dir = NULL;
    int ret;

    if (!access(log_path, F_OK)) {
        return check_file(log_path);
    }

    /* file not exist, so check file directory realpath */
    ret = strncpy_s(tmp, LOG_FILE_LEN, log_path, LOG_FILE_LEN - 1);
    if (ret) {
        (void)printf("check_log_path: strncpy_s tmp failed, ret: %d.", ret);
        return false;
    }

    dir = dirname(tmp);
    return check_file(dir);
}

/*
 * write msg to kernel mod file
 */
int set_value_to_file(const char *msg, const char *path)
{
    ssize_t ret;
    int fd = -1;

    fd = open(path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, KERNELMODE_FILE_PERMISSION);
    if (fd < 0) {
        log_printf(LOG_ERR, "set_value_to_file open %s failed, errno[%d].", path, errno);
        return -1;
    }

    ret = write(fd, msg, strlen(msg));
    if (ret == -1) {
        log_printf(LOG_ERR, "set_value_to_file write failed, errno[%d].", errno);
        (void)close(fd);
        return -1;
    }

    (void)close(fd);
    return 0;
}

/*
 * return value:
 * 1:  do not find value
 * 0:  get value from string successfully
 * -1: value length exceeds outsize or memcpy_s failed
 */
int get_string(const char *config, const char *value, char *outstr, unsigned int outsize, const char *item)
{
    char *begin = NULL;
    char *end = NULL;
    unsigned int size;
    int ret;

    begin = strstr(config, value);
    if (begin == NULL) {
        return 1;
    }
    begin += strlen(value);
    end = strstr(begin, "\"");
    if (end == NULL) {
        return 1;
    }

    size = (unsigned int)(end - begin);
    if (size >= outsize) {
        log_printf(LOG_ERR, "parse %s failed, length exceeds %d", item, outsize - 1);
        return -1;
    }

    if (size == 0) {
        return 1;
    }

    ret = memset_s(outstr, outsize, 0, outsize);
    if (ret != 0) {
        log_printf(LOG_ERR, "get_string: memset_s outstr failed, ret: %d", ret);
        return -1;
    }
    ret = memcpy_s(outstr, outsize, begin, size);
    if (ret != 0) {
        log_printf(LOG_ERR, "get_string: memcpy_s outstr failed, ret: %d", ret);
        return -1;
    }

    return 0;
}
