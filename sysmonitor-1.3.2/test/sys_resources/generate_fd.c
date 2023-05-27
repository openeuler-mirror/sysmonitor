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
 * Description: generate fd to test sys fd use
 * Author: xuchunmei
 * Create: 2019-10-28
 */
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <securec.h>

#define MAX_FD 1024
#define SLEEP_INTERVAL 600

static int g_fd[MAX_FD];
static int g_quit = false;
static void quit_handler(int signo)
{
    g_quit = true;
}

int main()
{
    int i;
    struct sigaction quit_action;

    (void)memset_s(&quit_action, sizeof(quit_action), 0, sizeof(quit_action));
    quit_action.sa_handler = quit_handler;
    (void)sigaction(SIGTERM, &quit_action, NULL);

    for (i = 0; i < MAX_FD; i++) {
        g_fd[i] = -1;
        g_fd[i] = open("/etc/sysconfig/sysmonitor", O_RDONLY | O_NONBLOCK | O_CLOEXEC, 0);
    }

    while (!g_quit) {
        (void)sleep(SLEEP_INTERVAL);
    }

    for (i = 0; i < MAX_FD; i++) {
        if (g_fd[i] == -1) {
            continue;
        }
        (void)close(g_fd[i]);
        g_fd[i] = -1;
    }
    return 0;
}
