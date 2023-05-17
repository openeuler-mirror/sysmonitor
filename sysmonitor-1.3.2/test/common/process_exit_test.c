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
 * Description: process receive SIGTERM not quit immediatally
 * Author: xuchunmei
 * Create: 2019-9-9
 */

#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <securec.h>

#define SLEEP_INTERVAL 600

static int g_quit = false;
static void quit_handler(int signo)
{
    g_quit = true;
}

int main()
{
    struct sigaction quit_action;

    (void)memset_s(&quit_action, sizeof(quit_action), 0, sizeof(quit_action));
    quit_action.sa_handler = quit_handler;
    (void)sigaction(SIGTERM, &quit_action, NULL);

    while (!g_quit) {
        (void)sleep(SLEEP_INTERVAL);
    }
    (void)sleep(SLEEP_INTERVAL);
    return 0;
}
