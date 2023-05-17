/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * sysmonitor licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Description: open fd to test process fd use
 * Author: zhangguangzhi
 * Create: 2020-02-14
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define MAX_FD 1024
#define SLEEP_TIME 10
#define TIME 1

static int g_openfd[MAX_FD];

int main()
{
    int i;

    for (i = 0; i < MAX_FD; i++) {
        g_openfd[i] = -1;
        g_openfd[i] = open("/etc/sysconfig/sysmonitor", O_RDONLY | O_NONBLOCK | O_CLOEXEC, 0);
    }

    for (i = 0; i < SLEEP_TIME; i++) {
        (void)sleep(TIME);
    }

    for (i = 0; i < MAX_FD; i++) {
        if (g_openfd[i] != -1) {
            (void)close(g_openfd[i]);
            g_openfd[i] = -1;
        }
    }
    return 0;
}
