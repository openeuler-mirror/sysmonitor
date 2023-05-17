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
 * Description: generate zombie process to test zombie monitor
 * Author: xietangxin
 * Create: 2021-11-29
 */
#include <stdlib.h>
#include <unistd.h>

#define ZOMBIE_NUM 5
#define SLEEP_INTERVAL 1

int main()
{
    int ret;

    for (int i = 0; i < ZOMBIE_NUM; i++) {
        ret = fork();
        if (ret > 0) {
            (void)sleep(SLEEP_INTERVAL);
        } else if (ret == 0) {
            exit(0);
        }
    }

    for (;;) {}
    return 0;
}