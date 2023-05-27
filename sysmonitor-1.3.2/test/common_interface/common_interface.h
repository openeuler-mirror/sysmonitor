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
 * Description: common function
 * Author: xuchunmei
 * Create: 2019-9-28
 */
#ifndef __COMMON_INTERFACE_H
#define __COMMON_INTERFACE_H
#include "common.h"

#define DEFAULT_FDTHRESHOLD 80
#define DEFAULT_FDENABLE 1
#define PROC_FDTHRESHOLD "/proc/fdthreshold"
#define RROC_FDENABLE "/proc/fdenable"
#define SIGCATCHMAK "/sys/module/sysmonitor/parameters/sigcatchmask"
#define MAX_LEN 200

void init_log_for_test(const char *name);
void clear_log_config(const char *name);
void set_log_interface_flag(int flag);
void set_flag_log_ok(bool flag);
int exec_cmd_test(const char *cmd);
monitor_thread *get_thread_item_info(int type);
void recover_sysmonitor(void);
void init_sysmonitor(void);
#endif
