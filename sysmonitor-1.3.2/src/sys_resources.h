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
 * Description: define structure and function for system monitor
 * Author: xuchunmei
 * Create: 2019-2-14
 */
#ifndef SYS_RESOURCES_H
#define SYS_RESOURCES_H

#include "common.h"

enum system_monitor_item {
    CPU,
    MEM,
    PSCNT,
    SYSTEM_FDCNT,
    SYSTEM_MONITOR_ITEM_CNT
};

/*
 * interface for parse item monitor or alarm in system resources
 */
bool sys_resources_monitor_parse(const char *item, const char *value, int type, bool monitor);

/*
 * create system resources monitor thread
 */
void sys_resources_monitor_init(void);

/*
 * init g_system_item_info before parse sysmonitor.conf
 */
void sys_resources_item_init_early(void);

/*
 * call after parse /etc/sysconfig/sysmonitor
 * init system resources monitor item default value
 */
void sys_resources_item_init(void);

#endif
