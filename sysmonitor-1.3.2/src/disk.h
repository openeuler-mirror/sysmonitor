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
 *  Description: define variable and function for disk monitor
 * Author: xuchunmei
 * Create: 2016-1-1
 */
#ifndef __DISK_H__
#define __DISK_H__

#define IO_DELAY_CONF "/etc/sysmonitor/iodelay"

void disk_monitor_init(void);
void inode_monitor_init(void);
void io_delay_monitor_init(void);

#endif
