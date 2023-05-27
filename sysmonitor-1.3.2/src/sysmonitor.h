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
 * Description: define variable and function for sysmonitor
 * Author: xuchunmei
 * Create: 2016-1-1
 */
#ifndef SYSMONITOR_H
#define SYSMONITOR_H

#define HEARTBEAT_SOCKET "/var/run/heartbeat.socket"
#define CONF "/etc/sysconfig/sysmonitor"

#define RESTART_ALARM "systemctl restart sysalarm &> /dev/null"

extern void close_alarm(void);

#endif
