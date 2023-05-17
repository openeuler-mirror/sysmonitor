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
 * Description: define structure for sysmonitor event, this is same as sysmonitor module defined
 * Author: xuchunmei
 * Create: 2019-3-21
 */
#ifndef SYS_EVENT_H
#define SYS_EVENT_H

#include <unistd.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <linux/limits.h>
#include "common.h"

#define EVENT_MSG_SIZE 1024
#define MAX_DEV 16

struct fdstat {
    pid_t pid;
    unsigned int total_fd_num;
    char comm[TASK_COMM_LEN];
};

#define CALL_CHAIN_NUM 4

typedef struct _signo_msg {
    unsigned long signo;
    pid_t send_pid;
    char send_comm[TASK_COMM_LEN];
    char send_exe[NAME_MAX];
    pid_t send_parent_pid;
    char send_parent_comm[TASK_COMM_LEN];
    char send_parent_exe[NAME_MAX];
    pid_t recv_pid;
    char recv_comm[TASK_COMM_LEN];
    char recv_exe[NAME_MAX];
    pid_t send_chain_pid[CALL_CHAIN_NUM];
    char send_chain_comm[CALL_CHAIN_NUM][TASK_COMM_LEN];
} signo_mesg;

enum netmonitor_event {
    UP,
    DOWN,
    DELADDR,
    NEWADDR,
    DELADDR6,
    NEWADDR6,
    FIB_DEL,
    FIB_ADD,
    FIB_REPLACE,
    FIB_APPEND,
    FIB6_DEL,
    FIB6_ADD,
    FIB6_REPLACE,
    FIB6_APPEND
};

typedef struct _netmonitor_info {
    int event;
    pid_t pid;
    char comm[TASK_COMM_LEN];
    pid_t parent_pid;
    char parent_comm[TASK_COMM_LEN];
    char dev[MAX_DEV];
    int plen;
    int tb_id;
    union nf_inet_addr addr;
} netmonitor_info;

enum sysmonitor_event_type {
    SIGNAL,
    FDSTAT,
    NETWORK,
    SYS_EVENT_CNT
};

typedef struct _sysmonitor_event_msg {
    int type;
    char msg[EVENT_MSG_SIZE];
} sysmonitor_event_msg;


bool sys_event_monitor_parse(const char *item, const char *value, int type, bool monitor);
void close_sys_event_fd(void);
void sys_event_item_init_early(void);
void sys_event_item_init(void);
void sys_event_monitor_init(void);
bool parse_net_ratelimit_burst(const char *value);
bool parse_fd_monitor_log_path(const char *value);
void set_poll_timeout(int timeout);
#endif
