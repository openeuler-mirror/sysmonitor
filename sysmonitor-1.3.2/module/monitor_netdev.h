/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2016-2019. All rights reserved.
 * Description: network device event monitor, structure for net event
 * Author: xuchunmei
 * Create: 2016-1-1
 */
#ifndef MONITOR_NETDEV_H
#define MONITOR_NETDEV_H

#include <uapi/linux/if.h>
#include <uapi/linux/netfilter.h>
#include <linux/sched.h>
#include <linux/types.h>

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

struct netmonitor_info {
	int event;
	pid_t pid;
	char comm[TASK_COMM_LEN];
	pid_t parent_pid;
	char parent_comm[TASK_COMM_LEN];
	char dev[IFNAMSIZ];
	int plen;
	int tb_id;
	union nf_inet_addr addr;
};

void monitor_netdev_init(void);
void monitor_netdev_exit(void);
#endif
