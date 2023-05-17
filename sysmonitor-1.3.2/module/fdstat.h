/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2016-2019. All rights reserved.
 * Description: file handle statistic
 * Author: xuchunmei
 * Create: 2016-1-1
 */
#ifndef SYSMONITOR_FDSTAT_H
#define SYSMONITOR_FDSTAT_H

#include <linux/types.h>
#include <linux/sched.h>

#ifndef CONFIG_EULEROS_SYSMONITOR_FD
struct fdstat {
	pid_t pid;
	unsigned int total_fd_num;
	char comm[TASK_COMM_LEN];
};
#endif

void fdstat_init(void);
void fdstat_exit(void);
#endif
