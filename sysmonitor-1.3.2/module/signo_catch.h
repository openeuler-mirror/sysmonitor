/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2016-2019. All rights reserved.
 * Description: define variable, structure and function for signal catch module
 * Author: xuchunmei
 * Create: 2016-1-1
 */
#ifndef SIGNO_CATCH_H
#define SIGNO_CATCH_H

#include <uapi/linux/limits.h>
#include <linux/sched.h>
#include <linux/types.h>

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
} ce_signo_msg;

typedef struct __signo_msg {
	unsigned long signo;
	pid_t send_pid;
	char send_comm[TASK_COMM_LEN];
	pid_t send_parent_pid;
	char send_parent_comm[TASK_COMM_LEN];
	pid_t recv_pid;
	char recv_comm[TASK_COMM_LEN];
} qemu_signo_msg;

void signo_catch_init(void);
void signo_catch_exit(void);

#endif
