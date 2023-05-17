/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: define for sysmonitor event msg and function
 * Author: xuchunmei
 * Create: 2019-3-20
 */
#ifndef SYSMONITOR_H
#define SYSMONITOR_H

#define NOTIFY_CALL_PRIORITY 100
enum sysmonitor_event_type {
	SIGNAL,
	FDSTAT,
	NETWORK
};

unsigned long get_sigcatchmask(void);
int get_netratelimit_burst(void);
int save_msg(int type, const void *msg, int msg_size);
#endif
