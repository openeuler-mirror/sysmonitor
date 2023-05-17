/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2016-2019. All rights reserved.
 * Description: file handle statistic
 * Author: xuchunmei
 * Create: 2016-1-1
 */
#include "fdstat.h"

#include <linux/file.h>
#include <linux/notifier.h>
#include <linux/poll.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>

#include "sysmonitor_main.h"

#ifdef CONFIG_EULEROS_SYSMONITOR_FD
static int do_fdstat(struct notifier_block *self, unsigned long val, void *data)
{
	struct fdstat *notifier_call_data = (struct fdstat *)data;
	struct fdstat msg;
	int ret;

	(void)memset(&msg, 0, sizeof(struct fdstat));
	msg.pid = notifier_call_data->pid;
	msg.total_fd_num = notifier_call_data->total_fd_num + 1;
	(void)memcpy(msg.comm, notifier_call_data->comm, TASK_COMM_LEN);
	(void)save_msg(FDSTAT, &msg, sizeof(struct fdstat));
	return NOTIFY_DONE;
}

static struct notifier_block g_fdstat_nb = {
	.notifier_call = do_fdstat,
	.priority = NOTIFY_CALL_PRIORITY,
};
#endif

void fdstat_init(void)
{
#ifdef CONFIG_EULEROS_SYSMONITOR_FD
	(void)register_fdstat_notifier(&g_fdstat_nb);
#endif
}

void fdstat_exit(void)
{
#ifdef CONFIG_EULEROS_SYSMONITOR_FD
	(void)unregister_fdstat_notifier(&g_fdstat_nb);
#endif
}
