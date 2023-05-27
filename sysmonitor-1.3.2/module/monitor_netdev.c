/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2016-2019. All rights reserved.
 * Description: network device event monitor
 * Author: xuchunmei
 * Create: 2016-1-1
 */
#include "monitor_netdev.h"

#include <net/addrconf.h>
#include <net/ip_fib.h>
#include <net/ip6_fib.h>
#include <linux/inetdevice.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/notifier.h>
#include <linux/ratelimit.h>
#include "sysmonitor_main.h"

#define LOOKUP_REG_NETDEV_FUNC_BIT 0x00000001
#define REG_NETDEV_NOTIFIER_BIT 0x00000002
#define REG_INETADDR_NOTIFIER_BIT 0x00000004
#define REG_INET6ADDR_NOTIFIER_BIT 0x00000008
#define REG_FIB_TBL_NOTIFIER_BIT 0x00000010
#define ALL_FUNC_AVAILABLE_MASK         \
	(REG_NETDEV_NOTIFIER_BIT |      \
	REG_INETADDR_NOTIFIER_BIT |     \
	REG_INET6ADDR_NOTIFIER_BIT |    \
	REG_FIB_TBL_NOTIFIER_BIT)
static unsigned int g_func_available_bit_mask;
static int g_is_exiting;

/* Not more than 5 messages every 1s */
static DEFINE_RATELIMIT_STATE(monitor_netdev_ratelimit, (1 * HZ), (5));

static int save_msg_process_info(struct netmonitor_info *msg)
{
	msg->pid = current->pid;
	msg->parent_pid = current->real_parent->pid;
	(void)memcpy(msg->comm, current->comm, TASK_COMM_LEN);
	(void)memcpy(msg->parent_comm, current->real_parent->comm, TASK_COMM_LEN);

	return 0;
}

static void print_netdev_status(const char *name, unsigned long event)
{
	struct netmonitor_info msg;
	int ret;

	if (unlikely(g_is_exiting != 0)) {
		return;
	}

	(void)memset(&msg, 0, sizeof(struct netmonitor_info));

	if (event == NETDEV_PRE_UP) {
		msg.event = UP;
	} else if (event == NETDEV_GOING_DOWN) {
		msg.event = DOWN;
	} else {
		return;
	}

	ret = save_msg_process_info(&msg);
	if (ret != 0) {
		return;
	}

	(void)memcpy(msg.dev, name, IFNAMSIZ);

	(void)save_msg(NETWORK, &msg, sizeof(struct netmonitor_info));
}

static void print_address_status(const struct in_ifaddr *in_dev, unsigned long event)
{
	struct netmonitor_info msg;
	int ret;

	(void)memset(&msg, 0, sizeof(struct netmonitor_info));

	if (event == NETDEV_UP) {
		msg.event = NEWADDR;
	} else if (event == NETDEV_DOWN) {
		msg.event = DELADDR;
	} else {
		return;
	}

	ret = save_msg_process_info(&msg);
	if (ret != 0) {
		return;
	}

	msg.addr.in.s_addr = in_dev->ifa_address;
	msg.plen = in_dev->ifa_prefixlen;
	(void)memcpy(msg.dev, in_dev->ifa_label, IFNAMSIZ);
	(void)save_msg(NETWORK, &msg, sizeof(struct netmonitor_info));
}

static int monitor_netdevice_event(struct notifier_block *unused, unsigned long event, void *ptr)
{
	struct netdev_notifier_info *info = (struct netdev_notifier_info *)ptr;

	if (info != NULL && info->dev != NULL) {
		print_netdev_status(info->dev->name, event);
	}

	return NOTIFY_DONE;
}

static void print_address6_status(const struct inet6_ifaddr *if6, unsigned long event)
{
	struct netmonitor_info msg;
	struct net_device *dev = (struct net_device *)if6->idev->dev;
	int ret;

	(void)memset(&msg, 0, sizeof(struct netmonitor_info));

	if (event == NETDEV_UP) {
		msg.event = NEWADDR6;
	} else if (event == NETDEV_DOWN) {
		msg.event = DELADDR6;
	} else {
		return;
	}

	ret = save_msg_process_info(&msg);
	if (ret != 0) {
		return;
	}

	msg.addr.in6 = if6->addr;
	msg.plen = (int)if6->prefix_len;
	(void)memcpy(msg.dev, dev->name, IFNAMSIZ);
	(void)save_msg(NETWORK, &msg, sizeof(struct netmonitor_info));
}

static int monitor_address_notifier(struct notifier_block *this, unsigned long event, void *ifa)
{
	struct in_ifaddr *in_dev = (struct in_ifaddr *)ifa;

	if (in_dev != NULL) {
		print_address_status(in_dev, event);
	}

	return NOTIFY_DONE;
}

static int monitor_address6_notifier(struct notifier_block *this, unsigned long event, void *ptr)
{
	struct inet6_ifaddr *if6 = (struct inet6_ifaddr *)ptr;
	if (if6 != NULL)
		print_address6_status(if6, event);

	return NOTIFY_DONE;
}

static struct notifier_block g_test_inet_notifier = {
	.notifier_call = monitor_address_notifier,
};

static struct notifier_block g_test_inet6_notifier = {
	.notifier_call = monitor_address6_notifier,
};

static struct notifier_block g_test_dev_notifier = {
	.notifier_call = monitor_netdevice_event,
};

static void print_fib4_table_status(const struct fib_entry_notifier_info *fib_entry_info, unsigned long event)
{
	struct netmonitor_info msg;
	int ret;

	if (fib_entry_info == NULL) {
		printk("[monitor_netdev]print_fib4_table_status: fib4_entry_info is null\n");
		return;
	}

	if (monitor_netdev_ratelimit.burst != get_netratelimit_burst())
		monitor_netdev_ratelimit.burst = get_netratelimit_burst();

	if (!__ratelimit(&monitor_netdev_ratelimit))
		return;

	(void)memset(&msg, 0, sizeof(struct netmonitor_info));
	if (event == FIB_EVENT_ENTRY_DEL) {
		msg.event = FIB_DEL;
	} else if (event == FIB_EVENT_ENTRY_ADD) {
		msg.event = FIB_ADD;
	} else if (event == FIB_EVENT_ENTRY_REPLACE) {
		msg.event = FIB_REPLACE;
	} else if (event == FIB_EVENT_ENTRY_APPEND) {
		msg.event = FIB_APPEND;
	} else {
		return;
	}

	ret = save_msg_process_info(&msg);
	if (ret != 0) {
		return;
	}

	msg.tb_id = (int)fib_entry_info->tb_id;
	msg.plen = fib_entry_info->dst_len;
	msg.addr.in.s_addr = htonl(fib_entry_info->dst);
	(void)save_msg(NETWORK, &msg, sizeof(struct netmonitor_info));
}

static void print_fib6_table_status(const struct fib6_entry_notifier_info *fib6_entry_info, unsigned long event)
{
	struct netmonitor_info msg;
	int ret;

	if (fib6_entry_info == NULL) {
		printk("[monitor_netdev]print_fib6_table_status: fib6_entry_info is null\n");
		return;
	}
	if (fib6_entry_info->rt == NULL) {
		printk("[monitor_netdev]print_fib6_table_status: fib6_entry_info->rt is null\n");
		return;
	}

	if (monitor_netdev_ratelimit.burst != get_netratelimit_burst())
		monitor_netdev_ratelimit.burst = get_netratelimit_burst();

	if (!__ratelimit(&monitor_netdev_ratelimit))
		return;

	(void)memset(&msg, 0, sizeof(struct netmonitor_info));

	if (event == FIB_EVENT_ENTRY_DEL) {
		msg.event = FIB6_DEL;
	} else if (event == FIB_EVENT_ENTRY_ADD) {
		msg.event = FIB6_ADD;
	} else if (event == FIB_EVENT_ENTRY_REPLACE) {
		msg.event = FIB6_REPLACE;
	} else if (event == FIB_EVENT_ENTRY_APPEND) {
		msg.event = FIB6_APPEND;
	} else {
		return;
	}

	ret = save_msg_process_info(&msg);
	if (ret != 0) {
		return;
	}

	msg.plen = fib6_entry_info->rt->fib6_dst.plen;

	msg.addr.in6 = fib6_entry_info->rt->fib6_dst.addr;
	(void)save_msg(NETWORK, &msg, sizeof(struct netmonitor_info));
}

static void print_fib_table_status(const struct fib_notifier_info *fib_info, unsigned long event)
{
	if (fib_info == NULL) {
		printk("[monitor_netdev]print_fib_table_status: fib_info is null\n");
		return;
	}

	if (fib_info->family == AF_INET) {
		struct fib_entry_notifier_info *fib_entry_info =
			container_of(fib_info, struct fib_entry_notifier_info, info);

		print_fib4_table_status(fib_entry_info, event);
	} else if (fib_info->family == AF_INET6) {
		struct fib6_entry_notifier_info *fib6_entry_info =
			container_of(fib_info, struct fib6_entry_notifier_info, info);

		print_fib6_table_status(fib6_entry_info, event);
	}
}

static int monitor_fib_table_event(struct notifier_block *unused, unsigned long event, void *ptr)
{
	struct fib_notifier_info *fib_info = (struct fib_notifier_info *)ptr;

	if (!(event == FIB_EVENT_ENTRY_REPLACE || event == FIB_EVENT_ENTRY_APPEND ||
		event == FIB_EVENT_ENTRY_ADD || event == FIB_EVENT_ENTRY_DEL))
		return NOTIFY_DONE;

	if (fib_info != NULL)
		print_fib_table_status(fib_info, event);

	return NOTIFY_DONE;
}

static struct notifier_block g_fib_table_notifier = {
	.notifier_call = monitor_fib_table_event,
};

void monitor_netdev_init(void)
{
	int err;

	g_func_available_bit_mask = 0;

	/* init net device status monitor */
	g_func_available_bit_mask |= LOOKUP_REG_NETDEV_FUNC_BIT;
	err = register_netdevice_notifier(&g_test_dev_notifier);
	if (err < 0) {
		printk(KERN_ERR "[monitor_netdev] register_netdevice_notifier fail\n");
	} else {
		g_func_available_bit_mask |= REG_NETDEV_NOTIFIER_BIT;
	}

	/* init net device ip monitor */
	err = register_inetaddr_notifier(&g_test_inet_notifier);
	if (err < 0) {
		printk(KERN_ERR "[monitor_netdev] register_inetaddr_notifier fail\n");
	} else {
		g_func_available_bit_mask |= REG_INETADDR_NOTIFIER_BIT;
	}

	err = register_inet6addr_notifier(&g_test_inet6_notifier);
	if (err < 0) {
		printk(KERN_ERR "[monitor_netdev] register_inetaddr_notifier fail\n");
	} else {
		g_func_available_bit_mask |= REG_INET6ADDR_NOTIFIER_BIT;
	}

	/* init fib table monitor */
	err = register_fib_notifier(&init_net, &g_fib_table_notifier, NULL, NULL);
	if (err < 0) {
		printk(KERN_ERR "[monitor_netdev] register_fib_notifier fail\n");
	} else {
		g_func_available_bit_mask |= REG_FIB_TBL_NOTIFIER_BIT;
	}

	if (!(g_func_available_bit_mask & ALL_FUNC_AVAILABLE_MASK)) {
		printk("[monitor_netdev] all functions are unavailable(0x%x), has to exit.\n",
			g_func_available_bit_mask);
		return;
	}

	printk("[monitor_netdev] initial finished. function available: 0x%x\n",
		g_func_available_bit_mask);
}

void monitor_netdev_exit(void)
{
	g_is_exiting = 1;

	if (g_func_available_bit_mask & REG_NETDEV_NOTIFIER_BIT) {
		unregister_netdevice_notifier(&g_test_dev_notifier);
	}

	if (g_func_available_bit_mask & REG_INETADDR_NOTIFIER_BIT) {
		unregister_inetaddr_notifier(&g_test_inet_notifier);
	}

	if (g_func_available_bit_mask & REG_INET6ADDR_NOTIFIER_BIT) {
		unregister_inet6addr_notifier(&g_test_inet6_notifier);
	}

	if (g_func_available_bit_mask & REG_FIB_TBL_NOTIFIER_BIT) {
		unregister_fib_notifier(&init_net, &g_fib_table_notifier);
	}

	printk("[monitor_netdev] exit\n");
}
