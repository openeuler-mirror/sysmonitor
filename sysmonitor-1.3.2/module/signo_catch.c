/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2016-2019. All rights reserved.
 * Description: signal catch module
 * Author: xuchunmei
 * Create: 2016-1-1
 */
#include "signo_catch.h"

#include <net/sock.h>
#include <asm/siginfo.h>
#include <linux/file.h>
#include <linux/netlink.h>
#include <linux/notifier.h>
#include <linux/proc_fs.h>
#include <linux/kprobes.h>

#include "sysmonitor_main.h"

#define SIGNAL_COUNT 31

/* qemu kill -9 process, for libvirt use, do not change !!!! */
#define QEMU_SIG
#ifdef QEMU_SIG
static DECLARE_WAIT_QUEUE_HEAD(g_qemu_wait);
static ulong g_qemu_log_seq; /* index for logged buffer */
static ulong g_qemu_buf_seq; /* index for reader */
#define SIG_BUFSIZE 256
#define SIG_BUFMASK (SIG_BUFSIZE - 1)
static qemu_signo_msg g_qemu_buf[SIG_BUFSIZE];
struct proc_dir_entry *g_proc_qemu;

static struct kprobe kp = {
	.symbol_name = "do_send_sig_info"
};

static ssize_t qemu_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	int error, index;

	if (buf == NULL || count < sizeof(qemu_signo_msg)) {
		return -EINVAL;
	}

	/* ring buf size is SIG_BUFSIZE, so we can't read more than that */
	if ((g_qemu_buf_seq - g_qemu_log_seq) >= SIG_BUFSIZE) {
		g_qemu_log_seq = g_qemu_buf_seq - SIG_BUFSIZE + 1;
	}

	/* it will return immediately if secend arg is not 0 */
	error = wait_event_interruptible(g_qemu_wait, g_qemu_buf_seq != g_qemu_log_seq);
	if (error != 0) {
		return error;
	}

	index = g_qemu_log_seq & SIG_BUFMASK;
	g_qemu_log_seq++;

	error = copy_to_user(buf, g_qemu_buf + index, sizeof(qemu_signo_msg));
	if (error != 0) {
		return -EFAULT;
	}
	return sizeof(qemu_signo_msg);
}

static unsigned int qemu_poll(struct file *file, poll_table *wait)
{
	poll_wait(file, &g_qemu_wait, wait);
	if (g_qemu_buf_seq != g_qemu_log_seq) {
		return POLLIN | POLLRDNORM;
	}

	return 0;
}

static int qemu_open(struct inode *inode, struct file *file)
{
	if (!try_module_get(THIS_MODULE)) {
		return -ENOENT;
	}

	return 0;
}

static int qemu_release(struct inode *inode, struct file *file)
{
	module_put(THIS_MODULE);
	return 0;
}

static const struct proc_ops g_proc_qemu_operations = {
	.proc_read = qemu_read,
	.proc_poll = qemu_poll,
	.proc_open = qemu_open,
	.proc_release = qemu_release,
	.proc_lseek = generic_file_llseek,
};
#endif

/* Here introduce euler_get_mm_exe_file and euler_get_task_exe_file
 * to solve the build and insmod error.
 */
static struct file *euler_get_mm_exe_file(const struct mm_struct *mm)
{
	struct file *exe_file = NULL;

	rcu_read_lock();
	exe_file = rcu_dereference(mm->exe_file);
	if (exe_file && !get_file_rcu(exe_file)) {
		exe_file = NULL;
	}
	rcu_read_unlock();
	return exe_file;
}

static struct file *euler_get_task_exe_file(struct task_struct *task)
{
	struct file *exe_file = NULL;
	struct mm_struct *mm = NULL;

	/* in oom_killer_process, task lock will be hold before send signal */
	if (spin_is_locked(&task->alloc_lock)) {
		return NULL;
	}

	task_lock(task);
	mm = task->mm;
	if (mm != NULL) {
		if (!(task->flags & PF_KTHREAD)) {
			exe_file = euler_get_mm_exe_file(mm);
		}
	}
	task_unlock(task);
	return exe_file;
}

static int save_exe_info(char *exe, int exe_size, struct task_struct *task)
{
	struct file *exe_file = NULL;
	void *ret;

	exe_file = euler_get_task_exe_file(task);
	if (exe_file != NULL) {
		ret = memcpy(exe,
			exe_file->f_path.dentry->d_name.name,
			exe_file->f_path.dentry->d_name.len);
		if (ret == NULL) {
			fput(exe_file);
			return -1;
		}
		fput(exe_file);
	}
	return 0;
}

static int save_msg_info(ce_signo_msg *msg, const send_sig_info_data_t *notifier_call_data)
{
	int ret, i;
	struct task_struct *ptask = NULL;

	(void)memset(msg, 0, sizeof(ce_signo_msg));

	msg->send_pid = current->pid;
	(void)memcpy(msg->send_comm, current->comm, TASK_COMM_LEN);

	msg->send_parent_pid = current->parent->pid;
	(void)memcpy(msg->send_parent_comm, current->parent->comm, TASK_COMM_LEN);

	rcu_read_lock();
	ptask = rcu_dereference(current->parent);
	for (i = 0; i < CALL_CHAIN_NUM; i++) {
		if ((ptask->pid == 0) || (ptask->pid == 1))
			break;

		ptask = rcu_dereference(ptask->real_parent);
		msg->send_chain_pid[i] = task_pid_nr(ptask);
		(void)memcpy(msg->send_chain_comm[i], ptask->comm, TASK_COMM_LEN);
	}
	rcu_read_unlock();

	msg->recv_pid = notifier_call_data->p->pid;
	(void)memcpy(msg->recv_comm, notifier_call_data->p->comm, TASK_COMM_LEN);

	msg->signo = notifier_call_data->sig;
	ret = save_exe_info(msg->send_exe, NAME_MAX, current);
	if (ret != 0) {
		pr_err("[signo]: memcpy msg->send_exe failed, ret: %d\n", ret);
		return -1;
	}

	ret = save_exe_info(msg->send_parent_exe, NAME_MAX, current->parent);
	if (ret != 0) {
		pr_err("[signo]: memcpy msg->send_parent_exe failed, ret: %d\n", ret);
		return -1;
	}

	ret = save_exe_info(msg->recv_exe, NAME_MAX, notifier_call_data->p);
	if (ret != 0) {
		pr_err("[signo]: memcpy msg->recv_exe failed, ret: %d\n", ret);
		return -1;
	}

	return 0;
}

static int save_qemu_msg_info(qemu_signo_msg *qemu_msg, const send_sig_info_data_t *notifier_call_data)
{
	(void)memset(qemu_msg, 0, sizeof(qemu_signo_msg));
	qemu_msg->send_pid = current->pid;
	(void)memcpy(qemu_msg->send_comm, current->comm, TASK_COMM_LEN);
	qemu_msg->send_parent_pid = current->parent->pid;
	(void)memcpy(qemu_msg->send_parent_comm, current->parent->comm, TASK_COMM_LEN);
	qemu_msg->recv_pid = notifier_call_data->p->pid;
	(void)memcpy(qemu_msg->recv_comm, notifier_call_data->p->comm, TASK_COMM_LEN);
	qemu_msg->signo = notifier_call_data->sig;
	return 0;
}

static int do_store_sig_info(send_sig_info_data_t *data)
{
	ce_signo_msg msg;
	ulong index;
	qemu_signo_msg *qemu_msg = NULL;
	unsigned long sigcatchmask = get_sigcatchmask();
	int ret;

	if ((data->sig <= SIGNAL_COUNT) &&
		(sigcatchmask & (1ul << (unsigned int)(data->sig - 1)))) {
		ret = save_msg_info(&msg, data);
		if (ret != 0) {
			goto out;
		}

		(void)save_msg(SIGNAL, &msg, sizeof(ce_signo_msg));
	}

#ifdef QEMU_SIG
	if ((data->sig == SIGKILL) &&
		!strcmp(data->p->comm, "qemu-kvm")) {
		index = g_qemu_buf_seq & SIG_BUFMASK;
		qemu_msg = g_qemu_buf + index;

		ret = save_qemu_msg_info(qemu_msg, data);
		if (ret) {
			goto out;
		}

		g_qemu_buf_seq++;

		if (waitqueue_active(&g_qemu_wait)) {
			wake_up_interruptible(&g_qemu_wait);
		}
	}
#endif
out:
	return 0;
}

static int pre_handler(struct kprobe *p, struct pt_regs *regs) 
{
#ifdef CONFIG_ARM64
	send_sig_info_data_t data;
	data.sig = regs->regs[0];
	data.info = (struct kernel_siginfo *)((unsigned long *)regs->regs[1]);
	data.p = (struct task_struct *)((unsigned long *)regs->regs[2]);
	do_store_sig_info(&data);
#endif

#ifdef CONFIG_X86_64
	send_sig_info_data_t data;
	data.sig = regs->di;
	data.info = (struct kernel_siginfo *)((unsigned long *)regs->si);
	data.p = (struct task_struct *)((unsigned long *)regs->dx);
	do_store_sig_info(&data);
#endif

#if defined(CONFIG_RISCV) && defined(CONFIG_64BIT)
	send_sig_info_data_t data;
	data.sig = regs->a0;
	data.info = (struct kernel_siginfo *)((unsigned long *)regs->a1);
	data.p = (struct task_struct *)((unsigned long *)regs->a2);
	do_store_sig_info(&data);
#endif
	return 0;
}


void signo_catch_init(void)
{
#ifdef QEMU_SIG
	g_proc_qemu = proc_create("sig_catch", 0400, NULL, &g_proc_qemu_operations);
	if (g_proc_qemu == NULL) {
		printk(KERN_ERR "signo_catch: create /proc/sig_catch failed.\n");
	}
#endif
	kp.pre_handler = pre_handler;
	register_kprobe(&kp);

	printk(KERN_INFO "signo_catch: register signal kprobe\n");
}

void signo_catch_exit(void)
{
	unregister_kprobe(&kp);
#ifdef QEMU_SIG
	if (g_proc_qemu != NULL) {
		proc_remove(g_proc_qemu);
	}
#endif
	printk(KERN_INFO "signo_catch: unregister signal kprobe\n");
}

