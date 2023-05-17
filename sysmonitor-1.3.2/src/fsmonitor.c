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
 * Description: ext3/ext4 file system monitor
 * Author: xuchunmei
 * Create: 2016-1-1
 */
#include "fsmonitor.h"

#include <limits.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <linux/fs.h>
#include <linux/netlink.h>

#include <securec.h>
#include "common.h"
#include "monitor_thread.h"

static struct nlmsghdr *g_nlh;
static int g_sockfd = -1;

static void resume_ext_alarm(void)
{
    int ret, i, j, start;
    char out[PATH_MAX] = {0};
    char dev[PATH_MAX] = {0};
    char devpath[FILE_SYSTEM_LENTH] = {0};
    const int timeout = 3;

    ret = monitor_popen("cat /proc/mounts | grep -E -w 'ext3|ext4' |awk '{print $1}'",
                        out, sizeof(out), timeout, NULL);
    if (ret < 0) {
        log_printf(LOG_ERR, "get system mounts failed");
        return;
    }

    start = 0;
    out[PATH_MAX - 1] = 0;

    /* search for dev name and report resume */
    for (i = 0; out[i] != 0; i++) {
        if (out[i] != '\n') {
            continue;
        }

        if (i == 0) {
            log_printf(LOG_INFO, "no ext disk found");
            break;
        }

        /* so here is the end of line, get this line for one dev */
        j = i - start;
        if (j >= FILE_SYSTEM_LENTH) {
            log_printf(LOG_ERR, "dev name too long ,something error");
            return;
        } else if (j <= 0) {
            continue;
        }

        ret = memcpy_s(devpath, FILE_SYSTEM_LENTH, out + start, (unsigned int)j);
        if (ret != 0) {
            log_printf(LOG_ERR, "resume ext alarm memcpy_s error [%d]", ret);
        }
        devpath[j] = 0;
        start = i + 1;

        /* chang /dev/mapper/xxx to /dev/dm-xx for real path */
        ret = memset_s(dev, sizeof(dev), 0, sizeof(dev));
        if (ret != 0) {
            log_printf(LOG_ERR, "resume ext alarm memset_s error [%d]", ret);
        }
        if (realpath(devpath, dev) == NULL) {
            log_printf(LOG_ERR, "get real path for %s failed", devpath);
            continue;
        }

        /*
         * we get the dev name, record resume log ,
         * dev name is /dev/dm-x or /dev/sdx, simply cut first 5 char for name only
         */
        log_printf(LOG_INFO, "%s ext-fs resume.", dev + FIRST_FIVE_DEV_CHAR);
    }

    return;
}

static void resume_alarm(void)
{
    char out[MAX_TEMPSTR] = {0};
    int ret;
    const unsigned int sleep_time = 10;
    const int timeout = 3;

    ret = monitor_popen("systemctl is-system-running", out, sizeof(out), timeout, NULL);
    if (ret < 0) {
        log_printf(LOG_ERR, "get system status error");
        return;
    }
    /* do not resume alarm if system is already started */
    if (strstr(out, "running") || strstr(out, "degraded")) {
        log_printf(LOG_INFO, "do not resume alarm if system is already started");
        return;
    }
    (void)sleep(sleep_time);
    resume_ext_alarm();

    return;
}

static void clean_res(void)
{
    if (g_nlh != NULL) {
        free(g_nlh);
        g_nlh = NULL;
    }
    if (g_sockfd >= 0) {
        (void)close(g_sockfd);
        g_sockfd = -1;
    }
}

static int set_sockfd(void)
{
    int ret;
    struct sockaddr_nl local;

    g_sockfd = socket(PF_NETLINK, (int)SOCK_RAW | SOCK_CLOEXEC, NETLINK_FILESYSTEM);
    if (g_sockfd < 0) {
        if (errno == EPROTONOSUPPORT) {
            set_thread_item_tid(FS_ITEM, 0);
            log_printf(LOG_INFO, "the kernel do not support filesystem monitor");
        } else {
            log_printf(LOG_INFO, "create NETLINK_FILESYSTEM socket failed [%d]", errno);
        }
        goto err;
    }

    ret = memset_s(&local, sizeof(local), 0, sizeof(local));
    if (ret != 0) {
        log_printf(LOG_ERR, "fs_monitor_ext3_4: memset_s local failed, ret: %d", ret);
        goto err;
    }

    local.nl_family = PF_NETLINK;
    local.nl_pid = (unsigned int)getpid();
    local.nl_groups = FS_ERROR_GRP_EXT3;

    if (bind(g_sockfd, (struct sockaddr *)&local, sizeof(local))) {
        log_printf(LOG_ERR, "bind NETLINK_FILESYSTEM socket failed [%d]", errno);
        goto err;
    }

    return 0;

err:
    if (g_sockfd >= 0) {
        (void)close(g_sockfd);
        g_sockfd = -1;
    }
    return -1;
}

static int alloc_for_nlmsghdr(void)
{
    int ret;

    g_nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(sizeof(struct ext4_err_msg)));
    if (g_nlh == NULL) {
        log_printf(LOG_ERR, "NETLINK_FILESYSTEM: can not allocate err_msg!");
        return -1;
    }

    ret = memset_s(g_nlh, NLMSG_SPACE(sizeof(struct ext4_err_msg)), 0, NLMSG_SPACE(sizeof(struct ext4_err_msg)));
    if (ret != 0) {
        log_printf(LOG_ERR, "fs_monitor_ext3_4: memset_s nlh failed, ret: %d", ret);
        free(g_nlh);
        g_nlh = NULL;
        return -1;
    }

    g_nlh->nlmsg_len = (unsigned int)NLMSG_SPACE(sizeof(struct ext4_err_msg));
    g_nlh->nlmsg_pid = pthread_self() << THREAD_PID_OFFSET | (unsigned int)getpid();
    g_nlh->nlmsg_flags = 0;

    return 0;
}

static int handle_fs_monitor_msg(void)
{
    struct msghdr msg;
    struct iovec iov;
    int ret;
    ssize_t recv_ret;
    struct ext4_err_msg *err_msg = NULL;

    ret = memset_s(&iov, sizeof(iov), 0, sizeof(iov));
    if (ret != 0) {
        log_printf(LOG_ERR, "fs_monitor_ext3_4: memset_s iov failed, ret: %d", ret);
        return -1;
    }

    iov.iov_base = (void *)g_nlh;
    iov.iov_len = g_nlh->nlmsg_len;

    ret = memset_s(&msg, sizeof(msg), 0, sizeof(msg));
    if (ret != 0) {
        log_printf(LOG_ERR, "fs_monitor_ext3_4: memset_s msg failed, ret: %d", ret);
        return -1;
    }

    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    for (;;) {
        recv_ret = recvmsg(g_sockfd, &msg, 0);
        if (recv_ret < 0) {
            if (errno != EINTR) {
                log_printf(LOG_ERR, "recvmsg from NETLINK_FILESYSTEM socket failed [%d]", errno);
                return -1;
            }
            continue;
        }

        err_msg = (struct ext4_err_msg *)NLMSG_DATA(g_nlh);
        if (err_msg != NULL && (err_msg->magic == EXT3_ERROR_MAGIC || err_msg->magic == EXT4_ERROR_MAGIC)) {
            if (err_msg->s_flags & MS_RDONLY) {
                log_printf(LOG_INFO, "%s filesystem error. Remount filesystem read-only.", err_msg->s_id);
            } else {
                log_printf(LOG_ERR, "fs_monitor_ext3_4: %s filesystem error. flag is %lu.", err_msg->s_id, err_msg->s_flags);
            }
        }
    }
    return 0;
}

static void fs_monitor_ext3_4(void)
{
    int ret;

    /* prctl does not return false if arg2 is right when arg1 is PR_SET_NAME */
    (void)prctl(PR_SET_NAME, "monitor-fs");
    log_printf(LOG_INFO, "filesystem monitor starting up");

    ret = set_sockfd();
    if (ret != 0) {
        goto err;
    }

    ret = alloc_for_nlmsghdr();
    if (ret) {
        goto err;
    }

    ret = handle_fs_monitor_msg();
    if (ret != 0) {
        goto err;
    }

err:
    clean_res();
}

static void *fs_monitor_start(void *arg)
{
    int ret;

    ret = set_thread_check_value(THREAD_FS_ITEM, true, FILE_SYSTEM_PERIOD);
    if (ret == -1) {
        log_printf(LOG_ERR, "file system monitor set check flag or period error");
        return NULL;
    }
    resume_alarm();
    ret = feed_thread_status_count(THREAD_FS_ITEM);
    if (ret == -1) {
        log_printf(LOG_ERR, "file system monitor feed error");
        return NULL;
    }
    fs_monitor_ext3_4();
    return NULL;
}

void fs_monitor_init(void)
{
    pthread_t tid;

    if (pthread_create(&tid, NULL, fs_monitor_start, NULL)) {
        log_printf(LOG_ERR, "create file system monitor thread error [%d]", errno);
        return;
    }
    set_thread_item_tid(FS_ITEM, tid);
}
