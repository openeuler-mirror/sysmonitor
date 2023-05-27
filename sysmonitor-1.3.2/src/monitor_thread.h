/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * sysmonitor licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Description: monitors the running status of each subthread.
 * Author: zhangguangzhi
 * Create: 2020-9-17
 */


#ifndef MONITOR_THREAD_H
#define MONITOR_THREAD_H

#include "common.h"

#include <stdbool.h>

#define RESTART_MONITOR "systemctl restart sysmonitor &> /dev/null"
#define THREAD_SYSALARM_HRAET_PERIOD 5
#define POLL_TIME 1000
#define CISTOM_PERIODIC_TIME 4
#define CHECK_THREAD_FAILURE_NUM 3    /* default check failure num is 3, range is 2-10 */
#define CHECK_THREAD_FAILURE_NUM_MAX 10
#define CHECK_THREAD_FAILURE_NUM_MIN 2

typedef enum monitor_thread_item_type {
    THREAD_PS_ITEM,
    THREAD_FS_ITEM,             /* check only once when start thread */
    THREAD_FILE_ITEM,           /* no need to check */
    THREAD_DISK_ITEM,
    THREAD_INODE_ITEM,
    THREAD_CUSTOM_DAEMON_ITEM,
    THREAD_CUSTOM_PERIODIC_ITEM,
    THREAD_IO_DELAY_ITEM,
    THREAD_SYSTEM_ITEM,
    THREAD_SYS_EVENT_ITEM,      /* no need to check */
    THREAD_ZOMBIE_ITEM,
    THREAD_PS_PARALLEL_ITEM,    /* add new item for check ps parallel thread status */
    THREAD_HEART_ITEM,          /* add new item for check heart thread status */
    THREAD_MONITOR_ITEMS_CNT
} monitor_thread_item;

typedef struct thread_status_s {
    unsigned int count;    /* thread feed dog count */
    unsigned int period;            /* thread run period */
    unsigned int check_num;        /* check thread count value, value increases by 1 every 2s */
    unsigned int check_failure_num;        /* check thread count value, value increases by 1 every 2s */
    bool check_flag;          /* check flag, need to check item or not */
} thread_status;

typedef struct thread_ps_parallel_status_s {
    thread_status status;
    pthread_t thread_id;    /* check for ps parallel status */
    struct list_head list;
} thread_ps_parallel_status;

int thread_status_struct_init(void);
int check_thread_status(void);
int feed_thread_status_count(monitor_thread_item item);
int set_thread_status_period(monitor_thread_item item, unsigned int period);
int set_thread_status_check_flag(monitor_thread_item item, bool flag);
int set_thread_check_value(monitor_thread_item item, bool flag, unsigned int period);
void clear_thread_status(monitor_thread_item item);
void clear_all_thread_status(void);
int set_ps_parallel_check_flag(monitor_thread_item item, bool flag, pthread_t id);
int feed_thread_ps_parallel_count(monitor_thread_item item, pthread_t id);
int set_thread_ps_parallel_period(monitor_thread_item item, pthread_t id, unsigned int period);
int set_ps_parallel_check_value(monitor_thread_item item, bool flag, pthread_t id, unsigned int period);
bool check_thread_monitor(const char *item, const char *value);
bool check_thread_failure_num(const char *item, const char *value);
void init_ps_parallel_head(void);

#endif