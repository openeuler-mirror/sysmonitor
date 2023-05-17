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


#include "monitor_thread.h"

#include <securec.h>

static thread_status g_thread_status[THREAD_MONITOR_ITEMS_CNT];
static struct list_head g_thread_ps_parallel_head;
static bool g_check_thread_monitor = true;
static unsigned int g_max_failure_num = CHECK_THREAD_FAILURE_NUM;
static pthread_mutex_t g_parallel_mtx = PTHREAD_MUTEX_INITIALIZER;

void init_ps_parallel_head(void)
{
    init_list_head(&g_thread_ps_parallel_head);
}

bool check_thread_monitor(const char *item, const char *value)
{
    if (strcmp(value, "on") == 0) {
        g_check_thread_monitor = true;
    } else if (strcmp(value, "off") == 0) {
        g_check_thread_monitor = false;
    } else {
        log_printf(LOG_ERR, "item:[%s] set value error", item);
        return false;
    }
    return true;
}

bool check_thread_failure_num(const char *item, const char *value)
{
    g_max_failure_num = (unsigned int)strtol(value, NULL, STRTOL_NUMBER_BASE);
    if (check_int(value) == false || g_max_failure_num < CHECK_THREAD_FAILURE_NUM_MIN ||
        g_max_failure_num > CHECK_THREAD_FAILURE_NUM_MAX) {
        log_printf(LOG_ERR, "item:[%s] set check_thread_failure_num error", item);
        return false;
    }
    return true;
}


int thread_status_struct_init(void)
{
    int ret;

    if (!g_check_thread_monitor) {
        return 0;
    }

    ret = memset_s(g_thread_status, sizeof(thread_status) * THREAD_MONITOR_ITEMS_CNT, 0,
        sizeof(thread_status) * THREAD_MONITOR_ITEMS_CNT);
    if (ret != 0) {
        log_printf(LOG_ERR, "thread status init memset_s error, ret:%d", ret);
        return -1;
    }
    init_ps_parallel_head();
    return 0;
}

/* if monitor is off, need to clear count, check_num and check_failure_num
 * for next check
 */
void clear_thread_status(monitor_thread_item item)
{
    if (!g_check_thread_monitor) {
        return;
    }

    if (item >= THREAD_MONITOR_ITEMS_CNT) {
        log_printf(LOG_ERR, "clear thread status error, item:%d", item);
        return;
    }

    g_thread_status[item].count = 0;
    g_thread_status[item].check_num = 0;
    g_thread_status[item].check_failure_num = 0;
    return;
}

void clear_all_thread_status(void)
{
    monitor_thread_item item;
    if (!g_check_thread_monitor) {
        return;
    }

    for (item = 0; item < THREAD_MONITOR_ITEMS_CNT; item++) {
        g_thread_status[item].check_num = 0;
        g_thread_status[item].check_failure_num = 0;
        /* file system only feed once, don't clear it's count */
        if (item != THREAD_FS_ITEM) {
            g_thread_status[item].count = 0;
        }
    }
    return;
}

/*
 * feed thread status, item's count + 1,
 * return: -1:error; 0: feed success or no need to feed
 */
int feed_thread_status_count(monitor_thread_item item)
{
    if (!g_check_thread_monitor) {
        return 0;
    }

    if (item >= THREAD_MONITOR_ITEMS_CNT) {
        log_printf(LOG_ERR, "feed thread status count error, item:%d", item);
        return -1;
    }

    if (!g_thread_status[item].check_flag) {
        return 0;
    }
    g_thread_status[item].count += 1;
    return 0;
}

/* clear the thread status when the check_flag changes. */
static void check_flag_and_clear(monitor_thread_item item, bool new_flag)
{
    /* if check_flag change form true to false, need to clear */
    if (!new_flag && g_thread_status[item].check_flag) {
        clear_thread_status(item);
    }
}

int set_thread_status_check_flag(monitor_thread_item item, bool flag)
{
    if (!g_check_thread_monitor) {
        return 0;
    }

    if (item >= THREAD_MONITOR_ITEMS_CNT) {
        log_printf(LOG_ERR, "set thread status check flag error, item:%d", item);
        return -1;
    }

    /* clear the thread status when check_flag change */
    check_flag_and_clear(item, flag);
    g_thread_status[item].check_flag = flag;
    return 0;
}

int set_thread_status_period(monitor_thread_item item, unsigned int period)
{
    if (!g_check_thread_monitor) {
        return 0;
    }

    if (item >= THREAD_MONITOR_ITEMS_CNT) {
        log_printf(LOG_ERR, "set thread status period error, item:%d", item);
        return -1;
    }
    g_thread_status[item].period = period;
    return 0;
}

int set_thread_check_value(monitor_thread_item item, bool flag, unsigned int period)
{
    int ret;

    if (!g_check_thread_monitor) {
        return 0;
    }

    ret = set_thread_status_check_flag(item, flag);
    if (ret == -1) {
        return -1;
    }

    ret = set_thread_status_period(item, period);
    if (ret == -1) {
        return -1;
    }
    return 0;
}

/*
 * check thread item count and failure time
 * return 0:success, -1: error,need to restart sysmonitor
 */
static int check_thread_is_normal(monitor_thread_item item)
{
    unsigned int count;

    count = g_thread_status[item].count;
    if (count == 0) {
        /* failed to feed dog */
        g_thread_status[item].check_failure_num += 1;
        g_thread_status[item].check_num += 1;
    } else {
        /* success to feed dog, clear the status for next check */
        clear_thread_status(item);
        return 0;
    }

    if (g_thread_status[item].check_failure_num >= g_max_failure_num) {
        log_printf(LOG_ERR, "need to restart sysmonitor, item:[%d] failure:[%u], count:[%u], max failure num:[%u]",
            item, g_thread_status[item].check_failure_num, g_thread_status[item].count, g_max_failure_num);
        return -1;
    }

    return 0;
}

/* check the specified item */
static int check_thread_item_status(monitor_thread_item item)
{
    int ret = 0;
    unsigned int check_num;
    unsigned int check_period;

    check_period = g_thread_status[item].period * (g_thread_status[item].check_failure_num + 1);
    /* if check period is 0, return for next check */
    if (check_period == 0) {
        return 0;
    }
    /* exclude check_num is 0 */
    check_num = (g_thread_status[item].check_num + 1) * SYSMONITOR_PERIOD;
    if (check_num >= check_period) {
        ret = check_thread_is_normal(item);
    } else {
        g_thread_status[item].check_num += 1;
    }
    return ret;
}

static int check_fs_failure_time(monitor_thread_item item)
{
    g_thread_status[item].check_failure_num += 1;
    log_printf(LOG_INFO, "fs check status failed, item[%d] failure:[%u], count:[%u], max failure num:[%u]",
        item, g_thread_status[item].check_failure_num, g_thread_status[item].count, g_max_failure_num);
    if (g_thread_status[item].check_failure_num >= g_max_failure_num) {
        log_printf(LOG_ERR, "fs need to restart sysmonitor, item[%u] failure:[%u], count[%u]",
            item, g_thread_status[item].check_failure_num, g_thread_status[item].count);
        return -1;
    }
    return 0;
}

/* check fs item status */
static int check_thread_fs_item_status(monitor_thread_item item)
{
    unsigned int count;
    unsigned int check_num;
    unsigned int check_period;
    int ret;

    check_period = g_thread_status[item].period * (g_thread_status[item].check_failure_num + 1);
    /* if check period is 0, return for next check */
    if (check_period == 0) {
        return 0;
    }

    count = g_thread_status[item].count;
    /* check success, don't need to check the item, set check_flag false and clear status */
    if (count > 0) {
        log_printf(LOG_INFO, "item[%d] check thread status success", item);
        ret = set_thread_status_check_flag(item, false);
        if (ret == -1) {
            log_printf(LOG_INFO, "item[%d] check thread set flag error", item);
            return -1;
        }
        return 0;
    }

    check_num = (g_thread_status[item].check_num + 1) * SYSMONITOR_PERIOD;
    if (check_num >= check_period) {
        ret = check_fs_failure_time(item);
        if (ret == -1) {
            return -1;
        }
    }
    g_thread_status[item].check_num += 1;
    return 0;
}


static int processs_parallel_add_node(pthread_t id)
{
    int ret;
    thread_ps_parallel_status *tmp = NULL;

    tmp = malloc(sizeof(thread_ps_parallel_status));
    if (tmp == NULL) {
        return -1;
    }
    ret = memset_s(tmp, sizeof(thread_ps_parallel_status), 0, sizeof(thread_ps_parallel_status));
    if (ret != 0) {
        log_printf(LOG_ERR, "ps parallel add list memset_s tmp failed, ret: %d.", ret);
        free(tmp);
        return -1;
    }
    tmp->status.check_flag = true;
    tmp->thread_id = id;
    log_printf(LOG_INFO, "ps parallel add list set status, id:%lu, check_flag:%d",
        tmp->thread_id, tmp->status.check_flag);
    (void)pthread_mutex_lock(&g_parallel_mtx);
    list_add(&tmp->list, &g_thread_ps_parallel_head);
    (void)pthread_mutex_unlock(&g_parallel_mtx);
    return 0;
}

static int process_parallel_del_node(pthread_t id)
{
    thread_ps_parallel_status *tmp = NULL;

    (void)pthread_mutex_lock(&g_parallel_mtx);
    list_for_each_entry(tmp, &g_thread_ps_parallel_head, list) {
        if (tmp != NULL && tmp->thread_id == id) {
            log_printf(LOG_INFO, "ps parallel del list status, id:%lu", id);
            list_del(&tmp->list);
            free(tmp);
            (void)pthread_mutex_unlock(&g_parallel_mtx);
            return 0;
        }
    }
    (void)pthread_mutex_unlock(&g_parallel_mtx);
    log_printf(LOG_ERR, "ps parallel del list status error, id:%lu", id);
    return -1;
}

/*
 * ps parallel check item is dynamically added,
 * when flag is true: need to malloc and add list;
 * when flag is false: need to del list and free memory
 * return 0:success, -1: error
 */
int set_ps_parallel_check_flag(monitor_thread_item item, bool flag, pthread_t id)
{
    int ret;

    if (!g_check_thread_monitor) {
        return 0;
    }

    if (item != THREAD_PS_PARALLEL_ITEM) {
        log_printf(LOG_ERR, "set thread ps parallel check flag wrong item:%d, id:%lu", item, id);
        return -1;
    }

    if (flag) {
        ret = processs_parallel_add_node(id);
        if (ret == -1) {
            return -1;
        }
    } else {
        ret = process_parallel_del_node(id);
        if (ret == -1) {
            return -1;
        }
    }

    return 0;
}

int feed_thread_ps_parallel_count(monitor_thread_item item, pthread_t id)
{
    thread_ps_parallel_status *tmp = NULL;

    if (!g_check_thread_monitor) {
        return 0;
    }

    if (item != THREAD_PS_PARALLEL_ITEM) {
        log_printf(LOG_ERR, "feed thread ps parallel status wrong item:%d, id:%lu", item, id);
        return -1;
    }

    (void)pthread_mutex_lock(&g_parallel_mtx);
    list_for_each_entry(tmp, &g_thread_ps_parallel_head, list) {
        if (tmp != NULL && tmp->thread_id == id) {
            tmp->status.count += 1;
            (void)pthread_mutex_unlock(&g_parallel_mtx);
            return 0;
        }
    }
    (void)pthread_mutex_unlock(&g_parallel_mtx);
    log_printf(LOG_ERR, "ps parallel id:[%lu] feed failed", id);
    return -1;
}

int set_thread_ps_parallel_period(monitor_thread_item item, pthread_t id, unsigned int period)
{
    thread_ps_parallel_status *tmp = NULL;

    if (!g_check_thread_monitor) {
        return 0;
    }

    if (item != THREAD_PS_PARALLEL_ITEM) {
        log_printf(LOG_ERR, "set thread ps parallel period wrong item:%d, id:%lu", item, id);
        return -1;
    }

    (void)pthread_mutex_lock(&g_parallel_mtx);
    list_for_each_entry(tmp, &g_thread_ps_parallel_head, list) {
        if (tmp != NULL && tmp->thread_id == id) {
            tmp->status.period = period;
            (void)pthread_mutex_unlock(&g_parallel_mtx);
            return 0;
        }
    }
    (void)pthread_mutex_unlock(&g_parallel_mtx);

    log_printf(LOG_ERR, "ps parallel id:[%lu] set period[%u] failed", id, period);
    return -1;
}

int set_ps_parallel_check_value(monitor_thread_item item, bool flag, pthread_t id, unsigned int period)
{
    int ret;

    if (!g_check_thread_monitor) {
        return 0;
    }

    ret = set_ps_parallel_check_flag(item, flag, id);
    if (ret == -1) {
        return -1;
    }

    ret = set_thread_ps_parallel_period(item, id, period);
    if (ret == -1) {
        return -1;
    }

    return 0;
}

static int check_thread_ps_parallel_status(void)
{
    thread_ps_parallel_status *tmp = NULL;
    pthread_t id;
    unsigned int count;
    unsigned int check_num;
    unsigned int check_period;

    (void)pthread_mutex_lock(&g_parallel_mtx);
    list_for_each_entry(tmp, &g_thread_ps_parallel_head, list) {
        if (tmp == NULL) {
            continue;
        }

        if (!tmp->status.check_flag) {
            continue;
        }

        check_period = tmp->status.period * (tmp->status.check_failure_num + 1);
        if (check_period == 0) {
            continue;
        }

        /* check success */
        count = tmp->status.count;
        if (count != 0) {
            tmp->status.count = 0;
            tmp->status.check_num = 0;
            tmp->status.check_failure_num = 0;
            continue;
        }

        check_num = (tmp->status.check_num + 1) * SYSMONITOR_PERIOD;
        if (check_num >= check_period) {
            id = tmp->thread_id;
            tmp->status.check_failure_num += 1;
            log_printf(LOG_ERR, "ps parallel check failed, id:[%lu], failure:[%u], count:[%u], max failure num:[%u]",
                id, tmp->status.check_failure_num, count, g_max_failure_num);
            if (tmp->status.check_failure_num >= g_max_failure_num) {
                log_printf(LOG_ERR, "ps parallell need to restart sysmonitor, id:[%lu], failure:[%u], count[%u]",
                    id, tmp->status.check_failure_num, count);
                (void)pthread_mutex_unlock(&g_parallel_mtx);
                return -1;
            }
        }
        tmp->status.check_num += 1;
    }
    (void)pthread_mutex_unlock(&g_parallel_mtx);
    return 0;
}

/*
 * check all thread status
 * return 0:success, -1: error,need to restart sysmonitor
 */
static int check_thread_running_status(void)
{
    int item;
    int ret;
    bool check_flag = false;

    /* no need to check thread status */
    if (!g_check_thread_monitor) {
        return 0;
    }

    for (item = 0; item < THREAD_MONITOR_ITEMS_CNT; item++) {
        /* don't need to check FILE_ITEM and THREAD_SYS_EVENT_ITEM */
        if (item == THREAD_FILE_ITEM || item == THREAD_SYS_EVENT_ITEM) {
            continue;
        }

        /* need to check ps parallel before check g_thread_status check_flag, because it's check_flag is never set */
        if (item == THREAD_PS_PARALLEL_ITEM) {
            ret = check_thread_ps_parallel_status();
            if (ret == -1) {
                return -1;
            }
            continue;
        }

        check_flag = g_thread_status[item].check_flag;
        if (!check_flag) {
            continue;
        }

        if (item == THREAD_FS_ITEM) {
            ret = check_thread_fs_item_status(item);
            if (ret == -1) {
                return -1;
            }
            continue;
        }
        /* check status */
        ret = check_thread_item_status(item);
        if (ret == -1) {
            return -1;
        }
    }
    return 0;
}

int check_thread_status(void)
{
    int ret;
    ret = check_thread_running_status();
    if (ret == -1) {
        ret = lovs_system(RESTART_MONITOR);
        if (ret != 0) {
            return -1;
        }
    }
    return 0;
}
