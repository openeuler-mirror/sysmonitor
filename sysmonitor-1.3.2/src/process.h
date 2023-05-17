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
 * Description: define variable, structure and function for process monitor
 * Author: xuchunmei
 * Create: 2016-1-1
 */
#ifndef PROCESS_H
#define PROCESS_H
#include <unistd.h>

#include "common.h"

#define MAX_PS_CONFIG_VALUE 200
#define PROCESS_CHECK_TIME 2
#define PROCESS_CHECK_NUM 2
#define POPEN_TIMEOUT_NUM 5 /* total number of timeouts in a check period */
#define PARALLEL_POPEN_TIMEOUT_NUM 3 /* total number of timeouts in a check period */
#define PROCESS_OTHER_TIME 100 /* extra time required, the value is the empirical value. */

typedef struct _mtask {
    int monitor_mode;
    uid_t uid;
    char user[MAX_PS_CONFIG_VALUE];
    char name[MAX_PS_CONFIG_VALUE];              /* monitor task name */
    char recover_cmd[MAX_PS_CONFIG_VALUE];       /* recover command */
    char monitor_cmd[MAX_PS_CONFIG_VALUE];       /* monitor command */
    char stop_cmd[MAX_PS_CONFIG_VALUE];          /* stop command, when exec monitor_cmd timeout, exec stop_cmd */
    char alarm_cmd[MAX_PS_CONFIG_VALUE];         /* alarm command, when use_cmd_alarm, use this to alarm */
    char alarm_recover_cmd[MAX_PS_CONFIG_VALUE]; /* alarm recover command, when use_cmd_alarm, use this to recover */
    bool chk_result_as_param;                    /* monitor_cmd ret set as param of recover_cmd */
    bool resend_recover_cmd;                     /* flag used to mark resend recover-cmd */
    bool start;                                  /* task is start or not */
    bool use_cmd_alarm;                          /* use alarm_cmd to alarm and alarm_recover_cmd to recover */
    pthread_t thread_id;
    unsigned int monitor_period;                 /* only use at PARALLEL_MONITOR mode */
    unsigned int fail;                           /* fail times */
    unsigned int time_count;                     /* monitor period counts after recover failed 3 times */
    unsigned int n1_recall;                      /* recall times when timeout less than RECALL_PERIOD */
    unsigned int n2_recall;                      /* recall times when timeout exceed RECALL_PERIOD */
    struct list_head list;
} mtask;

void ps_monitor_init(void);
bool parse_process_monitor_delay(const char *item, const char *value);
bool parse_process_alarm_supress(const char *value);
bool parse_process_restart_tiemout(const char *value);
bool parse_process_recall_period(const char *value);

#endif
