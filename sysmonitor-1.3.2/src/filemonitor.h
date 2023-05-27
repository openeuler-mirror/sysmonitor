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
 * Description: define variable, structure and function for file monitor
 * Author: xuchunmei
 * Create: 2016-1-1
 */
#ifndef __FILE_MONITOR_H
#define __FILE_MONITOR_H

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/inotify.h>

#include "common.h"

#define FM_MONITOR_CONF "/etc/sysmonitor/file"
#define FM_MONITOR_CONFIG_DIR "/etc/sysmonitor/file.d/"
#define FM_MAX_CFG_NAME_LEN      128
/* PATH_MAX 4096, security function requires less 1 bit */
#define MAX_PATH_LEN 4097
/* PATH_MAX 4096, operation code and blank */
#define MAX_LINE_LEN 4116
#define MAX_MASK_LEN 16
#define EVENT_BUF 16384

typedef struct _fqueue_entry {
    struct list_head list;
    char file_path[MAX_PATH_LEN];
    unsigned long wt_mask;
    int wd;
    bool flag;
    unsigned int count; /* counts of watch failed */
} fqueue_entry;

typedef struct _inotify_event_process_info {
    int pid;
    int parent_pid;
    char comm[TASK_COMM_LEN];
    char parent_comm[TASK_COMM_LEN];
} inotify_event_process_info;

typedef struct _queue_entry {
    struct list_head list;
    inotify_event_process_info info;
    struct inotify_event inot_ev;
} queue_entry;

void file_monitor_init(void);
void set_file_monitor_select_timeout(int timeout);

#endif
