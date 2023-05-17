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
 * Description: define variable, structure and function for custom process monitor
 * Author: xuchunmei
 * Create: 2016-1-1
 */
#ifndef CUSTOM_H
#define CUSTOM_H
#include <unistd.h>

#include "common.h"

#define CUSTOM_CONFIG_DIR "/etc/sysmonitor.d/"
#define MAX_CFG_NAME_LEN 128
#define MAX_CUSTOM_CMD_LEN 160
#define MAX_ENV_CONFIG 256    /* the max number of environment variables */
#define MAX_CLOSE_FD_NUM 1024

extern char **environ;

typedef enum customtype {
    CUSTOM_DAEMON = 1,
    CUSTOM_PERIODIC
} custom_type;

typedef struct str_custom_s {
    struct list_head list;                  /* list flag */
    pid_t pid;                              /* pid of child process */
    custom_type type;                       /* custom monitor type: daemon or periodic */
    char start_cmd[MAX_CUSTOM_CMD_LEN];     /* custom monitor exec cmd */
    char conf_name[MAX_CFG_NAME_LEN];       /* custom monitor config name */
    char enviroment_file[MAX_CFG_NAME_LEN]; /* environment file name: absolute path + name */
    char **envp;                            /* environment variables, include current process and configed */
    char *envp_config[MAX_ENV_CONFIG];      /* environment variables, only current, exclude inherited */
    unsigned int envp_config_count;         /* the number of environment variables by configed */
    unsigned int period;                    /* monitor period of periodic monitor */
    unsigned int time_count;                /* time counts for periodic monitor */
    unsigned int daemon_restart_times;
    int daemon_thread_start;
    int state_index;                        /* index of task state */
    int state;                              /* task state: running, exiting, exited */
    bool monitor_switch;                    /* monitor switch */
} str_custom;

typedef struct custom_item_func_s {
    char item[ITEM_LEN];
    bool (*func)(const char *item, const char *value, str_custom *t);
} custom_item_func;

void custom_daemon_monitor_init(void);
void custom_periodic_monitor_init(void);
bool worker_thread_init(pthread_t *tid);
bool worker_task_struct_init(void);

#endif
