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
 * Description: define common functions and variables
 * Author: xuchunmei
 * Create: 2016-1-1
 */
#ifndef COMMON_H
#define COMMON_H

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>

#define DAEMON_SYSLOG 0
#define NORMAL_WRITE 1
#define OK 0
#define ERR (-1)
#define LOG_FILE_LEN 128
#define MAX_LOG_LEN (4096 + (2 * MAX_TEMPSTR))
#define MAX_TEMPSTR 200
#define MAX_CONFIG 4096

#define POPEN_TIMEOUT 30
#define WORKER_TASK_TIMEOUT 30
#define ERROR_FORK (-1)
#define ERROR_FDOPEN (-2)
#define ERROR_SELECT (-3)
#define ERROR_TIMEOUT (-4)
#define ERROR_PIPE (-5)
#define ERROR_FCNTL (-6)
#define ERROR_ARGS_WRONG (-7)
#define ERROR_CONF (-8)
#define ERROR_OPEN (-9)
#define ERROR_SETUID (-10)
#define ERROR_PARSE (-11)
#define ERROR_CREATE_THREAD (-12)
#define ERROR_NO_CONF (-13)

#define DEFAULT_USER_ID 0xffffffff
#define QUEUE_SIZE 1000
#define TASK_QUEUE_SIZE 100
#define PARAS_LEN 256

#define ITEM_LEN 50
#define VALUE_LEN 10

#define COMMON_ALARM_TYPE_EVENT 2
#define COMMON_ALARM_TYPE_OCCUR 1
#define COMMON_ALARM_TYPE_RESUME 0

#define CPU_ABNORMAL 1001
#define MEM_ABNORMAL 1002
#define DISK_ABNORMAL 1003
#define FS_ABNORMAL 1004
#define PS_ABNORMAL 1005
#define FILE_ABNORMAL 1006
#define NET_ABNORMAL 1007
#define SIG_ABNORMAL 1008
#define PSCNT_ABNORMAL 1009
#define FDCNT_ABNORMAL 1010
#define DISK_INODE_ABNORMAL 1011
#define DISK_IO_DELAY_ABNORMAL 1012
#define PROCESS_FD_NUM_ABNORMAL 1014
#define PROCESS_FD_LEAK_ABNORMAL 1015
#define ZOMBIE_ABNORMAL        1016
#define FS_EXT4_ABNORMAL       1019
#define PS_THREADS_ABNORMAL 1025

#define ALARM_LEVEL_CRITICAL 1
#define ALARM_LEVEL_MAJOR 2
#define ALARM_LEVEL_MINOR 3
#define ALARM_LEVEL_WARNING 4
#define ALARM_LEVEL_INDETERMINATE 5

#define MAX_STRERROR_SIZE 1024
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#define DEFALUT_PROCESS_RESTART_TIMEOUT 90
#define TASK_COMM_LEN 16
#define EXEC_MAX 256
#define ARGS_MAX 64
#define TM_YEAR_BEGIN 1900
#define LOG_FILE_PERMISSION 0640
#define KERNELMODE_FILE_PERMISSION 0600
#define PROCESS_EXIT_TIMEOUT 10
#define PROCESS_SLEEP_INTERVAL (100 * 1000 * 1000)
#define THREAD_PID_OFFSET 16
#define POLL_TIMEOUT_DEFAULT (30 * 1000)
#define FAIL_NUM 3

#define RET_SUCCESS 0
#define RET_BREAK (-1)
#define RET_CONTINUE 1

#define array_size(arr) (sizeof(arr) / sizeof((arr)[0]))
#define SYSMONITOR_PERIOD 2

#define STRTOL_NUMBER_BASE 10
#define STRTOL_HEX_NUMBER_BASE 16
#define STRTOULL_NUMBER_BASE 10

typedef enum monitor_type {
    PS_ITEM,
    FS_ITEM,
    FILE_ITEM,
    DISK_ITEM,
    INODE_ITEM,
    CUSTOM_DAEMON_ITEM,
    CUSTOM_PERIODIC_ITEM,
    IO_DELAY_ITEM,
    SYSTEM_ITEM,
    SYS_EVENT_ITEM,
    ZOMBIE_ITEM,
    MONITOR_ITEMS_CNT
} monitor_item_type;

struct list_head {
    struct list_head *next, *prev;
};

typedef struct monitor_thread_s {
    pthread_t tid;
    bool monitor;
    bool alarm;
    bool reload;
    int period;
    void (*init)(void);
} monitor_thread;

typedef enum task_state_type {
    RUNNING_STATE = 1,
    EXITED_STATE,
    EXITING_STATE
} task_state;

typedef struct worker_task_s {
    pid_t cpid;
    int time_count;
    task_state state;
} worker_task;

enum heart_msg_type {
    PID_TYPE = 0,
    STOP_TYPE,
    START_TYPE
};

/*
 * type == 0 pid
 * type == 1 service stop
 * type == 2 service start
 */
typedef struct heart_msg_s {
    int type;
    pid_t pid;
} heart_message;

struct alarm_level_info {
    unsigned short alarm_id;
    unsigned char alarm_level;
};

extern int get_log_interface_flag(void);
extern bool get_flag_log_ok(void);
extern void log_printf(int priority, const char *format, ...);
extern bool get_thread_item_reload_flag(monitor_item_type type);
extern void set_thread_item_reload_flag(monitor_item_type type, bool flag);
extern void set_thread_item_tid(monitor_item_type type, pthread_t tid);
extern int get_thread_item_period(monitor_item_type type);
extern void set_thread_item_period(monitor_item_type type, int period);
extern bool get_thread_item_monitor_flag(monitor_item_type type);
extern void set_thread_item_monitor_flag(monitor_item_type type, bool flag);
extern bool get_thread_item_alarm_flag(monitor_item_type type);

/* exec command */
int monitor_popen(const char *psz_cmd, char *psz_buffer, unsigned int size, long timeout, const char *psz_stop_cmd);
int lovs_system(const char *cmdstring);
int monitor_cmd(uid_t uid, const char *psz_cmd, long timeout, const char *psz_stop_cmd, bool bash_cmd);

/* parse config */
void get_value(const char *config, unsigned int item_size, char *value, unsigned int value_len);
bool parse_config(const char *conf, bool (*parse_line)(const char *line));
FILE *open_cfgfile(const char *d_name, int *config_fd);
bool check_int(const char *input);
bool check_decimal(const char *input);
int check_conf_file_valid(const char *config);
bool check_file(const char *file);
bool parse_value_int(const char *item, const char *value, unsigned int *result);
bool parse_value_string(const char *item, const char *value, char *result, unsigned int size);
bool parse_value_bool(const char *item, const char *value, bool *result);
bool parse_value_float(const char *item, const char *value, float *result);
bool parse_value_ulong(const char *item, const char *value, unsigned long *result);
bool check_log_path(const char *log_path);

/* parse command */
int get_exec_and_args(const char *cmd, char *exec, char ***cmdline);
void free_args(char **args, int args_num);

static inline void init_list_head(struct list_head *list)
{
    list->next = list;
    list->prev = list;
}

#define m_offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)

/*
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:        the pointer to the member.
 * @type:       the type of the container struct this is embedded in.
 * @member:     the name of the member within the struct.
 */
#define container_of(ptr, type, member) ({               \
    const typeof(((type *)0)->member) * __mptr = (ptr);  \
    (type *)((char *)__mptr - m_offsetof(type, member)); \
})

/* refer to linux source code: include/linux/list.h */

/*
 * list_entry - get the struct for this entry
 * @ptr:        the &struct list_head pointer.
 * @type:       the type of the struct this is embedded in.
 * @member:     the name of the list_struct within the struct.
 */
#define list_entry(ptr, type, member) container_of(ptr, type, member)

/*
 * list_for_each_entry  -       iterate over list of given type
 * @pos:        the type * to use as a loop cursor.
 * @head:       the head for your list.
 * @member:     the name of the list_struct within the struct.
 */
#define list_for_each_entry(pos, head, member)                   \
    for ((pos) = list_entry((head)->next, typeof(*(pos)), member);   \
         &(pos)->member != (head);                                 \
         (pos) = list_entry((pos)->member.next, typeof(*(pos)), member))

/*
 * list_for_each_entry_safe - iterate over list of given type safe against removal of list entry
 * @pos:    the type * to use as a loop counter.
 * @n:      another type * to use as temporary storage
 * @head:   the head for your list.
 * @member: the name of the list_struct within the struct.
 */
#define list_for_each_entry_safe(pos, n, head, member)           \
    for ((pos) = list_entry((head)->next, typeof(*(pos)), member),   \
         (n) = list_entry((pos)->member.next, typeof(*(pos)), member); \
         &(pos)->member != (head);                                 \
         (pos) = (n), (n) = list_entry((n)->member.next, typeof(*(n)), member))

static inline void list_add(struct list_head *new, struct list_head *head)
{
    head->next->prev = new;
    new->next = head->next;
    new->prev = head;
    head->next = new;
}

/*
 * Delete a list entry by making the prev/next entries
 * point to each other.
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
static inline void _list_del(struct list_head *prev, struct list_head *next)
{
    next->prev = prev;
    prev->next = next;
}

/* delete a list entry */
static inline void list_del(struct list_head *entry)
{
    _list_del(entry->prev, entry->next);
}

static inline int list_empty(struct list_head *head)
{
    return head->next == head;
}

extern int set_value_to_file(const char *msg, const char *path);
extern int get_string(const char *config, const char *value, char *outstr, unsigned int outsize, const char *item);

#endif
