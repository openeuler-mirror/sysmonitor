/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * sysmonitor licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Description: system resources monitor, include cpu, memory, process count, and system fd num
 * Author: xuchunmei
 * Create: 2019-2-14
 */
#include "sys_resources.h"

#include <unistd.h>
#include <dirent.h>
#include <regex.h>
#include <securec.h>
#include <sys/sysinfo.h>
#include "monitor_thread.h"

#define MEM_STAT_TIMES 3
#define PSCNT_ALARM_RATIO 90
#define PSCNT_RESUME_RATIO 80
#define PSCNT_ALARM_VALUE 1600
#define PSCNT_RESUME_VALUE 1500
#define CACHE_TWEAK_FACTOR 64
#define SMLBUFSIZ (256 + CACHE_TWEAK_FACTOR)
#define trimz(x) ((tz = (long long)(x)) < 0 ? 0 : tz)
#define SYS_RES_MONITOR_PERIOD_MIN 1
#define MEM_INFO_BUFFER 4096
#define ALARM_RATIO_DEFAULT 90.0
#define RESUME_RATIO_DEFAULT 80.0
#define MONITOR_PERIOD_DEFAULT 60
#define SYSFD_ALARM_VALUE 80.0
#define SYSFD_RESUME_VALUE 70.0
#define SYSFD_MONITOR_PERIOD 600
#define CPU_STAT_PERIOD 300
/* monitor_count init value set to -1, when monitor startup, will exec item monitor */
#define MONITOR_COUNT_INIT (-1)
#define PROC_SYSRQ_TRIGGER "/proc/sysrq-trigger"

#ifndef isdigit
#define isdigit(c) ((c) >= '0' && (c) <= '9')
#endif
#define FD_TMP_BUF 400
#define FD_PATH_MAX 50
#define PS_CMD_MAX 300
#define PID_BUF_LEN 30
#define FD_BUF_LEN 50
#define TOPFD_PROCESS_NUM 3
#define TOP_PROCESS_THREADS_NUM 10
#define TOP_PROCESS_THREADS_NUM_MAX 1024
#define PSCNT_RET_TRUE 1
#define PSCNT_RET_CONTINUE 0
#define PSCNT_RET_ERROR (-1)
#define PSCNT_COUNT_FOR_PROCESS 1
#define RATIO 100

#define FLOAT_VALUE_LEN 8
#define DOMAIN_DESC_LEN 256
#define MAX_DOMAIN_CPU_COUNT 256
#ifdef __x86_64__
#define DOMAIN_CPU_LEN 1024  /* x86 supports max 8192 CPUs */
#elif defined(__riscv)
#define DOMAIN_CPU_LEN 64    /* riscv supports max 512 CPUs */
#else
#define DOMAIN_CPU_LEN 128   /* arm64 supports max 1024 CPUs */
#endif
#define CHAR_BITS 8
#define REPORT_CMD_LEN 160
#define REPORT_CMD_TIMEOUT 60
#define COMMON_ALARM_MAX 100
#define COMMON_RESUME_MAX 100

typedef struct _ps_fd_info {
    char cmd[PS_CMD_MAX + 1]; /* process name, max 300 characters */
    unsigned long num;        /* num of process opened */
    char pid[PID_BUF_LEN];    /* pid of process */
} ps_fd_info;

typedef struct _ps_threads_info {
    char cmd[PS_CMD_MAX + 1]; /* process name, max 300 characters */
    unsigned long num;        /* num of process threads opened */
    char pid[PID_BUF_LEN];    /* pid of process */
} ps_threads_info;

typedef struct system_monitor_info_s {
    float alarm_value;
    float resume_value;
    unsigned int monitor_period;
    unsigned int stat_period;
    int monitor_count;
    bool monitor;
    bool alarm;
    bool config_ok;
    bool status;
    void (*monitor_func)(void);
} system_monitor_info;

typedef struct str_cpu_s {
    unsigned long long u, n, s, i, w, x, y, z;                                 /* as represented in /proc/stat */
    unsigned long long u_sav, s_sav, n_sav, i_sav, w_sav, x_sav, y_sav, z_sav; /* in the order of our display */
} str_cpu;

typedef struct _cpu_domain {
    struct _cpu_domain *next;
    float alarm_value;
    float resume_value;
    unsigned int cpu_num;
    bool status;
    bool broken;                            /* when some cpu is offline, set broken to true */
    bool first_collected;                   /* cpustat has been refreshed for the first time */
    unsigned char desc[DOMAIN_DESC_LEN];    /* store DOMAIN config */
    unsigned char cpus[DOMAIN_CPU_LEN];     /* store domain cpu id by bit */
    str_cpu cpustat;
} cpu_domain;

struct item_value_func {
    char item[ITEM_LEN];
    bool (*func)(const char *item, const char *value, int type);
};

struct config_parse_func {
    char config_file[ITEM_LEN];
    bool (*parse_line_func)(const char *config);
    bool (*check_config)(bool parse_ok);
};

struct mem_info {
    unsigned long total;
    unsigned long cached;
    unsigned long sreclaimable;
    unsigned long free;
    unsigned long buffers;
    unsigned long shmem;
};

static cpu_domain *g_domain_head = NULL;
static cpu_domain *g_new_domain_list = NULL;
static bool g_monitor_domain_flag = false;          /* deal with change of monitor mode */
static bool g_has_reported_flag = false;            /* report_cmd execute most once during one monitor */
static char g_cpu_report_cmd[REPORT_CMD_LEN] = {0};

static system_monitor_info g_system_monitor_info[SYSTEM_MONITOR_ITEM_CNT];
static unsigned int g_sys_res_period;
static struct mem_info g_mem_info;
static float g_pscnt_alarm_ratio = PSCNT_ALARM_RATIO;
static float g_pscnt_resume_ratio = PSCNT_RESUME_RATIO;
static unsigned int g_pscnt_threads_top_num = TOP_PROCESS_THREADS_NUM;
static bool g_pscnt_threads_status_flag = false;
static bool g_pscnt_threads_create_flag = true;
static ps_threads_info *g_top_process_threads = NULL;

static void get_ps_cmd(char *cmd, const char *pid, size_t cmd_len);
static int get_file_nr(unsigned long *file_nr, unsigned long *file_max);
/*
 * check config before parse
 * for pscnt and system fd num, alarm and resume should be int
 */
static bool check_before_parse(const char *value, int type)
{
    if (type == PSCNT || type == SYSTEM_FDCNT) {
        return check_int(value);
    }
    return true;
}

static bool parse_alarm(const char *item, const char *value, int type)
{
    return check_before_parse(value, type) &&
        parse_value_float(item, value, &g_system_monitor_info[type].alarm_value);
}

static bool parse_resume(const char *item, const char *value, int type)
{
    return check_before_parse(value, type) &&
        parse_value_float(item, value, &g_system_monitor_info[type].resume_value);
}

static bool parse_monitor_period(const char *item, const char *value, int type)
{
    return parse_value_int(item, value, &g_system_monitor_info[type].monitor_period);
}

static bool parse_stat_period(const char *item, const char *value, int type)
{
    return parse_value_int(item, value, &g_system_monitor_info[type].stat_period);
}

static bool parse_alarm_ratio(const char *item, const char *value, int type)
{
    if (type != PSCNT) {
        return false;
    }

    return parse_value_float(item, value, &g_pscnt_alarm_ratio);
}

static bool parse_resume_ratio(const char *item, const char *value, int type)
{
    if (type != PSCNT) {
        return false;
    }

    return parse_value_float(item, value, &g_pscnt_resume_ratio);
}

static bool parse_threads_top_num(const char *item, const char *value, int type)
{
    if (type != PSCNT) {
        return false;
    }

    return parse_value_int(item, value, &g_pscnt_threads_top_num);
}

static bool clear_report_cmd(void)
{
    int ret = 0;

    ret = memset_s(g_cpu_report_cmd, REPORT_CMD_LEN, 0, REPORT_CMD_LEN);
    if (ret) {
        log_printf(LOG_ERR, "clear_report_cmd: memset_s g_cpu_report_cmd failed, ret: %d", ret);
        return false;
    }

    return true;
}

static bool parse_report_command(const char *item, const char *value, int type)
{
    if (type != CPU) {
        return false;
    }

    if (clear_report_cmd() == false) {
        return false;
    }

    if (strlen(value) == 0) {
        return true;
    }

    if (check_conf_file_valid(value) == -1) {
        return false;
    }

    return parse_value_string(item, value, g_cpu_report_cmd, REPORT_CMD_LEN);
}

static void free_domain_list(cpu_domain **domainlist)
{
    cpu_domain *t = NULL;
    cpu_domain *domain = NULL;

    if (*domainlist == NULL) {
        return;
    }

    domain = *domainlist;
    t = domain;
    while (t->next != NULL) {
        domain = t->next;
        free(t);
        t = domain;
    }
    free(domain);
    *domainlist = NULL;
}

static bool domain_add(const cpu_domain *add_domain, cpu_domain **domain_list)
{
    int ret = 0;
    cpu_domain *domain = NULL;

    if (add_domain == NULL) {
        return false;
    }

    domain = malloc(sizeof(cpu_domain));
    if (domain == NULL) {
        log_printf(LOG_ERR, "malloc cpu_domain error [%d]", errno);
        return false;
    }

    ret = memcpy_s(domain, sizeof(cpu_domain), add_domain, sizeof(cpu_domain));
    if (ret != 0) {
        log_printf(LOG_ERR, "domain_add: memcpy_s domain failed, ret: %d", ret);
        free(domain);
        return false;
    }

    domain->next = NULL;

    if (*domain_list == NULL) {
        *domain_list = domain;
    } else {
        domain->next = *domain_list;
        *domain_list = domain;
    }
    return true;
}

static void free_set_domain_head(void)
{
    cpu_domain *t = NULL;

    free_domain_list(&g_domain_head);
    g_domain_head = g_new_domain_list;
    g_new_domain_list = NULL;

    if (g_system_monitor_info[CPU].monitor && g_system_monitor_info[CPU].config_ok) {
        t = g_domain_head;
        while (t != NULL) {
            log_printf(LOG_INFO, "[cpu monitor]domain:%s alarm:%4.1f%% resume:%4.1f%% has monitored",
                t->desc, t->alarm_value, t->resume_value);
            t = t->next;
        }
    }
}

static bool check_and_set_cpuid(cpu_domain *domain, const unsigned int cpu)
{
    unsigned int index = 0;
    unsigned int offset = 0;
    int nprocs = get_nprocs_conf();
    cpu_domain *t = NULL;

    if (nprocs < 0) {
        log_printf(LOG_ERR, "failed to get number of system processors");
        return false;
    }

    index = cpu / CHAR_BITS;
    /* check cpu id valid */
    if (cpu >= (unsigned int)nprocs || index >= DOMAIN_CPU_LEN) {
        log_printf(LOG_ERR, "invalid CPU ID: %u", cpu);
        return false;
    }

    /* check cpu id repeated */
    offset = CHAR_BITS - cpu % CHAR_BITS - 1;
    if ((domain->cpus[index] >> offset) & 1) {
        log_printf(LOG_ERR, "repeated CPU ID %u in DOMAIN %s", cpu, domain->desc);
        return false;
    }

    t = g_new_domain_list;
    while (t != NULL) {
        if ((t->cpus[index] >> offset) & 1) {
            log_printf(LOG_ERR, "repeated CPU ID %u in DOMAIN %s", cpu, domain->desc);
            return false;
        }
        t = t->next;
    }

    domain->cpus[index] |= (unsigned char)((unsigned int)1 << offset);
    domain->cpu_num++;
    if (domain->cpu_num > MAX_DOMAIN_CPU_COUNT) {
        log_printf(LOG_ERR, "cpu num exceeds %d in one domain", MAX_DOMAIN_CPU_COUNT);
        return false;
    }
    return true;
}

static bool get_domain_cpuid_dash(cpu_domain *domain, char *domain_value, unsigned int size)
{
    char *p_cpu = NULL;
    char *p_save = NULL;
    unsigned int cpu_start;
    unsigned int cpu_end;
    unsigned int i;

    if (size == 0) {
        return false;
    }

    p_cpu = strtok_r(domain_value, "-", &p_save);
    if (p_cpu != NULL) {
        if (!parse_value_int("DOMAIN", p_cpu, &cpu_start) || !parse_value_int("DOMAIN", p_save, &cpu_end)) {
            return false;
        }
        if (cpu_start >= cpu_end) {
            log_printf(LOG_ERR, "invalid CPU range: %u-%u", cpu_start, cpu_end);
            return false;
        }
        /* first check border to increase efficiency */
        if (!check_and_set_cpuid(domain, cpu_start) || !check_and_set_cpuid(domain, cpu_end)) {
            return false;
        }

        for (i = cpu_start + 1; i < cpu_end; i++) {
            if (!check_and_set_cpuid(domain, i)) {
                return false;
            }
        }
        return true;
    }

    log_printf(LOG_ERR, "DOMAIN config illegal, check %s.", domain_value);
    return false;
}

static bool get_domain_cpuid_comma(cpu_domain *domain, char *domain_value, unsigned int size)
{
    unsigned int cpu = 0;
    char *p_cpu = NULL;
    char *p_save = NULL;

    if (size == 0) {
        return false;
    }

    p_cpu = strtok_r(domain_value, ",", &p_save);
    if (p_cpu == NULL) {
        log_printf(LOG_ERR, "DOMAIN config illegal, check %s.", domain_value);
        return false;
    }

    while (p_cpu != NULL) {
        /* contains X-Y */
        if (strstr(p_cpu, "-") != NULL) {
            if (!get_domain_cpuid_dash(domain, p_cpu, (unsigned int)strlen(p_cpu))) {
                return false;
            }
            p_cpu = strtok_r(NULL, ",", &p_save);
            continue;
        }
        /* only contains N1,N2 */
        if (!parse_value_int("DOMAIN", p_cpu, &cpu) || !check_and_set_cpuid(domain, cpu)) {
            return false;
        }
        p_cpu = strtok_r(NULL, ",", &p_save);
    }
    return true;
}

static bool regs_check_domain(const char *domain_value)
{
    regex_t reg;
    int flags = REG_EXTENDED;
    const char *pattern = "^[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*$";
    bool ret = true;

    if (regcomp(&reg, pattern, flags)) {
        return false;
    }

    if (regexec(&reg, domain_value, 0, NULL, 0)) {
        log_printf(LOG_ERR, "DOMAIN config illegal, check %s.", domain_value);
        ret = false;
    }

    regfree(&reg);
    return ret;
}

static bool get_domain_cpuid(cpu_domain *domain, char *domain_value, unsigned int size)
{
    int ret = 0;

    ret = strncpy_s((char *)domain->desc, DOMAIN_DESC_LEN, domain_value, DOMAIN_DESC_LEN - 1);
    if (ret != 0) {
        log_printf(LOG_ERR, "get_domain_cpuid: strncpy_s domain_value failed, ret: %d", ret);
        return false;
    }

    domain->cpu_num = 0;
    if (regs_check_domain(domain_value) == false) {
        return false;
    }

    /* parse format "N1,N2,N3,X-Y" */
    return get_domain_cpuid_comma(domain, domain_value, size);
}

static bool get_domain_alarm(cpu_domain *domain, const char *config)
{
    char key[FLOAT_VALUE_LEN] = {0};
    int ret = 0;

    ret = get_string(config, "ALARM=\"", key, sizeof(key), "ALARM");
    if (ret > 0) {
        domain->alarm_value = ALARM_RATIO_DEFAULT;
        return true;
    }
    if (ret < 0) {
        return false;
    }

    if (!parse_value_float(NULL, key, &(domain->alarm_value))) {
        log_printf(LOG_ERR, "invalid CPU alarm value: %s", key);
        return false;
    }
    return true;
}

static bool get_domain_resume(cpu_domain *domain, const char *config)
{
    char key[FLOAT_VALUE_LEN] = {0};
    int ret = 0;

    ret = get_string(config, "RESUME=\"", key, sizeof(key), "RESUME");
    if (ret > 0) {
        domain->resume_value = RESUME_RATIO_DEFAULT;
        return true;
    }
    if (ret < 0) {
        return false;
    }

    if (!parse_value_float(NULL, key, &(domain->resume_value))) {
        log_printf(LOG_ERR, "invalid CPU resume value: %s", key);
        return false;
    }
    return true;
}

static bool parse_domainline(char *domain_value, unsigned int size, cpu_domain *domain, const char *config)
{
    if (get_domain_cpuid(domain, domain_value, size) == false) {
        return false;
    }

    if (get_domain_alarm(domain, config) == false) {
        return false;
    }

    if (get_domain_resume(domain, config) == false) {
        return false;
    }

    if (domain->alarm_value < 0 || domain->alarm_value > COMMON_ALARM_MAX || domain->resume_value < 0 ||
        domain->resume_value > COMMON_RESUME_MAX || domain->resume_value >= domain->alarm_value) {
        log_printf(LOG_ERR, "invalid CPU alarm/resume value: %4.1f%%,%4.1f%%", domain->alarm_value,
            domain->resume_value);
        return false;
    }

    /* keep remaining domain status before reload */
    cpu_domain *t = g_domain_head;
    while (t != NULL) {
        if (memcmp(domain->cpus, t->cpus, DOMAIN_CPU_LEN) == 0) {
            domain->status = t->status;
            domain->cpustat = t->cpustat;
            domain->first_collected = t->first_collected;
            domain->broken = t->broken;
            break;
        }
        t = t->next;
    }

    return true;
}

static bool parse_domain(const char *config, char *domain_value, unsigned int size, int type)
{
    int ret;
    cpu_domain domain_tmp;

    if (type != CPU) {
        return false;
    }

    ret = memset_s(&domain_tmp, sizeof(domain_tmp), 0, sizeof(domain_tmp));
    if (ret != 0) {
        log_printf(LOG_ERR, "parse_domain: memset_s domain_tmp failed, ret: %d", ret);
        return false;
    }

    if (!parse_domainline(domain_value, size, &domain_tmp, config)) {
        return false;
    }

    return domain_add(&domain_tmp, &g_new_domain_list);
}

static const struct item_value_func g_item_array[] = {
    { "ALARM", parse_alarm },
    { "MONITOR_PERIOD", parse_monitor_period },
    { "PERIOD", parse_monitor_period },
    { "RESUME", parse_resume },
    { "STAT_PERIOD", parse_stat_period },
    { "SYS_FD_ALARM", parse_alarm },
    { "SYS_FD_RESUME", parse_resume },
    { "SYS_FD_PERIOD", parse_monitor_period },
    { "ALARM_RATIO", parse_alarm_ratio },
    { "RESUME_RATIO", parse_resume_ratio },
    { "SHOW_TOP_PROC_NUM", parse_threads_top_num },
    { "REPORT_COMMAND", parse_report_command }
};

static bool parse_line(const char *config, int type)
{
    char item[ITEM_LEN] = {0};
    char value[MAX_CONFIG] = {0};
    char *ptr = NULL;
    unsigned int size;
    int ret;
    unsigned int i;

    while (*config == ' ' || *config == '\t') {
        config++;
    }

    if (*config == '#') {
        return true;
    }

    ptr = strstr(config, "=\"");
    if (ptr != NULL) {
        size = (unsigned int)(ptr - config);
        if (size >= sizeof(item)) {
            log_printf(LOG_ERR, "parse_line: item length(%u) too long(>%u).", size, sizeof(item));
            return false;
        }
        ret = strncpy_s(item, sizeof(item), config, size);
        if (ret != 0) {
            log_printf(LOG_ERR, "parse_line: strncpy_s item failed, ret: %d", ret);
            return false;
        }
        get_value(config, size, value, sizeof(value));
        if (!strlen(value)) {
            return true;
        }
        for (i = 0; i < array_size(g_item_array); i++) {
            if (strcmp(item, g_item_array[i].item) == 0 && g_item_array[i].func != NULL) {
                return g_item_array[i].func(item, value, type);
            }
        }
        if (strcmp(item, "DOMAIN") == 0) {
            return parse_domain(config, value, sizeof(value), type);
        }
    }
    return true;
}

static bool parse_cpu_line(const char *config)
{
    return parse_line(config, CPU);
}

static bool parse_mem_line(const char *config)
{
    return parse_line(config, MEM);
}

static bool parse_sysfd_line(const char *config)
{
    return parse_line(config, SYSTEM_FDCNT);
}

static bool parse_pscnt_line(const char *config)
{
    return parse_line(config, PSCNT);
}

static bool check_config_common(int type)
{
    if (g_system_monitor_info[type].alarm_value < 0 ||
        g_system_monitor_info[type].alarm_value > COMMON_ALARM_MAX ||
        g_system_monitor_info[type].resume_value < 0 ||
        g_system_monitor_info[type].resume_value > COMMON_RESUME_MAX ||
        g_system_monitor_info[type].resume_value >= g_system_monitor_info[type].alarm_value ||
        g_system_monitor_info[type].monitor_period == 0)  {
        return false;
    }
    return true;
}

static void log_item_info(const char *item, bool config_ok)
{
    if (config_ok == false) {
        log_printf(LOG_INFO, "%s monitor: configuration illegal", item);
    } else {
        log_printf(LOG_INFO, "%s monitor starting up", item);
    }
}

static bool check_cpu_config(bool parse_ok)
{
    bool ret = parse_ok && check_config_common(CPU) && (g_system_monitor_info[CPU].stat_period != 0);

    log_item_info("cpu", ret);
    return ret;
}

static bool check_mem_config(bool parse_ok)
{
    bool ret = parse_ok && check_config_common(MEM);

    log_item_info("memory", ret);
    return ret;
}

static bool check_pscnt_ratio(void)
{
    if (g_pscnt_alarm_ratio < 0 || g_pscnt_alarm_ratio > COMMON_ALARM_MAX || g_pscnt_resume_ratio < 0 ||
        g_pscnt_resume_ratio > COMMON_RESUME_MAX || g_pscnt_resume_ratio >= g_pscnt_alarm_ratio) {
        return false;
    }
    return true;
}

static bool check_pscnt_config(bool parse_ok)
{
    if (parse_ok == false ||
        g_system_monitor_info[PSCNT].alarm_value < 0 ||
        g_system_monitor_info[PSCNT].resume_value < 0 ||
        g_system_monitor_info[PSCNT].resume_value >= g_system_monitor_info[PSCNT].alarm_value ||
        g_system_monitor_info[PSCNT].monitor_period == 0 || !check_pscnt_ratio() ||
        g_pscnt_threads_top_num > TOP_PROCESS_THREADS_NUM_MAX)  {
        log_item_info("process count", false);
        return false;
    }
    log_item_info("process count", true);
    return true;
}

static void set_default_sysfd_config(void)
{
    g_system_monitor_info[SYSTEM_FDCNT].alarm_value = SYSFD_ALARM_VALUE;
    g_system_monitor_info[SYSTEM_FDCNT].resume_value = SYSFD_RESUME_VALUE;
    g_system_monitor_info[SYSTEM_FDCNT].monitor_period = SYSFD_MONITOR_PERIOD;
}

static bool check_sysfd_config(bool parse_ok)
{
    bool ret = false;

    ret = parse_ok && check_config_common(SYSTEM_FDCNT);
    if (ret == false) {
        set_default_sysfd_config();
        log_printf(LOG_INFO, "[error]system fd num monitor: configuration illegal,use default value");
    }
    log_item_info("system fd num", true);
    return true;
}

static const struct config_parse_func g_config_func[SYSTEM_MONITOR_ITEM_CNT] = {
    { "/etc/sysmonitor/cpu", parse_cpu_line, check_cpu_config },
    { "/etc/sysmonitor/memory", parse_mem_line, check_mem_config },
    { "/etc/sysmonitor/pscnt", parse_pscnt_line, check_pscnt_config },
    { "/etc/sysmonitor/sys_fd_conf", parse_sysfd_line, check_sysfd_config }
};

static void parse_sy_resources_config(void)
{
    unsigned int i;
    bool ret = false;

    for (i = 0; i < array_size(g_config_func); i++) {
        if (g_system_monitor_info[i].monitor == false) {
            continue;
        }
        ret = parse_config(g_config_func[i].config_file, g_config_func[i].parse_line_func);
        g_system_monitor_info[i].config_ok = g_config_func[i].check_config(ret);
    }
}

static bool get_single_cpu_stat(cpu_domain *domain, unsigned int cpu)
{
    int ret = 0;
    int tmp_cpu = 0;
    unsigned long long tmp_u, tmp_n, tmp_s, tmp_i, tmp_w, tmp_x, tmp_y, tmp_z;
    char buf[SMLBUFSIZ] = {0};
    char cmd[MAX_TEMPSTR] = {0};

    tmp_u = tmp_n = tmp_s = tmp_i = tmp_w = tmp_x = tmp_y = tmp_z = 0;
    ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "cat /proc/stat | grep -w cpu%u", cpu);
    if (ret < 0) {
        log_printf(LOG_ERR, "get_single_cpu_stat: snprintf_s cmd failed, ret: %d", ret);
        return false;
    }
    ret = monitor_popen(cmd, buf, sizeof(buf) - 1, POPEN_TIMEOUT, NULL);
    if (ret != 0) {
        log_printf(LOG_WARNING, "failed to read CPU %d stats, check cpu state", cpu);
        return false;
    }
    ret = sscanf_s(buf, "cpu%d %llu %llu %llu %llu %llu %llu %llu %llu", &tmp_cpu,
                &tmp_u, &tmp_n, &tmp_s, &tmp_i, &tmp_w, &tmp_x, &tmp_y, &tmp_z);
    if (ret <= 0) {
        log_printf(LOG_WARNING, "failed to read CPU %d stats, check cpu state", cpu);
        return false;
    }

    domain->cpustat.u += tmp_u;
    domain->cpustat.n += tmp_n;
    domain->cpustat.s += tmp_s;
    domain->cpustat.i += tmp_i;
    domain->cpustat.w += tmp_w;
    domain->cpustat.x += tmp_x;
    domain->cpustat.y += tmp_y;
    domain->cpustat.z += tmp_z;
    return true;
}

static bool cpus_refresh_domain(cpu_domain *domain)
{
    unsigned int index, offset, cpu;
    unsigned int nprocs = 0;
    unsigned int num = 0;
    int tmp = get_nprocs_conf();

    domain->cpustat.u = domain->cpustat.n = domain->cpustat.s = domain->cpustat.i = 0;
    domain->cpustat.w = domain->cpustat.x = domain->cpustat.y = domain->cpustat.z = 0;

    if (tmp > 0) {
        nprocs = (unsigned int)tmp;
    }

    for (cpu = 0; cpu < nprocs; cpu++) {
        if (num >= domain->cpu_num) {
            break;
        }

        index = cpu / CHAR_BITS;
        if (index >= DOMAIN_CPU_LEN) {
            break;
        }

        offset = CHAR_BITS - cpu % CHAR_BITS - 1;
        if (!((domain->cpus[index] >> offset) & 1)) {
            continue;
        }

        num++;
        if (get_single_cpu_stat(domain, cpu) == false) {
            domain->broken = true;
            return false;
        }
    }

    domain->broken = false;
    return true;
}

static bool cpus_refresh(str_cpu *cpus)
{
    FILE *fp = NULL;
    int num;
    char buf[SMLBUFSIZ] = {0};

    fp = fopen("/proc/stat", "r");
    if (fp == NULL) {
        log_printf(LOG_ERR, "failed /proc/stat open [%d]", errno);
        return false;
    }

    rewind(fp);
    (void)fflush(fp);

    if (!fgets(buf, sizeof(buf), fp)) {
        log_printf(LOG_ERR, "failed /proc/stat read [%d]", errno);
        (void)fclose(fp);
        return false;
    }
    num = sscanf_s(buf, "cpu %llu %llu %llu %llu %llu %llu %llu %llu",
        &cpus->u, &cpus->n, &cpus->s, &cpus->i, &cpus->w, &cpus->x, &cpus->y, &cpus->z);
    if (num <= 0) {
        log_printf(LOG_INFO, "failed /proc/stat read");
        (void)fclose(fp);
        return false;
    }
    (void)fclose(fp);
    return true;
}

static float get_usage_percent(str_cpu *cpu)
{
    long long u_frme, s_frme, n_frme, i_frme, w_frme, x_frme, y_frme, z_frme, tot_frme, tz;

    u_frme = (long long)(cpu->u - cpu->u_sav);
    s_frme = (long long)(cpu->s - cpu->s_sav);
    n_frme = (long long)(cpu->n - cpu->n_sav);
    i_frme = trimz(cpu->i - cpu->i_sav);
    w_frme = (long long)(cpu->w - cpu->w_sav);
    x_frme = (long long)(cpu->x - cpu->x_sav);
    y_frme = (long long)(cpu->y - cpu->y_sav);
    z_frme = (long long)(cpu->z - cpu->z_sav);
    tot_frme = u_frme + s_frme + n_frme + i_frme + w_frme + x_frme + y_frme + z_frme;
    if (tot_frme < 1) {
        tot_frme = 1;
    }

    /* remember for next time around */
    cpu->u_sav = cpu->u;
    cpu->s_sav = cpu->s;
    cpu->n_sav = cpu->n;
    cpu->i_sav = cpu->i;
    cpu->w_sav = cpu->w;
    cpu->x_sav = cpu->x;
    cpu->y_sav = cpu->y;
    cpu->z_sav = cpu->z;

    return (float)(tot_frme - i_frme) / (float)tot_frme * 100.0;
}

static void handle_cpu_alarm(float usage, bool alarm, const cpu_domain *domain)
{
    char cpu_info[MAX_TEMPSTR];
    if (domain == NULL) {
        snprintf_s(cpu_info, sizeof(cpu_info), sizeof(cpu_info) - 1,
            "CPU usage");
    } else {
        snprintf_s(cpu_info, sizeof(cpu_info), sizeof(cpu_info) - 1,
            "CPU %s usage", domain->desc);
    }

    if (alarm) {
        log_printf(LOG_WARNING, "%s alarm: %4.1f%%", cpu_info, usage);
    } else {
        log_printf(LOG_INFO, "%s resume: %4.1f%%", cpu_info, usage);
    }
}

static void process_cpu_usage(float usage, bool thread_start, cpu_domain *domain)
{
    float alarm;
    float resume;
    bool *status = NULL;
    int ret = 0;

    if (domain == NULL) {
        alarm = g_system_monitor_info[CPU].alarm_value;
        resume = g_system_monitor_info[CPU].resume_value;
        status = &g_system_monitor_info[CPU].status;
    } else {
        alarm = domain->alarm_value;
        resume = domain->resume_value;
        status = &domain->status;
    }

    if (usage >= alarm && *status == false) {
        handle_cpu_alarm(usage, true, domain);
        if (strlen(g_cpu_report_cmd) && g_has_reported_flag == false) {
            ret = monitor_cmd(DEFAULT_USER_ID, g_cpu_report_cmd, REPORT_CMD_TIMEOUT, NULL, false);
            if (ret == 0) {
                log_printf(LOG_INFO, "cpu monitor: execute REPORT_COMMAND[%s] successfully", g_cpu_report_cmd);
            } else {
                log_printf(LOG_ERR, "cpu monitor: execute REPORT_COMMAND[%s] failed", g_cpu_report_cmd);
            }
            g_has_reported_flag = true;
        }
        *status = true;
    } else if ((usage <= resume && *status == true) || (usage <= resume && thread_start)) {
        handle_cpu_alarm(usage, false, domain);
        *status = false;
    }
}

static void process_domain_cpustat_first(void)
{
    cpu_domain *t = NULL;

    for (t = g_domain_head; t != NULL; t = t->next) {
        if (!cpus_refresh_domain(t)) {
            continue;
        }
        (void)get_usage_percent(&t->cpustat);
        t->first_collected = true;
    }
    g_monitor_domain_flag = true;
}

static void process_domain_cpustat_second(bool thread_start)
{
    float usage;
    cpu_domain *t = NULL;

    for (t = g_domain_head; t != NULL; t = t->next) {
        if (t->broken || !cpus_refresh_domain(t)) {
            t->first_collected = false;
            log_printf(LOG_WARNING, "skip monitor on CPU %s", t->desc);
            continue;
        }
        /* skip if cpustat not collected in the first refresh */
        if (t->first_collected == false) {
            continue;
        }

        t->first_collected = false;
        usage = get_usage_percent(&t->cpustat);
        process_cpu_usage(usage, thread_start, t);
    }
}

static bool process_global_cpustat_first(str_cpu *cpus)
{
    int ret = 0;

    g_monitor_domain_flag = false;
    ret = memset_s(cpus, sizeof(str_cpu), 0, sizeof(str_cpu));
    if (ret != 0) {
        log_printf(LOG_ERR, "process_global_cpustat_first: memset_s cpus failed, ret: %d", ret);
        return false;
    }
    if (!cpus_refresh(cpus)) {
        return false;
    }
    (void)get_usage_percent(cpus);
    return true;
}

static bool process_global_cpustat_second(str_cpu *cpus, bool thread_start)
{
    float usage;

    if (!cpus_refresh(cpus)) {
        return false;
    }
    usage = get_usage_percent(cpus);
    process_cpu_usage(usage, thread_start, NULL);
    return true;
}

static void monitor_cpu(void)
{
    static bool thread_start = true;
    static unsigned int stat_count = 0;
    static str_cpu cpus = {0};

    /* when monitor mode changes, make sure go into first refresh */
    if ((g_monitor_domain_flag == true && g_domain_head == NULL) ||
        (g_monitor_domain_flag == false && g_domain_head != NULL)) {
        stat_count = 0;
    }

    /* first refresh cpustat */
    if (stat_count == 0) {
        if (g_domain_head != NULL) {
            process_domain_cpustat_first();
        } else {
            if (process_global_cpustat_first(&cpus) == false) {
                return;
            }
        }
    }

    if ((stat_count++) * g_sys_res_period < g_system_monitor_info[CPU].stat_period) {
        return;
    }
    stat_count = 0;

    /* second refresh cpustat and get usage */
    if (g_domain_head != NULL) {
        process_domain_cpustat_second(thread_start);
    } else {
        if (process_global_cpustat_second(&cpus, thread_start) == false) {
            return;
        }
    }
    thread_start = false;
    g_has_reported_flag = false;
}

struct mem_info_table {
    const char *name;
    unsigned long *count;
};

static struct mem_info_table g_meminfo_table[] = {
    { "Buffers", &g_mem_info.buffers },
    { "Cached", &g_mem_info.cached },
    { "MemFree", &g_mem_info.free },
    { "MemTotal",  &g_mem_info.total },
    { "SReclaimable", &g_mem_info.sreclaimable },
    { "Shmem",  &g_mem_info.shmem }
};

static int compare_mem_table_structs(const void *a, const void *b)
{
    return strcmp(((const struct mem_info_table*)a)->name, ((const struct mem_info_table*)b)->name);
}

static int get_mem_info(void)
{
    int fd = -1;
    char out_buf[MEM_INFO_BUFFER] = {0};
    char namebuf[ITEM_LEN];
    char *head = NULL;
    char *tail = NULL;
    struct mem_info_table *found = NULL;
    struct mem_info_table findme = { namebuf, NULL };
    int ret;
    ssize_t read_ret;

    fd = open("/proc/meminfo", O_RDONLY);
    if (fd == -1) {
        log_printf(LOG_ERR, "get_mem_info: open /proc/meminfo failed, errno[%d]", errno);
        return -1;
    }

    (void)lseek(fd, 0, SEEK_SET);

    read_ret = read(fd, out_buf, sizeof(out_buf) - 1);
    if (read_ret < 0) {
        log_printf(LOG_ERR, "get_mem_info: read /proc/meminfo failed, rrno[%d]", errno);
        (void)close(fd);
        return -1;
    }
    out_buf[read_ret] = '\0';

    head = out_buf;
    for (;;) {
        tail = strchr(head, ':');
        if (tail == NULL) {
            break;
        }
        *tail = '\0';
        if (strlen(head) > sizeof(namebuf)) {
            head = tail + 1;
            goto nextline;
        }
        ret = strcpy_s(namebuf, sizeof(namebuf) - 1, head);
        if (ret != 0) {
            log_printf(LOG_ERR, "get_mem_info: strcpy_s namebuf failed, errno[%d]", errno);
            (void)close(fd);
            return -1;
        }
        found = bsearch(&findme, g_meminfo_table, array_size(g_meminfo_table),
            sizeof(struct mem_info_table), compare_mem_table_structs);
        head = tail + 1;
        if (found != NULL) {
            *(found->count) = (unsigned long)strtoull(head, &tail, STRTOULL_NUMBER_BASE);
        }
nextline:
        tail = strchr(head, '\n');
        if (tail == NULL) {
            break;
        }
        head = tail + 1;
    }

    if (fd >= 0) {
        (void)close(fd);
    }
    return 0;
}

static void sysrq_show_memory_info(void)
{
    int ret;
    char cmd[MAX_CONFIG] = {0};

    ret = snprintf_s(cmd, MAX_CONFIG, MAX_CONFIG - 1, "echo m > %s", PROC_SYSRQ_TRIGGER);
    if (ret == -1) {
        log_printf(LOG_ERR, "sysrq_show_memory_info: snprintf_s failed");
        return;
    }

    ret = monitor_cmd(DEFAULT_USER_ID, cmd, POPEN_TIMEOUT, NULL, true);
    if (ret != 0) {
        log_printf(LOG_ERR, "sysrq_show_memory_info: monitor_cmd failed");
        return;
    }
    log_printf(LOG_INFO, "sysrq show memory info in message.");
}

static void show_memory_info(void)
{
    FILE *fp = NULL;
    char buf[MAX_CONFIG] = {0};

    fp = fopen("/proc/meminfo", "r");
    if (fp == NULL) {
        log_printf(LOG_ERR, "show_memory_info: fopen /proc/meminfo error [%d]", errno);
        return;
    }
    log_printf(LOG_INFO, "---------------show /proc/meminfo: ---------------");
    while (fgets(buf, MAX_CONFIG - 1, fp)) {
        log_printf(LOG_INFO, "%s", buf);
    }

    (void)fclose(fp);
    log_printf(LOG_INFO, "---------------show_memory_info end.---------------");
}

static void handle_memory_alarm(float usage, bool alarm)
{

    if (alarm) {
        log_printf(LOG_INFO, "memory usage alarm: %4.1f%%", usage);
    } else {
        log_printf(LOG_INFO, "memory usage resume: %4.1f%%", usage);
    }

    if (alarm) {
        show_memory_info();
        sysrq_show_memory_info();
    }
}

static void handle_memory_usage(float usage, bool thread_start)
{
    if (usage >= g_system_monitor_info[MEM].alarm_value && g_system_monitor_info[MEM].status == false) {
        handle_memory_alarm(usage, true);
        g_system_monitor_info[MEM].status = true;
    } else if ((usage <= g_system_monitor_info[MEM].resume_value && g_system_monitor_info[MEM].status == true) ||
               (usage <= g_system_monitor_info[MEM].resume_value && thread_start)) {
        handle_memory_alarm(usage, false);
        g_system_monitor_info[MEM].status = false;
    }
}

/*
 * memory usage monitor
 * get three times of usage and calculate average usage
 */
static void monitor_memory(void)
{
    static float usage = 0.0;
    static int times = 0;
    static bool thread_start = true;
    int ret;

    ret = memset_s(&g_mem_info, sizeof(struct mem_info), 0, sizeof(struct mem_info));
    if (ret != 0) {
        log_printf(LOG_ERR, "memset_s meminfo failed, ret: %d", ret);
        return;
    }

    ret = get_mem_info();
    if (ret != 0) {
        return;
    }

    if (g_mem_info.total == 0) {
        log_printf(LOG_INFO, "get total memory failed.");
        return;
    }

    usage += (float)(g_mem_info.total - g_mem_info.free - g_mem_info.cached -
        g_mem_info.sreclaimable - g_mem_info.buffers + g_mem_info.shmem) * 100 / (float)g_mem_info.total;

    times++;
    if (times < MEM_STAT_TIMES) {
        return;
    }
    usage /= MEM_STAT_TIMES;
    times = 0;

    handle_memory_usage(usage, thread_start);
    thread_start = false;
    usage = 0.0;
}

static int get_item_from_proc_file(const char *file, unsigned long *result)
{
    char cnt_buf[MAX_TEMPSTR] = {0};
    FILE *fp = NULL;

    fp = fopen(file, "r");
    if (fp == NULL) {
        log_printf(LOG_ERR, "open %s failed, errno[%d]", file, errno);
        return -1;
    }

    rewind(fp);
    (void)fflush(fp);

    if (fgets(cnt_buf, sizeof(cnt_buf), fp) == NULL) {
        (void)fclose(fp);
        log_printf(LOG_ERR, "read %s failed", file);
        return -1;
    }

    *result = strtoul(cnt_buf, NULL, 0);
    (void)fclose(fp);
    return 0;
}

static unsigned long get_process_use_threads_cnt(const char *dir)
{
    DIR *dir_tmp = NULL;
    struct dirent *direntp = NULL;
    unsigned long num = 0;
    struct stat sb;

    if (stat(dir, &sb) < 0) {
        return 0;
    }
    if (!S_ISDIR(sb.st_mode)) {
        return 0;
    }

    /* if dno't monitor threads, return 1 for counting process num */
    if (g_pscnt_threads_top_num == 0) {
        return PSCNT_COUNT_FOR_PROCESS;
    }

    dir_tmp = opendir(dir);
    if (dir_tmp == NULL) {
        return 0;
    }

    for (;;) {
        direntp = readdir(dir_tmp);
        if (direntp == NULL) {
            break;
        }
        /* check int to exclude directory . and .. */
        if (check_int(direntp->d_name) == false) {
            continue;
        }
        num++;
    }
    (void)closedir(dir_tmp);
    return num;
}

/*
 * create for g_top_process_threads by size size, and free by using free_top_process_threads
 */
static void create_top_process_threads(unsigned int size)
{
    int ret;

    /* no need to maloc repeatedly */
    if (!g_pscnt_threads_create_flag) {
        return;
    }
    if (g_top_process_threads != NULL) {
        log_printf(LOG_ERR, "top process threads g_top_process_threads is not null, so return.");
        return;
    }

    if (size == 0 || size > TOP_PROCESS_THREADS_NUM_MAX) {
        log_printf(LOG_ERR, "create top process threads size %d is error.", size);
        return;
    }

    g_top_process_threads = malloc(sizeof(ps_threads_info) * size);
    if (g_top_process_threads == NULL) {
        log_printf(LOG_ERR, "top process threads malloc error.");
        return;
    }
    ret = memset_s(g_top_process_threads, sizeof(ps_threads_info) * size, 0, sizeof(ps_threads_info) * size);
    if (ret != 0) {
        log_printf(LOG_ERR, "top process threads memset_s error.");
        free(g_top_process_threads);
        g_top_process_threads = NULL;
        return;
    }
    g_pscnt_threads_create_flag = false;
    return;
}

static void get_top_process_threads(const char *pid, unsigned long num,
    unsigned int process_threads_num)
{
    int ret;
    unsigned int i;
    unsigned int j;
    size_t len;

    create_top_process_threads(g_pscnt_threads_top_num);
    if (g_top_process_threads == NULL) {
        log_printf(LOG_ERR, "get top process threads is null.");
        return;
    }

    if (process_threads_num < 1) {
        log_printf(LOG_ERR, "process_threads_num %u is error.", process_threads_num);
        return;
    }

    if (num < g_top_process_threads[process_threads_num - 1].num) {
        return;
    }

    ps_threads_info info;
    ret = memset_s(&info, sizeof(info), 0, sizeof(info));
    if (ret != 0) {
        log_printf(LOG_ERR, "get top process threads memset_s error [%d]", ret);
        return;
    }
    len = sizeof(info.cmd);
    get_ps_cmd(info.cmd, pid, len);
    info.num = num;
    ret = strcpy_s(info.pid, sizeof(info.pid) - 1, pid);
    if (ret != 0) {
        log_printf(LOG_ERR, "get top process threads strcpy_s error [%d]", ret);
        return;
    }

    for (i = 0; i < process_threads_num; ++i) {
        if (info.num > g_top_process_threads[i].num) {
            for (j = process_threads_num - 1; j > i; --j) {
                g_top_process_threads[j] = g_top_process_threads[j - 1];
            }
            g_top_process_threads[i] = info;
            break;
        }
    }
}

static int get_threads_for_count(const char *name, bool get_top_flag, unsigned long *count_threads_tmp)
{
    unsigned long count_threads;
    char path[MAX_TEMPSTR] = {0};
    int ret;

    ret = snprintf_s(path, MAX_TEMPSTR, MAX_TEMPSTR - 1, "/proc/%s/task", name);
    if (ret == -1) {
        log_printf(LOG_ERR, "get threads: snprintf_s path failed, errno: %d", errno);
        return PSCNT_RET_ERROR;
    }

    count_threads = get_process_use_threads_cnt(path);
    if (count_threads == 0) {
        return PSCNT_RET_CONTINUE;
    }

    if (get_top_flag) {
        get_top_process_threads(name, count_threads, g_pscnt_threads_top_num);
    }

    *count_threads_tmp = count_threads;
    return PSCNT_RET_TRUE;
}

/*
 * get process count and threads count from /proc/xxx/task/
 * read /proc/xxx/task/ count for process count and count for dir, which name is number for threads count
 */
static int get_process_and_threads_count(unsigned long *result_process, unsigned long *result_threads,
    bool get_top_threads_flag)
{
    struct dirent *direntp = NULL;
    DIR *dir = NULL;
    unsigned long count_process = 0;
    unsigned long count_threads_sum = 0;
    unsigned long count_threads_tmp = 0;
    int ret;

    dir = opendir("/proc");
    if (dir == NULL) {
        log_printf(LOG_ERR, "open /proc failed");
        return -1;
    }

    for (;;) {
        direntp = readdir(dir);
        if (direntp == NULL) {
            break;
        }
        if (check_int(direntp->d_name) == false) {
            continue;
        }

        ret = get_threads_for_count(direntp->d_name, get_top_threads_flag, &count_threads_tmp);
        if (ret == PSCNT_RET_ERROR) {
            (void)closedir(dir);
            return -1;
        } else if (ret == PSCNT_RET_CONTINUE) {
            continue;
        } else {
            count_threads_sum += count_threads_tmp;
            /* calculate process count when get threads return true */
            count_process++;
        }
    }
    *result_process = count_process;
    *result_threads = count_threads_sum;
    (void)closedir(dir);
    return 0;
}

static void update_alarm_value(unsigned long cnt_max, unsigned long *alarm, float set_alarm_value,
    float alarm_ratio)
{
    float alarm_value = (float)cnt_max * alarm_ratio / RATIO;

    if (set_alarm_value >= alarm_value) {
        *alarm = (unsigned long)set_alarm_value;
    } else {
        *alarm = (unsigned long)alarm_value;
    }
}

static void update_resume_value(unsigned long cnt_max, unsigned long *resume, float set_resume_value,
    float resume_ratio)
{
    float resume_value = (float)cnt_max * resume_ratio / RATIO;

    if (set_resume_value >= resume_value) {
        *resume = (unsigned long)set_resume_value;
    } else {
        *resume = (unsigned long)resume_value;
    }
}

static void handle_pscnt_and_threads_alarm(unsigned long cnt, bool alarm, const char *str, unsigned short alarmid)
{
    if (alarm) {
        log_printf(LOG_WARNING, "%s alarm: %lu", str, cnt);
    } else {
        log_printf(LOG_INFO, "%s resume: %lu", str, cnt);
    }
}

static void ps_show_sysfd_info(const char *alarm_msg)
{
    unsigned long cnt = 0;
    unsigned long max_fd_num = 0;
    int ret;

    ret = get_file_nr(&cnt, &max_fd_num);
    if (ret != 0 || cnt == 0 || max_fd_num == 0) {
        return;
    }

    log_printf(LOG_INFO, "%s, show sys fd count: %lu", alarm_msg, cnt);
}

static void ps_show_mem_info(const char *alarm_msg)
{
    log_printf(LOG_INFO, "%s, show mem info", alarm_msg);
    show_memory_info();
}

static void process_pscnt_usage(unsigned long cnt, unsigned long alarm, unsigned long resume, bool thread_start)
{
    if (cnt >= alarm && g_system_monitor_info[PSCNT].status == false) {
        log_printf(LOG_INFO, "---------------process count alarm start: ---------------");
        handle_pscnt_and_threads_alarm(cnt, true, "process count", PSCNT_ABNORMAL);
        ps_show_sysfd_info("process count alarm");
        ps_show_mem_info("process count alarm");
        log_printf(LOG_INFO, "---------------process count alarm end. ---------------");
        g_system_monitor_info[PSCNT].status = true;
    } else if ((cnt <= resume && g_system_monitor_info[PSCNT].status == true) ||
               (cnt <= resume && thread_start)) {
        handle_pscnt_and_threads_alarm(cnt, false, "process count", PSCNT_ABNORMAL);
        g_system_monitor_info[PSCNT].status = false;
    }
}

static void free_top_process_threads(void)
{
    if (g_top_process_threads != NULL) {
        free(g_top_process_threads);
        g_top_process_threads = NULL;
        g_pscnt_threads_create_flag = true;
    }
}


static void print_top_threads(unsigned int process_threads_num)
{
    unsigned int i;
    int ret;
    char tmp_buf[FD_TMP_BUF + 1] = {0};
    unsigned int zero_num = 0;
    unsigned int print_num = 0;
    if (g_top_process_threads == NULL) {
        log_printf(LOG_ERR, "print top threads is null.");
        return;
    }

    for (i = 0; i < process_threads_num; i++) {
        ret = memset_s(tmp_buf, sizeof(tmp_buf), 0, sizeof(tmp_buf));
        if (ret != 0) {
            log_printf(LOG_ERR, "print top threads memset_s error [%d]", ret);
            continue;
        }
        /* if top process num in config is bigger than process num on device, need to ignore useless processes count */
        if (g_top_process_threads[i].num == 0) {
            zero_num++;
            continue;
        }
        ret = snprintf_s(tmp_buf, sizeof(tmp_buf), sizeof(tmp_buf) - 1,
            "open threads most %u processes is:[top%u:pid=%s,openthreadsnum=%lu,cmd=%s]",
            process_threads_num, i + 1, g_top_process_threads[i].pid, g_top_process_threads[i].num,
            g_top_process_threads[i].cmd);
        if (ret < 0) {
            log_printf(LOG_ERR, "print top threads snprintf_s error [%d]", ret);
            continue;
        }
        print_num++;
        log_printf(LOG_INFO, "%s", tmp_buf);
    }

    if (zero_num > 0) {
        log_printf(LOG_INFO, "print top threads: total set num:%u, actual print num:%u, ignore useless num:%u.",
            process_threads_num, print_num, zero_num);
    }
}

/* print top threads info, and free g_pscnt_threads_top_num after print */
static void print_threads_info(void)
{
    print_top_threads(g_pscnt_threads_top_num);
    free_top_process_threads();
}

static void ps_show_process_cnt(unsigned long cnt_process)
{
    log_printf(LOG_INFO, "threads count alarm, show process count %lu", cnt_process);
}
static void ps_threads_usage(unsigned long cnt, unsigned long alarm, unsigned long resume, bool thread_start_flag)
{
    int ret;
    unsigned long cnt_process = 0;
    unsigned long cnt_threads = 0;

    if (cnt >= alarm && g_pscnt_threads_status_flag == false) {
        log_printf(LOG_INFO, "---------------threads count alarm start: ---------------");
        handle_pscnt_and_threads_alarm(cnt, true, "threads count", PS_THREADS_ABNORMAL);
        /* get and print threads alarm info */
        ret = get_process_and_threads_count(&cnt_process, &cnt_threads, true);
        if (ret < 0 || cnt_process == 0 || cnt_threads == 0) {
            log_printf(LOG_ERR, "ps threads usage error return ret:%d, cnt_process:%lu, cnt_threads:%lu",
                ret, cnt_process, cnt_threads);
            return;
        }
        print_threads_info();
        ps_show_process_cnt(cnt_process);
        ps_show_sysfd_info("threads count alarm");
        ps_show_mem_info("threads count alarm");
        log_printf(LOG_INFO, "---------------threads count alarm end. ---------------");
        g_pscnt_threads_status_flag = true;
    } else if ((cnt <= resume && g_pscnt_threads_status_flag == true) ||
               (cnt <= resume && thread_start_flag)) {
        handle_pscnt_and_threads_alarm(cnt, false, "threads count", PS_THREADS_ABNORMAL);
        g_pscnt_threads_status_flag = false;
    }
}

static void monitor_threads_cnt(unsigned long cnt_threads)
{
    unsigned long cnt_threads_max = 0;
    unsigned long threads_alarm_bigger;
    unsigned long threads_resume_bigger;
    int ret;
    static bool thread_start_flag = true;

    ret = get_item_from_proc_file("/proc/sys/kernel/threads-max", &cnt_threads_max);
    if (ret < 0 || cnt_threads_max == 0) {
        log_printf(LOG_ERR, "monitor threads cnt: get file error ret: %d, cnt_threads_max:%lu.", ret, cnt_threads_max);
        return;
    }
    update_alarm_value(cnt_threads_max, &threads_alarm_bigger, g_system_monitor_info[PSCNT].alarm_value,
        g_pscnt_alarm_ratio);
    update_resume_value(cnt_threads_max, &threads_resume_bigger, g_system_monitor_info[PSCNT].resume_value,
        g_pscnt_resume_ratio);
    ps_threads_usage(cnt_threads, threads_alarm_bigger, threads_resume_bigger, thread_start_flag);
    thread_start_flag = false;
}

static void monitor_pscnt(void)
{
    static bool thread_start = true;
    unsigned long cnt_process = 0;
    unsigned long cnt_threads = 0;
    unsigned long cnt_max = 0;
    unsigned long alarm_bigger;
    unsigned long resume_bigger;
    int ret;

    ret = get_process_and_threads_count(&cnt_process, &cnt_threads, false);
    if (ret < 0 || cnt_process == 0 || cnt_threads == 0) {
        return;
    }

    ret = get_item_from_proc_file("/proc/sys/kernel/pid_max", &cnt_max);
    if (ret < 0 || cnt_max == 0) {
        return;
    }

    update_alarm_value(cnt_max, &alarm_bigger, g_system_monitor_info[PSCNT].alarm_value,
        g_pscnt_alarm_ratio);
    update_resume_value(cnt_max, &resume_bigger, g_system_monitor_info[PSCNT].resume_value,
        g_pscnt_resume_ratio);
    process_pscnt_usage(cnt_process, alarm_bigger, resume_bigger, thread_start);
    thread_start = false;
    /* monitor for threads cnt */
    if (g_pscnt_threads_top_num != 0) {
        monitor_threads_cnt(cnt_threads);
    }
}

static unsigned long get_dirfilenum(const char *dir)
{
    DIR *dp = NULL;
    struct dirent *entry = NULL;
    struct stat statbuf;
    unsigned long num = 0;
    int ret;
    char tmp_path[FD_PATH_MAX + 1] = {0};

    ret = memset_s(&statbuf, sizeof(statbuf), 0, sizeof(statbuf));
    if (ret != 0) {
        log_printf(LOG_ERR, "get_dirfilenum: memset_s statbuf failed, ret: %d.", ret);
        return 0;
    }

    dp = opendir(dir);
    if (dp == NULL) {
        return 0;
    }

    for (;;) {
        entry = readdir(dp);
        if (entry == NULL) {
            break;
        }

        if (entry->d_type == DT_DIR) {
            ret = memset_s(tmp_path, sizeof(tmp_path), 0, sizeof(tmp_path));
            if (ret != 0) {
                log_printf(LOG_ERR, "monitor_io_delay memset_s error [%d]", ret);
                break;
            }
            ret = snprintf_s(tmp_path, sizeof(tmp_path), sizeof(tmp_path) - 1, "%s/%s", dir, entry->d_name);
            if (ret < 0) {
                log_printf(LOG_ERR, "monitor_io_delay snprintf_s error [%d]", ret);
                break;
            }
            continue;
        }

        num++;
    }
    (void)closedir(dp);
    return num;
}

static void get_ps_cmd(char *cmd, const char *pid, size_t cmd_len)
{
    char cmd_line[PS_CMD_MAX + 1] = { 0 };
    int fd = -1;
    char cmd_file[FD_PATH_MAX + 1] = { 0 };
    ssize_t len;
    int ret;

    ret = snprintf_s(cmd_file, sizeof(cmd_file), sizeof(cmd_file) - 1, "/proc/%s/cmdline", pid);
    if (ret < 0) {
        log_printf(LOG_ERR, "get_ps_cmd snprintf_s error [%d]", ret);
        return;
    }
    fd = open(cmd_file, O_RDONLY);
    if (fd < 0) {
        log_printf(LOG_ERR, "can't open %s", cmd_file);
        return;
    }

    len = read(fd, cmd_line, PS_CMD_MAX);
    if (len == -1) {
        log_printf(LOG_ERR, "get cmd from file [%s] failed", cmd_file);
        (void)close(fd);
        return;
    }

    while (len > 0) {
        if (((unsigned char)cmd_line[len - 1]) < ' ') {
            cmd_line[len - 1] = ' ';
        }
        len--;
    }
    (void)close(fd);
    cmd_line[PS_CMD_MAX] = '\0';
    ret = memset_s(cmd, cmd_len, '\0', cmd_len);
    if (ret != 0) {
        log_printf(LOG_ERR, "get_ps_cmd memset_s error [%d]", ret);
        return;
    }
    ret = memcpy_s(cmd, cmd_len, cmd_line, strlen(cmd_line));
    if (ret != 0) {
        log_printf(LOG_ERR, "get_ps_cmd memcpy_s error [%d]", ret);
    }
}

static void get_top_fd_info(ps_fd_info *top_fd, const char *pid, unsigned long num)
{
    int ret;
    int i, j;
    size_t len;
    ps_fd_info ps_info;

    ret = memset_s(&ps_info, sizeof(ps_info), 0, sizeof(ps_info));
    if (ret != 0) {
        log_printf(LOG_ERR, "get_top_fd_info memset_s error [%d]", ret);
        return;
    }
    len = sizeof(ps_info.cmd);
    get_ps_cmd(ps_info.cmd, pid, len);
    ps_info.num = num;
    ret = strcpy_s(ps_info.pid, sizeof(ps_info.pid) - 1, pid);
    if (ret != 0) {
        log_printf(LOG_ERR, "get_top_fd_info strcpy_s error [%d]", ret);
        return;
    }

    /* update top 3 processes list */
    if (ps_info.num < top_fd[TOPFD_PROCESS_NUM - 1].num) {
        return;
    }
    for (i = 0; i < TOPFD_PROCESS_NUM; ++i) {
        if (ps_info.num > top_fd[i].num) {
            for (j = TOPFD_PROCESS_NUM - 1; j > i; --j) {
                top_fd[j] = top_fd[j - 1];
            }
            top_fd[i] = ps_info;
            break;
        }
    }
}

static void print_processes(const ps_fd_info top_fd[], unsigned int process_num)
{
    unsigned int i;
    int ret;
    char tmp_buf[FD_TMP_BUF + 1] = {0};

    for (i = 0; i < process_num; i++) {
        ret = memset_s(tmp_buf, sizeof(tmp_buf), 0, sizeof(tmp_buf));
        if (ret != 0) {
            log_printf(LOG_ERR, "get_maxfd_process_info memset_s error [%d]", ret);
            continue;
        }
        ret = snprintf_s(tmp_buf, sizeof(tmp_buf), sizeof(tmp_buf) - 1,
            "open fd most three processes is:[top%u:pid=%s,openfdnum=%lu,cmd=%s]",
            i + 1, top_fd[i].pid, top_fd[i].num, top_fd[i].cmd);
        if (ret < 0) {
            log_printf(LOG_ERR, "get_maxfd_process_info snprintf_s error [%d]", ret);
            continue;
        }
        log_printf(LOG_INFO, "%s", tmp_buf);
    }
}

static void get_maxfd_process_info(void)
{
    DIR *dp = NULL;
    struct dirent *dirp = NULL;
    unsigned long num;
    size_t i, len;
    char fd_dir[FD_BUF_LEN] = {0};
    ps_fd_info top_fd[TOPFD_PROCESS_NUM] = {0};
    int ret;

    dp = opendir("/proc");
    if (dp == NULL) {
        log_printf(LOG_ERR, "dir [/proc] not exist,failed to get open fd most three processes");
        return;
    }
    for (;;) {
        dirp = readdir(dp);
        if (dirp == NULL) {
            break;
        }

        if (dirp->d_type != DT_DIR) {
            continue;
        }

        len = strlen(dirp->d_name);
        for (i = 0; dirp->d_name[i] != 0; ++i) {
            if (!isdigit(dirp->d_name[i])) {
                break;
            }
        }

        if (len == i) {
            ret = memset_s(fd_dir, sizeof(fd_dir), 0, sizeof(fd_dir));
            if (ret != 0) {
                log_printf(LOG_ERR, "get_maxfd_process_info memset_s error [%d]", ret);
                continue;
            }
            ret = snprintf_s(fd_dir, sizeof(fd_dir), sizeof(fd_dir) - 1, "/proc/%s/fd", dirp->d_name);
            if (ret < 0) {
                log_printf(LOG_ERR, "get_maxfd_process_info snprintf_s error [%d]", ret);
                continue;
            }
            num = get_dirfilenum(fd_dir);
            if (num == 0) {
                continue;
            }
            get_top_fd_info(top_fd, dirp->d_name, num);
        }
    }

    print_processes(top_fd, TOPFD_PROCESS_NUM);
    (void)closedir(dp);
}

static int get_file_nr(unsigned long *file_nr, unsigned long *file_max)
{
    char file[MAX_TEMPSTR] = "/proc/sys/fs/file-nr";
    char cnt_buf[MAX_TEMPSTR] = {0};
    FILE *fp = NULL;
    unsigned long nr_files = 0;
    unsigned long nr_free_files;
    unsigned long max_files = 0;
    int ret;

    fp = fopen(file, "r");
    if (fp == NULL) {
        log_printf(LOG_ERR, "open %s failed, errno: %d", file, errno);
        return -1;
    }

    rewind(fp);
    (void)fflush(fp);

    if (fgets(cnt_buf, sizeof(cnt_buf), fp) == NULL) {
        log_printf(LOG_ERR, "read %s failed", file);
        (void)fclose(fp);
        return -1;
    }

    ret = sscanf_s(cnt_buf, "%lu %lu %lu", &nr_files, &nr_free_files, &max_files);
    if (ret <= 0) {
        log_printf(LOG_INFO, "parse %s failed", file);
        (void)fclose(fp);
        return -1;
    }

    *file_nr = nr_files;
    *file_max = max_files;
    (void)fclose(fp);
    return 0;
}

static void handle_sysfd_alarm(unsigned long cnt, bool alarm, unsigned long max_fd)
{
    unsigned long alarm_value;
    unsigned long resume_value;

    alarm_value = (unsigned long)(g_system_monitor_info[SYSTEM_FDCNT].alarm_value / 100 * max_fd);
    resume_value = (unsigned long)(g_system_monitor_info[SYSTEM_FDCNT].resume_value / 100 * max_fd);

    if (alarm) {
        log_printf(LOG_INFO, "sys fd count alarm: %lu (alarm: %lu, resume: %lu)",
            cnt, alarm_value, resume_value);
    } else {
        log_printf(LOG_INFO, "sys fd count resume: %lu (alarm: %lu, resume: %lu)",
            cnt, alarm_value, resume_value);
    }
}

static void monitor_sysfd(void)
{
    unsigned long cnt = 0;
    unsigned long max_fd_num = 0;
    float usage;
    int ret;

    ret = get_file_nr(&cnt, &max_fd_num);
    if (ret != 0 || cnt == 0 || max_fd_num == 0) {
        return;
    }

    usage = (float)((float)cnt * 100 / (float)max_fd_num);

    if (usage >= g_system_monitor_info[SYSTEM_FDCNT].alarm_value &&
        (g_system_monitor_info[SYSTEM_FDCNT].status == false)) {
        handle_sysfd_alarm(cnt, true, max_fd_num);
        g_system_monitor_info[SYSTEM_FDCNT].status = true;
        get_maxfd_process_info();
    }
    if ((usage < g_system_monitor_info[SYSTEM_FDCNT].resume_value) &&
        (g_system_monitor_info[SYSTEM_FDCNT].status == true)) {
        handle_sysfd_alarm(cnt, false, max_fd_num);
        g_system_monitor_info[SYSTEM_FDCNT].status = false;
    }
}

/*
 * monitor item, if config_ok, exec monitor_func
 * for system_fdnum, if config_ok = false, use default config
 * we calculate monitor sleep period according to item monitor period and cpu stat period
 * monitor_count is default to -1, this will call monitor_func at the thread startup
 */
static void monitor_item(void)
{
    int i;

    for (i = 0; i < SYSTEM_MONITOR_ITEM_CNT; i++) {
        if (g_system_monitor_info[i].monitor == false || g_system_monitor_info[i].config_ok == false) {
            continue;
        }

        g_system_monitor_info[i].monitor_count++;

        if (g_system_monitor_info[i].monitor_count == 0) {
            goto exec_monitor;
        }

        if (((unsigned int)g_system_monitor_info[i].monitor_count * g_sys_res_period <
            g_system_monitor_info[i].monitor_period)) {
            if (i == CPU &&
                (unsigned int)g_system_monitor_info[i].monitor_count * g_sys_res_period >=
                g_system_monitor_info[i].stat_period) {
                goto exec_monitor;
            }
            continue;
        }
exec_monitor:
        g_system_monitor_info[i].monitor_func();
        g_system_monitor_info[i].monitor_count = 0;
    }
}

/*
 * Maximum common divisor
 */
static unsigned int get_common_divisor(unsigned int a, unsigned int b)
{
    while (a != b) {
        if (a > b) {
            a = a - b;
        } else {
            b = b - a;
        }
    }
    return a;
}

/*
 * get system resource monitor period
 * the period is refer to cpu, memory, system-fd and pscnt monitor period config
 * also this period is refer to cpu stat period
 */
static void get_sys_res_period(void)
{
    int i;
    int j = 0;
    unsigned int array_period[SYSTEM_MONITOR_ITEM_CNT + 1] = {0};
    unsigned int temp;
    int ret;

    g_sys_res_period = SYS_RES_MONITOR_PERIOD_MIN;

    for (i = 0; i < SYSTEM_MONITOR_ITEM_CNT; i++) {
        if (g_system_monitor_info[i].monitor && g_system_monitor_info[i].config_ok) {
            array_period[j++] = g_system_monitor_info[i].monitor_period;
        }
    }

    if (g_system_monitor_info[CPU].monitor && g_system_monitor_info[CPU].config_ok) {
        array_period[j++] = g_system_monitor_info[CPU].stat_period;
    }

    if (j == 0) {
        log_printf(LOG_INFO, "calculate for g_sys_res_period failed, use default %d", SYS_RES_MONITOR_PERIOD_MIN);
        return;
    }

    temp = array_period[0];
    for (i = 1; i < j; i++) {
        temp = get_common_divisor(temp, array_period[i]);
    }

    g_sys_res_period = temp;
    log_printf(LOG_INFO, "system resource monitor period: %u", g_sys_res_period);

    /* increase monitor thread period or sysmonitor will be restarted during report_cmd execution */
    if (strlen(g_cpu_report_cmd)) {
        temp += REPORT_CMD_TIMEOUT;
    }
    ret = set_thread_status_period(THREAD_SYSTEM_ITEM, temp);
    if (ret == -1) {
        log_printf(LOG_ERR, "system resource monitor set period error");
        return;
    }
}

static void *sys_resources_monitor_start(void *arg)
{
    bool reload_flag = false;
    int ret;

    (void)prctl(PR_SET_NAME, "monitor-sysres");
    log_printf(LOG_INFO, "system resources monitor starting up");

    for (;;) {
        reload_flag = get_thread_item_reload_flag(SYSTEM_ITEM);
        if (reload_flag) {
            log_printf(LOG_INFO, "system resource monitor, start reload");
            (void)clear_report_cmd();
            parse_sy_resources_config();

            /* refresh monitor sleep period */
            get_sys_res_period();
            /* free g_top_process_threads when reload config for new malloc size */
            free_top_process_threads();
            /* free g_domain_head and set new domain list */
            free_set_domain_head();
            set_thread_item_reload_flag(SYSTEM_ITEM, false);
            clear_thread_status(THREAD_SYSTEM_ITEM);
            ret = set_thread_status_check_flag(THREAD_SYSTEM_ITEM, true);
            if (ret == -1) {
                log_printf(LOG_ERR, "system resource monitor set check flag error");
                break;
            }
        }

        monitor_item();
        ret = feed_thread_status_count(THREAD_SYSTEM_ITEM);
        if (ret == -1) {
            log_printf(LOG_ERR, "system resource monitor feed error");
            break;
        }
        (void)sleep(g_sys_res_period);
    }

    return NULL;
}

bool sys_resources_monitor_parse(const char *item, const char *value, int type, bool monitor)
{
    return parse_value_bool(item, value,
        monitor ? &g_system_monitor_info[type].monitor : &g_system_monitor_info[type].alarm);
}

void sys_resources_item_init_early(void)
{
    int ret;
    int i;

    ret = memset_s(g_system_monitor_info, sizeof(system_monitor_info) * SYSTEM_MONITOR_ITEM_CNT,
        0, sizeof(system_monitor_info) * SYSTEM_MONITOR_ITEM_CNT);
    if (ret != 0) {
        log_printf(LOG_ERR, "sys_resources_item_init_early, memset_s system_item_info failed, ret: %d.", ret);
        return;
    }

    for (i = 0; i < SYSTEM_MONITOR_ITEM_CNT; i++) {
        g_system_monitor_info[i].monitor = true;
        g_system_monitor_info[i].alarm = false;
    }
}

void sys_resources_item_init(void)
{
    int i;

    set_thread_item_monitor_flag(SYSTEM_ITEM, false);
    for (i = 0; i < SYSTEM_MONITOR_ITEM_CNT; i++) {
        if (g_system_monitor_info[i].monitor == true) {
            set_thread_item_monitor_flag(SYSTEM_ITEM, true);
            break;
        }
    }

    if (!get_thread_item_monitor_flag(SYSTEM_ITEM)) {
        return;
    }

    /* set default value for monitor item info */
    if (g_system_monitor_info[CPU].monitor) {
        g_system_monitor_info[CPU].alarm_value = ALARM_RATIO_DEFAULT;
        g_system_monitor_info[CPU].resume_value = RESUME_RATIO_DEFAULT;
        g_system_monitor_info[CPU].monitor_period = MONITOR_PERIOD_DEFAULT;
        g_system_monitor_info[CPU].stat_period = CPU_STAT_PERIOD;
        g_system_monitor_info[CPU].monitor_count = MONITOR_COUNT_INIT;
        g_system_monitor_info[CPU].monitor_func = monitor_cpu;
    }

    if (g_system_monitor_info[MEM].monitor) {
        g_system_monitor_info[MEM].alarm_value = ALARM_RATIO_DEFAULT;
        g_system_monitor_info[MEM].resume_value = RESUME_RATIO_DEFAULT;
        g_system_monitor_info[MEM].monitor_period = MONITOR_PERIOD_DEFAULT;
        g_system_monitor_info[MEM].monitor_count = MONITOR_COUNT_INIT;
        g_system_monitor_info[MEM].monitor_func = monitor_memory;
    }

    if (g_system_monitor_info[PSCNT].monitor) {
        g_system_monitor_info[PSCNT].alarm_value = PSCNT_ALARM_VALUE;
        g_system_monitor_info[PSCNT].resume_value = PSCNT_RESUME_VALUE;
        g_system_monitor_info[PSCNT].monitor_period = MONITOR_PERIOD_DEFAULT;
        g_system_monitor_info[PSCNT].monitor_count = MONITOR_COUNT_INIT;
        g_system_monitor_info[PSCNT].monitor_func = monitor_pscnt;
    }

    if (g_system_monitor_info[SYSTEM_FDCNT].monitor) {
        set_default_sysfd_config();
        g_system_monitor_info[SYSTEM_FDCNT].monitor_count = MONITOR_COUNT_INIT;
        g_system_monitor_info[SYSTEM_FDCNT].monitor_func = monitor_sysfd;
    }
}

void sys_resources_monitor_init(void)
{
    pthread_t tid;

    if (pthread_create(&tid, NULL, sys_resources_monitor_start, NULL)) {
        log_printf(LOG_ERR, "create system resources monitor thread error [%d]", errno);
        return;
    }
    set_thread_item_tid(SYSTEM_ITEM, tid);
}
