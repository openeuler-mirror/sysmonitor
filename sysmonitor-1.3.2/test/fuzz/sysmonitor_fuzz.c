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
 * Description: fuzz test
 * Author: pengyeqing
 * Create: 2019-12-24
 */

#include <stdio.h>
#include <stdlib.h>
#include <securec.h>
#include "common.h"

#define MIN_FORMAT_LEN 4
#define MAX_DATA_SIZE (128 * 1024)

/* calculate string length */
static int string_len(const char *data, size_t size)
{
    const char *p = NULL;

    if (data == NULL || size == 0) {
        return 0;
    }

    p = data;
    while (p < data + size && *p) {
        p++;
    }

    return p - data;
}

/* key="value" */
static int is_key_value_format(const char *buf, int len)
{
    char *ptr = NULL;

    if (buf == NULL || len < MIN_FORMAT_LEN) {
        return 0;
    }
    ptr = strchr(buf + 1, '=');
    if (ptr == NULL) {
        return 0;
    }
    ptr = strchr(ptr + 1, '"');
    if (ptr == NULL) {
        return 0;
    }
    return 1;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    return 0;
}

int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size)
{
    char *buf = NULL;
    int len;
    char *value = NULL;
    char *ptr = NULL;
    char secure_func_test[] = "k=\"v\"";
    int res;

    if (data == NULL || size > MAX_DATA_SIZE) {
        printf("data=%lx, size=%lu\n", (unsigned long)data, size);
        return 0;
    }

    buf = malloc(size + 1);
    if (buf == NULL) {
        printf("malloc for buf fail!\n");
        return -1;
    }
    res = memcpy_s(buf, size + 1, data, size);
    if (res != 0) {
        printf("memcpy_s for buf fail!\n");
        free(buf);
        return -1;
    }
    /* avoid overflow check */
    buf[size] = '\0';

    value = malloc(size);
    if (value == NULL) {
        printf("malloc for value fail!\n");
        free(buf);
        return -1;
    }

    /* test check_int */
    if (size == 0) {
        (void)check_int(NULL);
    } else {
        (void)check_int(buf);
    }

    len = string_len((const char *)data, size);
    if (is_key_value_format(buf, len)) {
        ptr = strchr(buf, '=');
        if (ptr != NULL) {
            /* test get_value */
            get_value(buf, ptr - buf, value, len);
        }
    }
    if (size == 0) {
        get_value(secure_func_test, 1, secure_func_test, 0);
    }

    free(buf);
    free(value);

    return 0;
}
