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
 * Description: define variable, structure and function for ext3/ext4 file system monitor
 * Author: xuchunmei
 * Create: 2016-1-1
 */
#ifndef EX3_NETLINK_H
#define EX3_NETLINK_H

#define EXT4_ERROR_MAGIC 0xAE43125U
#define EXT3_ERROR_MAGIC 0xAE32014U
#define NETLINK_FILESYSTEM 28

#define FILE_SYSTEM_LENTH 64
#define FIRST_FIVE_DEV_CHAR 5
#define FILE_SYSTEM_PERIOD 20

enum fs_error_group {
    FS_ERROR_GRP_EXT3 = 1
};

/* this struct same as ext4_err_msg in kernel fs/ext4/ext4.h */
struct ext4_err_msg {
    unsigned int magic;
    char s_id[32];
    unsigned long s_flags;
    int ext4_errno;
};

void fs_monitor_init(void);

#endif
