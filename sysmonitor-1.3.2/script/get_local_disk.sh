#!/bin/bash

# Copyright (c) Huawei Technologies Co., Ltd. 2016-2019. All rights reserved.
# Description: get local disk
# Author:
# Create: 2016-12-14

fc_disk_file=""
local_disk_file=""
if uname -a | grep -q aarch64; then
	fc_local_disk=`ls -l /sys/block/ | grep -E 'pci|HISI0162' 2> /dev/null`
else
	fc_local_disk=`ls -l /sys/block/ | grep pci 2> /dev/null`
fi
disk_list=""

# **************************************************************************** #
# Function Name: OS_CREATE_TMP_FILE
# Description: Create a secure tmp file
# Parameter: tmp file
# Return: 0-succ, 1-failed
# **************************************************************************** #
OS_CREATE_TMP_FILE()
{
        local file_name=$1
        local tmp_file=""
        local save_mask=$(umask)

        umask 077
        tmp_file=$(mktemp "${file_name}_XXXXXXXXXX" 2>/dev/kmsg)
        if [ $? -ne 0 ]
        then
                umask "${save_mask}"
                return 1
        fi
        umask "${save_mask}"
        echo "${tmp_file}"
        return 0
}

fc_disk_file=$(OS_CREATE_TMP_FILE "/tmp/fc_disk")
if [ $? -eq 1 ];then
	rm -rf "${fc_disk_file}"
	exit 1
fi

local_disk_file=$(OS_CREATE_TMP_FILE "/tmp/local_disk")
if [ $? -eq 1 ];then
	rm -rf "${fc_disk_file}" "${local_disk_file}"
	exit 1
fi

ls -l /sys/class/fc_host/ > ${fc_disk_file} 2> /dev/null
while read line
do
	total_line=`echo ${line} | grep total`
	if [ ! -z "${total_line}" ];then
		continue
	fi
	host=$(echo "${line}" | awk -F "/" '{print $NF}' 2> /dev/null)
	fc_local_disk=`echo "${fc_local_disk}" | grep -v -w ${host} 2> /dev/null`
done < ${fc_disk_file}

echo "${fc_local_disk}" > ${local_disk_file} 2> /dev/null
while read line
do
	disk=`echo ${line} | awk -F "/" '{print $NF}' 2> /dev/null`
	cd_rom=`echo "${disk}" | grep "sr[0-9]\{1,\}$"`
	if [ ! -z "${cd_rom}" ];then
		continue
	fi
	if [ -z ${disk_list} ];then
		disk_list=${disk}
	else
		disk_list="${disk_list},${disk}"
	fi
done < ${local_disk_file}
echo -e "${disk_list}\c"

rm -f ${fc_disk_file} ${local_disk_file}

