#!/bin/bash

# Copyright (c) Huawei Technologies Co., Ltd. 2016-2019. All rights reserved.
# Description: check sshd service
# Author:
# Create: 2016-9-1

SSHD_STATUS=""
SSHD_PID=""
NUM=2
count=$(expr $NUM - 1)

function sshd_process_exist()
{
	status=$(systemctl status sshd -n 0 | grep "Active:" | grep running)
	[ -n "${status}" ] && return 0
	return 1
}

for((i=0;i<$NUM;i++))
do
	sshd_process_exist
	SSHD_STATUS=$?
	if [ $SSHD_STATUS -eq 0 ]; then
		break;
	fi
	if [ "$i" -lt "$count" ];then
		sleep 2
	fi
done

if [ $SSHD_STATUS -ne 0 ];then
	SSHD_PID=$(ps -ef | grep -w "/usr/sbin/sshd" | grep -v grep | awk '{if ($3==1) print $2}')
	kill -9 $SSHD_PID 2>/dev/null
	exit 1
fi
exit 0
