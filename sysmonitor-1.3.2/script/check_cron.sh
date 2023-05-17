#!/bin/bash

# Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
# Description: check cron service enable/disable
# Author:
# Create: 2017-09-29

# --------------------------  variables  ------------------------------------- #
G_CRON_NUM=0
CRON_STATUS=""
CRON_BIN=/usr/sbin/crond
# --------------------------  main  ------------------------------------------ #
function crond_process_exist()
{
	status=$(systemctl status crond -n 0 | grep "Active:" | grep running)
	[ -n "${status}" ] && return 0
	#if crond was stopped normally, do not report monitor error
	status=$(systemctl status crond -n 0 | grep "Active:" | grep 'inactive (dead)')
	[ -n "${status}" ] && return 0
	return 1
}

for((i=0;i<2;i++))
do
	crond_process_exist
	CRON_STATUS=$?
	if [ $CRON_STATUS -eq 0 ]; then
		break;
	fi
	sleep 4
done

G_CRON_PID=$(ps -ef | grep "$CRON_BIN" |awk '{if($3==1)print $2}')
G_CRON_NUM=$(echo $G_CRON_PID | wc -w)

if [ $CRON_STATUS -ne 0 ];then
	exit 1
fi
if [ $G_CRON_NUM -gt 1 ]; then
	kill -9 $G_CRON_PID 2>/dev/null
	exit 2
fi
