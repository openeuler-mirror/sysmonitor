#!/bin/bash

# Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
# Description: check syslog service enable/disable
# Author:
# Create: 2017-08-31

# --------------------------  variables  ------------------------------------- #
declare -i MESSAGE_AVAILABLE_LIMIT
G_SYSLOG_PID=""
G_MESSAGE_AVAILABLE=""
MESSAGE_AVAILABLE_LIMIT=8
DEV_MSG=""
DEV_TYPE=""
MEM_RESTART=0
DISK_RESTART=0
DISK_FLAG=0
MEM_LIST=""
DISK_LIST=""
# --------------------------  main  ------------------------------------------ #
G_SYSLOG_PID=$(systemctl status rsyslog | grep "Main PID:" | awk '{print $3}')
if [ ! -d /proc/${G_SYSLOG_PID}/fd ]; then
	logger -t "sysmonitor" "[$(date +"%Y-%m-%d:%H:%M:%S")]sysmonitor[$(pidof sysmonitor)]: The directory of /proc/${G_SYSLOG_PID}/fd does not exist, now restart rsyslog"
	exit 1
fi
#only read journal log, when journal log is deleted,
#rsyslog can ensure correct reading, so do not check journal log.
for i in $(ls -l /proc/${G_SYSLOG_PID}/fd | grep " \-> .* (deleted)$" | grep -wv journal | awk '{print $9}')
do
	DELETE_FILE="$(ls -l /proc/${G_SYSLOG_PID}/fd/$i | awk -F '-> ' '{print $2}')"
	FD_STATUS="$(file /proc/${G_SYSLOG_PID}/fd/$i)"
	# add new judgment condition for no broken to adapt file command change
	if [ "$FD_STATUS" != "/proc/${G_SYSLOG_PID}/fd/$i: broken symbolic link to $DELETE_FILE" ] && \
		[ "$FD_STATUS" != "/proc/${G_SYSLOG_PID}/fd/$i: symbolic link to $DELETE_FILE" ];then
		continue
	fi
	DELETE_FILE="${DELETE_FILE% (deleted)}"
	DELETE_PATH="${DELETE_FILE%/*}"
	DEV_MSG=$(df -mT "$DELETE_PATH" | awk 'NR>1')
	DEV_TYPE=$(echo $DEV_MSG | awk '{print $2}' | grep -v rootfs | grep -v tmpfs)
	if [ -z "$DEV_TYPE" ];then
		MEM_RESTART=1
		if [ -n "$MEM_LIST" ];then
			MEM_LIST="${MEM_LIST};${DELETE_FILE}"
		else
			MEM_LIST="$DELETE_FILE"
		fi
		continue
	fi
	DISK_FLAG=1
	G_MESSAGE_AVAILABLE=$(echo $DEV_MSG | awk '{print $5}')
	if [ "${G_MESSAGE_AVAILABLE}" -ge "${MESSAGE_AVAILABLE_LIMIT}" ]; then
		DISK_RESTART=1
		if [ -n "$DISK_LIST" ];then
			DISK_LIST="${DISK_LIST};${DELETE_FILE}"
		else
			DISK_LIST="$DELETE_FILE"
		fi
	else
		DISK_RESTART=0
		break;
	fi
done
if [ $DISK_FLAG -eq 0 ];then
	if [ $MEM_RESTART -eq 1 ];then
		logger -t "sysmonitor" "[$(date +"%Y-%m-%d:%H:%M:%S")]sysmonitor[$(pidof sysmonitor)]: The fd of $MEM_LIST in rsyslog is abnormal, now restart rsyslog"
		exit 1
	else
		exit 0
	fi
else
	if [ $DISK_RESTART -eq 1 ];then
		if [ -z "$MEM_LIST" ];then
			logger -t "sysmonitor" "[$(date +"%Y-%m-%d:%H:%M:%S")]sysmonitor[$(pidof sysmonitor)]: The fd of $DISK_LIST in rsyslog is abnormal, now restart rsyslog"
		else
			logger -t "sysmonitor" "[$(date +"%Y-%m-%d:%H:%M:%S")]sysmonitor[$(pidof sysmonitor)]: The fd of $DISK_LIST;$MEM_LIST in rsyslog is abnormal, now restart rsyslog"
		fi
		exit 1
	else
		exit 0
	fi
fi
