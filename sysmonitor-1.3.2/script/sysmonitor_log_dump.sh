#!/bin/bash

# Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
# Description: log dump for sysmonitor
# Author:
# Create: 2017-10-19

logdump_dir=/var/log/logdump/sysmonitor
logrotate_conf_file=/usr/libexec/sysmonitor/sysmonitor-logrotate
lock_file=$logdump_dir/sysmonitor-logrotate.lock
status_file=$logdump_dir/sysmonitor-logrotate.status

function mkdir_logdump_dir()
{
	local logdump_dir=$1
	if [ -e "${logdump_dir%/*}" -a ! -d "${logdump_dir%/*}" ];then
		logger -it sysmonitor_log_dump.sh "${logdump_dir%/*} is not a directory,now remove it" -p warning
		rm -rf ${logdump_dir%/*}
	elif [ -e "$logdump_dir" -a ! -d "$logdump_dir" ];then
		logger -it sysmonitor_log_dump.sh "$logdump_dir is not a directory,now remove it" -p warning
		rm -rf $logdump_dir
        fi

	mkdir_out=$(mkdir -m 700 -p $logdump_dir 2>&1)
	if [ $? -ne 0 ];then
		logger -it sysmonitor_log_dump.sh "$mkdir_out" -p warning
		rm -rf $lock_file
		exit 1
	fi
	chmod 700 $logdump_dir/..
}

function exec_logrotate()
{
	out=$(logrotate $logrotate_conf_file -s $status_file 2>&1)
	if [ $? -ne 0 ];then
		logger -it sysmonitor_log_dump.sh "$out" -p warning
		# if logrotate.status is invalid ,remove it
		if [ -n "$(echo $out | grep sysmonitor-logrotate.status)" ];then
			rm -f $status_file
			out=$(logrotate $logrotate_conf_file -s $status_file 2>&1)
			if [ $? -ne 0 ];then
				logger -it sysmonitor_log_dump.sh "$out" -p warning
				rm -rf $lock_file
				exit 1
			fi
		else
			rm -rf $lock_file
			exit 1
		fi
	fi
	chmod 400 $logdump_dir/*
}

function get_save_cnt()
{
	max_save_cnt=$(cat $logrotate_conf_file | grep -w rotate | awk '{print $2}')
	if [ -z "$max_save_cnt" ];then
		max_save_cnt=30
	fi
	echo $max_save_cnt
}

function check_rotate_file()
{
	rootbak_dir=$1
	sysmonitor_rootbak_dir=$rootbak_dir/logdump/sysmonitor
	rotate_cnt=$(ls $logdump_dir/sysmonitor.log.*.gz | wc -l)
	if [ $rotate_cnt -ne 1 ];then
		return
	fi
	rootbak_type=$(df -T $rootbak_dir | awk 'NR>1' | egrep -wv "/dev/(ram|loop)[0-9]{0,}" | awk '{print $2}' | grep -v rootfs | grep -v tmpfs)
	if [ -z "$rootbak_type" ];then
		return
	fi
	mkdir_logdump_dir $sysmonitor_rootbak_dir
	logdump_id=$(ls $sysmonitor_rootbak_dir/sysmonitor.log.*.gz | awk -F . '{print $3}' | sort -nr | head -n1)
	rotate_id=$(($logdump_id+1))
	rotate_date=$(date "+%Y%m%d%H%M%S")

	mv_result=$(mv $logdump_dir/sysmonitor.log.*.gz $sysmonitor_rootbak_dir/sysmonitor.log.$rotate_id.$rotate_date.gz 2>&1)
	if [ $? -ne 0 ];then
		logger -it sysmonitor_log_dump.sh "$mv_result" -p warning
	fi
	logdump_file_count=$(ls $sysmonitor_rootbak_dir/sysmonitor.log.*.gz | wc -l)
	max_save_cnt=$(get_save_cnt)
	if [ $logdump_file_count -le $max_save_cnt ];then
		return
	fi

	delet_file=$(ls $sysmonitor_rootbak_dir/sysmonitor.log.*.gz | sort -n -k 3 -t . | head -n $(($logdump_file_count-$max_save_cnt)))
	rm -rf $delet_file
}

#main
mkdir_logdump_dir $logdump_dir

exec 7<>$lock_file
flock  7

varlog_type=$(df -T /var/log | awk 'NR>1' | egrep -wv "/dev/(ram|loop)[0-9]{0,}" | awk '{print $2}' | grep -v rootfs | grep -v tmpfs)
if [ -n "$varlog_type" ];then
	exec_logrotate
	rm -rf $lock_file
	exit 0
fi
rm -rf $logdump_dir/*
exec_logrotate
log_bak_dir=$(cat /etc/esyslog/oslogdump.conf | grep LOG_BAK_DIR= | awk -F = '{print $2}')
if [ -z "$log_bak_dir" ];then
	#on logical part
	check_rotate_file /opt/udisk/log/transfer
	#on memory file system of CE
	check_rotate_file /rootbak/var/log
else
	check_rotate_file $log_bak_dir
fi
if [ -z "$(ls $logdump_dir/sysmonitor.log.*.gz)" ];then
	rm -rf $logdump_dir
fi
rm -rf $lock_file
