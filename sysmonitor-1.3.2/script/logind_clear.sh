#!/bin/bash

# Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
# Description: clear login session
# Author:
# Create: 2017-3-15

session_path="/run/systemd/sessions"
scope_path="/run/systemd/system"
clear_start=100

session_files=$(ls ${session_path})
session_array=(${session_files})
count=${#session_array[@]}

if [ ${count} -le ${clear_start} ];then
	exit 0
fi

for files in ${session_array[*]}
do
	ref=`echo ${files} | grep ref`
	if [ ! -z "${ref}" ];then
		continue
	fi
	session_file=${session_path}/${files}
	state=`cat ${session_file} | grep STATE | awk -F '=' '{print $2}'`
	scope=`cat ${session_file} | grep SCOPE | awk -F '=' '{print $2}'`
	if [ "${state}" == "closing" ];then
		rm -f ${session_file}
		rm -f ${session_file}.ref
		rm -f ${scope_path}/${scope}
		rm -rf ${scope_path}/${scope}.d
	fi
done

