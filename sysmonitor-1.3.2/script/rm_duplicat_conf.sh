#!/bin/bash

# Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
# Description: remove duplicat config file
# Author:
# Create: 2018-6-5

function fn_replace_conf_file()
{
	local process_path="/etc/sysmonitor/process"
	local conf_file_list="libvirtd UVPHostd vBMC_agentd"

	for i in $conf_file_list
	do
		if [ -f ${process_path}/${i}-monitor ]&&[ -f ${process_path}/${i}-daemon ];then
			rm -f ${process_path}/${i}-monitor
			if [ $? -ne 0 ];then
				logger -it rm_duplicat_conf.sh "Delete ${i}-monitor failed."
			else
				logger -it rm_duplicat_conf.sh "Deleted ${i}-monitor."
			fi
		fi
	done
}

fn_replace_conf_file

