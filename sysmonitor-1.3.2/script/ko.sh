#!/bin/bash

# Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
# Description: handle sysmonitor module insmod and rmmod
# Author:
# Create: 2018-8-14

function install_ko()
{
	local ko_list=

	ko_list[0]="signo_catch"
	ko_list[1]="fdstat"
	ko_list[2]="monitor_netdev"

	for i in ${ko_list[*]}
	do
		rmmod $i 2>/dev/null 1>/dev/null
	done
	insmod /lib/modules/sysmonitor/sysmonitor.ko 2>/dev/null 1>/dev/null
}

function rm_ko()
{
	local ko_list=

	ko_list[0]="sysmonitor"

	for i in ${ko_list[*]}
	do
		rmmod $i 2>/dev/null 1>/dev/null
	done
}

case "$1" in
install)
	install_ko
	;;
rm)
	rm_ko
	;;
*)
	exit 1
esac
