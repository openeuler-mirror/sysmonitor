#!/bin/bash

# Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
# Description: check clocktime.data
# Author:
# Create: 2020-04-16

CLOCK_TIME_FILE="/usr/libexec/sysmonitor/data/clocktime.data"

function init_clockdata()
{
	if [ -f $CLOCK_TIME_FILE ];then
		rm -rf $CLOCK_TIME_FILE
	fi
	umask 026
	touch $CLOCK_TIME_FILE
}

function rm_clockdata()
{
	if [ -f $CLOCK_TIME_FILE ];then
		rm -rf $CLOCK_TIME_FILE
	fi
}

case "$1" in
init)
	init_clockdata
	;;
rm)
	rm_clockdata
	;;
*)
	exit 1
esac
