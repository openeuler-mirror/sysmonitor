#!/bin/bash
# Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
# Description: clean remaining main process when stop sysmonitor service
# Create: 2021-8-24

REMAIN_PID=""
SYSMONITOR_DAEMON="/usr/bin/sysmonitor --daemon"

REMAIN_PID=$(ps -ef | grep -w "$SYSMONITOR_DAEMON" | grep -v grep | awk '{if($3==1) print $2}')
if [ -n "$REMAIN_PID" ]; then
        kill -TERM $REMAIN_PID 2>/dev/null
fi

