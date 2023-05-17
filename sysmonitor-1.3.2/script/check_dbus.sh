#!/bin/bash

# Copyright (c) Huawei Technologies Co., Ltd. 2016-2022. All rights reserved.
# Description: check dbus status
# Author:
# Create: 2022-7-25

DBUS_STRING=":1"

function can_dbus_process()
{
        which busctl > /dev/null 2>&1
        if [ $? -ne 0 ]; then
                return 0
        fi

        result=$(timeout 26s busctl call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus GetNameOwner "s" "org.freedesktop.systemd1" 2>&1)
        if [[ $result =~ $DBUS_STRING ]]; then
                return 0
        fi

        return 1
}

can_dbus_process
exit $?
