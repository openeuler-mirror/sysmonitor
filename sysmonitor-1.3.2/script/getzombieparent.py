#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.

"""
Description: get and print the information of the zombies' parent process
Author:
Create: 2019-7-22
"""
from __future__ import absolute_import
import subprocess
import syslog


def zombie_get_parent_process():
    """Get and output the zombie process info"""
    check_cmd = "ps -eLwwo pid,stat,ppid,args| awk 'NR>1'"
    ret, ps_result = subprocess.getstatusoutput(check_cmd)
    if ret != 0:
        syslog.syslog(syslog.LOG_WARNING, "Failed to get all process info!")
        return
    ps_result = ps_result.splitlines()
    all_process = {}
    zombie_parent = {}
    for line in ps_result:
        sp_result = line.strip().split()
        all_process[sp_result[0]] = sp_result[3]
        if sp_result[1].startswith(('Z', 'z')):
            zombie_parent[sp_result[2]] = sp_result[0]

    for ppid in zombie_parent:
        str_log = ("zombie parent process: pid is {0}, "
            "args is {1}").format(ppid, all_process[ppid])
        syslog.syslog(syslog.LOG_ERR, str_log)

if __name__ == '__main__':
    zombie_get_parent_process()

