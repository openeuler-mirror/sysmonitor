#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Copyright (c) Huawei Technologies Co., Ltd. 2016-2019. All rights reserved.

"""
Description: check time change and handle NetworkManager service
Author:
Create: 2016-12-14
"""

from __future__ import absolute_import
import time
import os
import subprocess
import signal
import syslog

CLOCK_TIME_FILE = "/usr/libexec/sysmonitor/data/clocktime.data"


def start_dhclient_task(cmd):
    """Start cmd and move the process to network cgroup slice
    otherwise restart sysmonitor will kill the thread
    """
    ret = os.system("/usr/bin/systemctl |grep NetworkManager.service")
    if ret == 0:
        syslog.syslog(syslog.LOG_INFO, "wait for restarting dhclient")
        restart_cmd = "systemctl restart NetworkManager"
        ret, _ = subprocess.getstatusoutput(restart_cmd)
        if ret != 0:
            syslog.syslog(syslog.LOG_ERR, "restart NetworkManager failed.")
        return

    ret = os.system(cmd)
    if ret != 0:
        syslog.syslog(syslog.LOG_ERR, "start dhclient failed.")

    check_cmd = "ps -eLwwo pid,args|grep \"{0}\"|grep -v grep".format(cmd)
    ret, ps_result = subprocess.getstatusoutput(check_cmd)
    if ret != 0:
        syslog.syslog(syslog.LOG_ERR, ("create dhcliet error,"
            " need network restart!"))
        return

    ps_result = ps_result.splitlines()
    for line in ps_result:
        # Get the pid and change the systemd cgroup
        sp_result = line.strip().split()
        pid = int(sp_result[0])

        os.system(("mkdir -p /sys/fs/cgroup/systemd/system.slice/"
            "network.service"))
        res_cmd = ("echo {0} > /sys/fs/cgroup/systemd/system.slice/"
            "network.service/tasks").format(pid)

        ret = os.system(res_cmd)
        if ret != 0:
            syslog.syslog(syslog.LOG_ERR, "write pid of dhclient failed.")


def check_cmd_user(cmd_user):
    """check cmd user is root"""
    if cmd_user == "root":
            return True
    return False


def check_cmd_name(cmd_line):
    """check cmd name is /sbin/dhclient"""
    std_cmd_name = "/sbin/dhclient"
    if cmd_line is None:
        return False
    cmd_name = cmd_line.split()
    if len(cmd_name) < 2:
        return False
    if cmd_name[1]:
        if cmd_name[1] == std_cmd_name:
            return True
    return False


def reset_dhclient():
    """find and kill dhclient process and start new dhclient"""
    ret, ps_result = subprocess.getstatusoutput("ps -eLwwo user,pid,args|"
        "grep -w /sbin/dhclient|grep -v grep")
    if ret != 0:
        return

    sp_result = ps_result.splitlines()
    invalidstr = [
        '!', '\\n', ';', '|', '&', '$', '>', '<', '(', ')',
        './', '/.', '?', '*', '`', '\\', '[', ']', '\''
    ]
    for line in sp_result:
        inval_flag = False
        # Remove space,find the dev device and restart dhclient
        line = line.strip(' ')
        i = line.find(' ')
        cmd_user = line[:i]
        line = line[i + 1:]
        line = line.strip(' ')
        ret_flag = check_cmd_user(cmd_user)
        if not ret_flag:
            syslog.syslog(syslog.LOG_ERR, "invaild cmd user, continue")
            continue
        ret_flag = check_cmd_name(line)
        if not ret_flag:
            syslog.syslog(syslog.LOG_ERR, "invaild cmd name, continue")
            continue
        for inval in invalidstr:
            if line.find(inval) != -1:
                inval_flag = True
                str_info = ("invaild symbol in line cmd is {0}, "
                    "continue").format(inval)
                syslog.syslog(syslog.LOG_ERR, str_info)
                break
        if inval_flag is True:
            continue
        i = line.rfind(' ')
        dev = line[i + 1:]
        cmd = "/usr/sbin/ifconfig {0}".format(dev)

        ret, _ = subprocess.getstatusoutput(cmd)
        if ret != 0:
            # Dev not found
            continue

        i = line.find(' ')
        pid = int(line[:i])
        cmd = line[i + 1:]

        try:
            os.kill(pid, signal.SIGKILL)
            # Wait process killed
            time.sleep(1)
        except BaseException:
            syslog.syslog(syslog.LOG_ERR, "killed dhclient failed.")
        else:
            syslog.syslog(syslog.LOG_INFO, "killed dhclient successed.")
        finally:
            syslog.syslog(syslog.LOG_INFO, "process kill dhclient end.")

        start_dhclient_task(cmd)


def read_time_file():
    """read time from file"""
    tmp_time = None
    if os.path.exists(CLOCK_TIME_FILE):
        tmp_file = open(CLOCK_TIME_FILE, mode='r')
        tmp_time = tmp_file.read()
        tmp_file.close()
    return tmp_time


def write_time_file(now):
    """write time to file"""
    chmod_flag = False
    if not os.path.exists(CLOCK_TIME_FILE):
        chmod_flag = True
    tmp_file = open(CLOCK_TIME_FILE, mode='w')
    if chmod_flag:
        os.chmod(CLOCK_TIME_FILE, 0o640)
    tmp_file.write(str(now))
    tmp_file.flush()
    tmp_file.close()


def check_time_change():
    """check if time has been changed"""
    tmp_time = None
    reset_time = 3620
    now = time.time()
    tmp_time = read_time_file()
    if tmp_time:
        # More than one hour
        if (float(tmp_time) - now) > reset_time:
            str_time = ("time change catched, before is {0},"
                " now is {1}").format(tmp_time, now)
            syslog.syslog(syslog.LOG_WARNING, str_time)
            reset_dhclient()
    write_time_file(now)

if __name__ == '__main__':
    check_time_change()
