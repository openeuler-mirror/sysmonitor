# Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
# Description: cmake file of sysmonitor testcase
# Author: xuchunmei
# Create: 2019-9-9

project(sysmonitor)

set(CMAKE_C_FLAGS "-g -Wall -Werror -D_FORTIFY_SOURCE=2 -O2 -fPIE -fstack-protector-strong -s")

add_subdirectory(common)
add_subdirectory(custom)
add_subdirectory(process)
add_subdirectory(disk)
add_subdirectory(filemonitor)
add_subdirectory(sys_resources)
add_subdirectory(sys_event)
add_subdirectory(sysmonitor)
add_subdirectory(fuzz)
add_subdirectory(zombie)
add_subdirectory(fs)
