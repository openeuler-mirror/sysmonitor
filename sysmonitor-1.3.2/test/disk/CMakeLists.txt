# Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
# Description: cmake file of disk_llt
# Author: xuchunmei
# Create: 2019-9-28
project(sysmonitor)

INCLUDE_DIRECTORIES(../../src)
add_executable(disk_llt ../../src/common.c ../../src/disk.c ../common_interface/common_interface.c ../../src/monitor_thread.c disk_llt.c)
set_target_properties(disk_llt PROPERTIES LINK_FLAGS "-Wl,-z,relro -Wl,-z,noexecstack -Wl,-z,now -Wtrampolines -pie -g")
target_link_libraries(disk_llt boundscheck pthread cunit)
