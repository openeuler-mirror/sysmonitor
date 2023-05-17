# Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
# Description: cmake file of fs_llt
# Author: xietangxin
# Create: 2021-12-06

project(sysmonitor)

INCLUDE_DIRECTORIES(../../src)
add_executable(fs_llt fs_llt.c ../../src/fsmonitor.c ../../src/common.c ../common_interface/common_interface.c ../../src/monitor_thread.c)
set_target_properties(fs_llt PROPERTIES LINK_FLAGS "-Wl,-z,relro -Wl,-z,noexecstack -Wl,-z,now -Wtrampolines -pie")
target_link_libraries(fs_llt cunit boundscheck pthread)
