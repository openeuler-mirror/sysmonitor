# Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
# Description: cmake file of zombie_llt
# Author: xietangxin
# Create: 2021-11-29

project(sysmonitor)

INCLUDE_DIRECTORIES(../../src)
add_executable(zombie_llt zombie_llt.c ../../src/zombie.c ../../src/common.c ../common_interface/common_interface.c ../../src/monitor_thread.c)
set_target_properties(zombie_llt PROPERTIES LINK_FLAGS "-Wl,-z,relro -Wl,-z,noexecstack -Wl,-z,now -Wtrampolines -pie")
target_link_libraries(zombie_llt cunit boundscheck pthread)

add_executable(generate_zombie generate_zombie.c)
set_target_properties(generate_zombie PROPERTIES LINK_FLAGS "-Wl,-z,relro -Wl,-z,noexecstack -Wl,-z,now -Wtrampolines -pie")
target_link_libraries(generate_zombie boundscheck)
