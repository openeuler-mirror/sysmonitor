# Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
# Description: cmake file of sysmonitor testcase sys_event
# Author: xuchunmei
# Create: 2019-10-28

project(sysmonitor)

INCLUDE_DIRECTORIES(../../src ../../test/include)
add_executable(sys_event_llt ../../src/common.c ../../src/sys_event.c sys_event_llt.c ../common_interface/common_interface.c ../../src/monitor_thread.c)
set_target_properties(sys_event_llt PROPERTIES LINK_FLAGS "-Wl,-z,relro -Wl,-z,noexecstack -Wl,-z,now -Wtrampolines -pie")
target_link_libraries(sys_event_llt boundscheck pthread cunit)

add_executable(sys_event_fd sys_event_fd.c)
set_target_properties(sys_event_fd PROPERTIES LINK_FLAGS "-Wl,-z,relro -Wl,-z,noexecstack -Wl,-z,now -Wtrampolines -pie")
target_link_libraries(sys_event_fd boundscheck)
