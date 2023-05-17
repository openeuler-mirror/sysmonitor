# Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
# Description: cmake file of sysmonitor testcase sys_resources
# Author: zhangguangzhi
# Create: 2019-9-9

project(sysmonitor)

INCLUDE_DIRECTORIES(../../src ../../test/include)
add_executable(sys_resources_llt ../../src/common.c ../../src/sys_resources.c sys_resources_llt.c ../common_interface/common_interface.c ../../src/monitor_thread.c)
set_target_properties(sys_resources_llt PROPERTIES LINK_FLAGS "-Wl,-z,relro -Wl,-z,noexecstack -Wl,-z,now -Wtrampolines -pie")
target_link_libraries(sys_resources_llt boundscheck pthread cunit)

add_executable(generate_fd generate_fd.c)
set_target_properties(generate_fd PROPERTIES LINK_FLAGS "-Wl,-z,relro -Wl,-z,noexecstack -Wl,-z,now -Wtrampolines -pie")
target_link_libraries(generate_fd boundscheck)
