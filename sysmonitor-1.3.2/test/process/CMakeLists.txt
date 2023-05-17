# Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
# Description: cmake file of process_llt
# Author: xuchunmei
# Create: 2019-9-28
project(sysmonitor)

INCLUDE_DIRECTORIES(../../src)
add_executable(process_llt ../../src/common.c ../../src/process.c ../common_interface/common_interface.c ../../src/monitor_thread.c process_llt.c)
set_target_properties(process_llt PROPERTIES LINK_FLAGS "-Wl,-z,relro -Wl,-z,noexecstack -Wl,-z,now -Wtrampolines -pie -g")
target_link_libraries(process_llt boundscheck pthread cunit)
