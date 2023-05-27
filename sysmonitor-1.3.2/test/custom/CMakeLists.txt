# Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
# Description: cmake file of custom_llt
# Author: xuchunmei
# Create: 2019-9-28
project(sysmonitor)

INCLUDE_DIRECTORIES(../../src)
add_executable(custom_llt ../../src/common.c ../../src/custom.c ../common_interface/common_interface.c ../../src/monitor_thread.c custom_llt.c)
set_target_properties(custom_llt PROPERTIES LINK_FLAGS "-Wl,-z,relro -Wl,-z,noexecstack -Wl,-z,now -Wtrampolines -pie -g")
target_link_libraries(custom_llt boundscheck pthread cunit)
