# Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
# Description: cmake file of disk_llt
# Author: xuchunmei
# Create: 2019-9-28
project(sysmonitor)

INCLUDE_DIRECTORIES(../../src)
add_executable(filemonitor_llt ../../src/common.c ../../src/filemonitor.c ../common_interface/common_interface.c filemonitor_llt.c)
set_target_properties(filemonitor_llt PROPERTIES LINK_FLAGS "-Wl,-z,relro -Wl,-z,noexecstack -Wl,-z,now -Wtrampolines -pie -g")
target_link_libraries(filemonitor_llt boundscheck pthread  cunit)
