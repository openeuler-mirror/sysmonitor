# Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
# Description: cmake file of common_llt
# Author: xuchunmei
# Create: 2019-9-9

project(sysmonitor)

SET(EXE common_llt)
INCLUDE_DIRECTORIES(../../src)
add_executable(${EXE} common_llt.c ../../src/common.c ../common_interface/common_interface.c)
set_target_properties(${EXE} PROPERTIES LINK_FLAGS "-Wl,-z,relro -Wl,-z,noexecstack -Wl,-z,now -Wtrampolines -pie")
target_link_libraries(${EXE} cunit boundscheck pthread)

add_executable(process_exit_test process_exit_test.c)
set_target_properties(process_exit_test PROPERTIES LINK_FLAGS "-Wl,-z,relro -Wl,-z,noexecstack -Wl,-z,now -Wtrampolines -pie")
target_link_libraries(process_exit_test boundscheck)
