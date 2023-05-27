# Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
# Description: cmake file of sysmonitor
# Author: zhangguangzhi
# Create: 2020-04-03

project(sysmonitor)

SET(EXE sysmonitor_llt)
SET(EXE_TEST sysmonitor_test)
INCLUDE_DIRECTORIES(../../src)
add_executable(${EXE} sysmonitor_llt.c ../../src/common.c ../common_interface/common_interface.c ../../src/monitor_thread.c)
set_target_properties(${EXE} PROPERTIES LINK_FLAGS "-Wl,-z,relro -Wl,-z,noexecstack -Wl,-z,now -Wtrampolines -pie")
target_link_libraries(${EXE} cunit boundscheck pthread)

# sysmonitor test file
add_executable(${EXE_TEST} ../../src/common.c ../../src/custom.c ../../src/disk.c ../../src/fsmonitor.c ../../src/filemonitor.c ../../src/process.c ../../src/sys_resources.c ../../src/sys_event.c ../../src/sysmonitor.c ../../src/zombie.c ../../src/monitor_thread.c)
set_target_properties(${EXE_TEST} PROPERTIES LINK_FLAGS "-Wl,-z,relro -Wl,-z,noexecstack -Wl,-z,now -Wtrampolines -pie")
target_link_libraries(${EXE_TEST} cunit boundscheck pthread)

