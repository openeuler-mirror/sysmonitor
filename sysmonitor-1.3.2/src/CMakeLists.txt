# Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
# Description: cmake file of sysmonitor src
# Author: xuchunmei
# Create: 2018-12-15

project(sysmonitor)

set(CMAKE_C_FLAGS "-Wall -Werror -D_FORTIFY_SOURCE=2 -O2 -fPIE -fstack-protector-strong -g")

if (VERSION)
  add_compile_options(-D ${VERSION})
endif(VERSION)

if (CUSTOM)
  add_compile_options(-D ${CUSTOM})
endif(CUSTOM)

add_executable(sysmonitor common.c custom.c disk.c fsmonitor.c filemonitor.c process.c sys_resources.c sys_event.c sysmonitor.c zombie.c monitor_thread.c)
set_target_properties(sysmonitor PROPERTIES LINK_FLAGS "-Wl,-z,relro -Wl,-z,noexecstack -Wl,-z,now -Wtrampolines -pie")
target_link_libraries(sysmonitor boundscheck pthread)
