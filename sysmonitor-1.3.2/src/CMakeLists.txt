# Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
# Description: cmake file of sysmonitor src
# Author: xuchunmei
# Create: 2018-12-15

project(sysmonitor)

set(CMAKE_C_FLAGS "-Wall -Werror -D_FORTIFY_SOURCE=2 -O2 -fPIE -fstack-protector-strong -g")
set(CMAKE_INSTALL_SYSCONFDIR "/etc")
set(CMAKE_INSTALL_LIBEXECDIR "/usr/libexec")
set(CMAKE_INSTALL_SYSLOGDIR "/etc/rsyslog.d")
set(CMAKE_INSTALL_SBINDIR "/usr/sbin")
set(CMAKE_INSTALL_BINDIR "/usr/bin")
set(SYSTEMD_SERVICEDIR "/usr/lib/systemd/system/")

if (VERSION)
  add_compile_options(-D ${VERSION})
endif(VERSION)

if (CUSTOM)
  add_compile_options(-D ${CUSTOM})
endif(CUSTOM)

add_executable(sysmonitor common.c custom.c disk.c fsmonitor.c filemonitor.c process.c sys_resources.c sys_event.c sysmonitor.c zombie.c monitor_thread.c)
set_target_properties(sysmonitor PROPERTIES LINK_FLAGS "-Wl,-z,relro -Wl,-z,noexecstack -Wl,-z,now -Wtrampolines -pie")
target_link_libraries(sysmonitor boundscheck pthread)
install(TARGETS sysmonitor DESTINATION ${CMAKE_INSTALL_BINDIR})
install(DIRECTORY ../conf/ DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/sysmonitor PATTERN "rsyslog.d " EXCLUDE PATTERN "clock_transition" EXCLUDE PATTERN "io_monitor" EXCLUDE PATTERN "logind_monitor" EXCLUDE PATTERN "sysmonitor" EXCLUDE PATTERN "io_monitor" EXCLUDE)
install(FILES ../conf/rsyslog.d/sysmonitor.conf DESTINATION ${CMAKE_INSTALL_SYSLOGDIR})
install(FILES ../conf/logrotate.d/sysmonitor-logrotate DESTINATION ${CMAKE_INSTALL_LIBEXECDIR}/sysmonitor)
install(FILES ../conf/clock_transition DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/sysmonitor.d)
install(FILES ../conf/io_monitor DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/sysmonitor.d)
install(FILES ../conf/logind_monitor DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/sysmonitor.d)
install(FILES ../conf/sysmonitor DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/sysconfig)

install(DIRECTORY ../script/ DESTINATION ${CMAKE_INSTALL_LIBEXECDIR}/sysmonitor PATTERN "iomonitor_daemon" EXCLUDE)
install(PROGRAMS ../script/iomonitor_daemon  DESTINATION ${CMAKE_INSTALL_SBINDIR})
install(FILES ../conf/io_monitor DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/sysmonitor.d)
install(FILES ../service/sysmonitor.service DESTINATION ${SYSTEMD_SERVICEDIR})

add_custom_target(uninstall
	COMMAND rm -rf /etc/sysmonitor ${CMAKE_INSTALL_SYSCONFDIR}/sysconfig/sysmonitor /usr/libexec/sysmonitor /etc/rsyslog.d/sysmonitor.conf /etc/sysmonitor.d/
	COMMAND rm -rf /usr/lib/systemd/system/sysmonitor.service
	COMMAND rm -rf /usr/sbin/iomonitor_daemon /usr/bin/sysmonitor
	COMMENT "Uninstall sysmonitor"
	VERBATIM
)
