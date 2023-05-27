# needssslcertforbuild
#
# spec file for package sysmonitor
#
# Copyright (c) Huawei Technologies Co., Ltd. 2014-2019. All rights reserved.
#

%define kmod_name sysmonitor
%define rpmversion 1.3.2
%define releaseversion 1.0
Summary: System Monitor Daemon
Name: %{kmod_name}-kmod
Version: %{rpmversion}
Release: %{releaseversion}
License: GPLv2 and Mulan PSL v2
Group: System Environment/Daemons
Source0: %{kmod_name}-%{rpmversion}.tar.bz2
BuildRoot: %{_builddir}/%{kmod_name}-root
BuildRequires: libboundscheck
Requires: systemd
BuildRequires: module-init-tools
BuildRequires: kernel-devel
BuildRequires: dos2unix
BuildRequires: elfutils-libelf-devel
BuildRequires: cmake gcc-c++
BuildRequires: libcap-devel
BuildRequires: uname-build-checks
Requires: bash dhcp gawk kmod logrotate
Requires: net-tools which file
#for test
BuildRequires: CUnit CUnit-devel
Requires: libboundscheck
Requires: kernel >= 3.10.0-514.44.5.10
Requires: iotop
Requires: python3
Provides: sysmonitor

%description
System Monitor Daemon

%prep
%setup -n   %{kmod_name}-%{rpmversion}

%build
cmake .
make %{?_smp_mflags}
cd module
make KDIR=/lib/modules/`uname -r`/build
strip -g sysmonitor.ko

%install
#export BRP_PESIGN_FILES="*.ko"

dos2unix %_builddir/%{kmod_name}-%{rpmversion}/script/iomonitor_daemon
dos2unix %_builddir/%{kmod_name}-%{rpmversion}/conf/io_monitor

mkdir -p %{buildroot}/usr/sbin/
mkdir -p %{buildroot}/etc/sysmonitor.d/

install -d %{buildroot}%{_bindir}
install -d %{buildroot}%{_sysconfdir}/sysconfig
install -d -m 700 %{buildroot}%{_sysconfdir}/sysmonitor/
install -d -m 700 %{buildroot}%{_sysconfdir}/sysmonitor/process
install -d -m 700 %{buildroot}/usr/libexec/sysmonitor
install -d -m 700 %{buildroot}%{_sysconfdir}/sysmonitor.d/
install -d %{buildroot}/etc/rsyslog.d/
install -d -m 750 %{buildroot}/lib/modules/sysmonitor
install -d -m 750 %{buildroot}/usr/libexec/sysmonitor/data

install -m 600 conf/process/* %{buildroot}%{_sysconfdir}/sysmonitor/process
install -m 600 conf/signal %{buildroot}%{_sysconfdir}/sysmonitor
install -m 600 conf/network %{buildroot}%{_sysconfdir}/sysmonitor
install -m 500 src/sysmonitor %{buildroot}%{_bindir}
install -m 600 conf/sysmonitor %{buildroot}%{_sysconfdir}/sysconfig/sysmonitor
install -m 640 module/sysmonitor.ko %{buildroot}/lib/modules/sysmonitor
install -m 600 conf/disk %{buildroot}%{_sysconfdir}/sysmonitor/disk
install -m 600 conf/inode %{buildroot}%{_sysconfdir}/sysmonitor/inode
install -m 600 conf/file %{buildroot}%{_sysconfdir}/sysmonitor/file
install -m 600 conf/cpu %{buildroot}%{_sysconfdir}/sysmonitor/cpu
install -m 600 conf/memory %{buildroot}%{_sysconfdir}/sysmonitor/memory
install -m 600 conf/pscnt %{buildroot}%{_sysconfdir}/sysmonitor/pscnt
install -m 600 conf/iodelay %{buildroot}%{_sysconfdir}/sysmonitor/iodelay
install -m 600 conf/process_fd_conf %{buildroot}%{_sysconfdir}/sysmonitor/process_fd_conf
install -m 600 conf/sys_fd_conf %{buildroot}%{_sysconfdir}/sysmonitor/sys_fd_conf
install -m 600 conf/w_log_conf %{buildroot}%{_sysconfdir}/sysmonitor/w_log_conf
install -m 500 script/get_local_disk.sh %{buildroot}/usr/libexec/sysmonitor/
install -m 500 script/check_sshd.sh %{buildroot}/usr/libexec/sysmonitor/
install -m 500 script/check_dbus.sh %{buildroot}/usr/libexec/sysmonitor/
install -m 600 conf/rsyslog.d/sysmonitor.conf %{buildroot}/etc/rsyslog.d/sysmonitor.conf
install -m 500 script/check_syslog.sh %{buildroot}/usr/libexec/sysmonitor/
install -m 600 conf/logrotate.d/sysmonitor-logrotate %{buildroot}/usr/libexec/sysmonitor/sysmonitor-logrotate
install -m 500 script/sysmonitor_log_dump.sh %{buildroot}/usr/libexec/sysmonitor/
install -m 500 script/check_cron.sh %{buildroot}/usr/libexec/sysmonitor/
install -m 600 conf/clock_transition %{buildroot}%{_sysconfdir}/sysmonitor.d/clock_transition
install -m 500 script/clocktransition.py  %{buildroot}/usr/libexec/sysmonitor/
install -m 500 script/ko.sh %{buildroot}/usr/libexec/sysmonitor/
install -m 500 script/rm_duplicat_conf.sh %{buildroot}/usr/libexec/sysmonitor/
install -m 500 script/process_clock_data.sh %{buildroot}/usr/libexec/sysmonitor/
install -m 500 script/iomonitor_daemon %{buildroot}/usr/sbin/
install -m 600 conf/io_monitor %{buildroot}/etc/sysmonitor.d/
install -m 600 conf/zombie %{buildroot}%{_sysconfdir}/sysmonitor/zombie
install -m 500 script/getzombieparent.py %{buildroot}/usr/libexec/sysmonitor/
install -m 500 script/clean_remain_process.sh %{buildroot}/usr/libexec/sysmonitor/

mkdir -p  $RPM_BUILD_ROOT/usr/lib/systemd/system/multi-user.target.wants
mkdir -p  $RPM_BUILD_ROOT/etc/systemd/
install -m 600 conf/logind_monitor %{buildroot}%{_sysconfdir}/sysmonitor.d/
install -m 500 script/logind_clear.sh  %{buildroot}/usr/libexec/sysmonitor/

install -m 0600 service/sysmonitor.service $RPM_BUILD_ROOT/usr/lib/systemd/system/sysmonitor.service
ln -s ../sysmonitor.service $RPM_BUILD_ROOT/usr/lib/systemd/system/multi-user.target.wants/sysmonitor.service

%post
%systemd_post sysmonitor.service

%preun
%systemd_preun sysmonitor.service

%postun
if [ "$1" == "0" ]
then
	rmmod sysmonitor 2>/dev/null 1>/dev/null
fi
%systemd_postun_with_restart sysmonitor.service
depmod -a

%posttrans
for line in $(ls /lib/modules/)
do
	if [ -L /lib/modules/"$line"/weak-updates/sysmonitor/sysmonitor.ko ];then
		rm -rf /lib/modules/"$line"/weak-updates/sysmonitor
	fi
done
depmod -a $(uname -r)
systemctl daemon-reload 2>/dev/null 1>/dev/null

%clean

%files
%defattr(-,root,root)
%dir %{_sysconfdir}/sysmonitor
%dir %{_sysconfdir}/sysmonitor/process
%dir %{_sysconfdir}/sysmonitor.d/
%dir /usr/libexec/
%dir /usr/libexec/sysmonitor
%dir /usr/
%dir %{_sysconfdir}/sysconfig
%dir %attr(0550,root,root) /lib/modules/sysmonitor
%config(noreplace) %{_sysconfdir}/sysconfig/sysmonitor
%config(noreplace) %{_sysconfdir}/sysmonitor/*
%config(noreplace) %{_sysconfdir}/sysmonitor/process/*
%{_bindir}/sysmonitor

/usr/libexec/sysmonitor/*
%attr(0500,root,root) /usr/libexec/sysmonitor/sysmonitor_log_dump.sh
%config(noreplace) %attr(0600,root,root) /usr/libexec/sysmonitor/sysmonitor-logrotate
%exclude /usr/libexec/sysmonitor/*.pyc
%exclude /usr/libexec/sysmonitor/*.pyo
%dir %attr(0700,root,root) /usr/libexec/sysmonitor/data
%attr(0400,root,root) /lib/modules/sysmonitor/sysmonitor.ko

%config(noreplace) /etc/rsyslog.d/sysmonitor.conf
%attr(0500,root,root)  /usr/sbin/iomonitor_daemon
%attr(0600,root,root)  /etc/sysmonitor.d/io_monitor

%config(noreplace) %{_sysconfdir}/sysmonitor.d/*
/usr/lib/systemd/system/sysmonitor.service
/usr/lib/systemd/system/multi-user.target.wants/sysmonitor.service

%changelog
* Sat May 27 2023 xietangxin<xietangxin@huawei.com> - 1.3.2-1.0
- Type:bugfix
- CVE:NA
- SUG:restart
- DESC: init for sysmonitor
