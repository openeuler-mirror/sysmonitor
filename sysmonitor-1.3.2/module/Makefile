# Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
# Description: make file of sysmonitor
# Author: xuchunmei
# Create: 2018-12-15

KERNELVER?=$(shell uname -r)

obj-m += sysmonitor.o
sysmonitor-objs := sysmonitor_main.o signo_catch.o fdstat.o monitor_netdev.o
KERNELDIR ?= /lib/modules/$(KERNELVER)/build
PWD := $(shell pwd)
EXTRA_CFLAGS += -Wall -Werror

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNELDIR) SUBDIRS=$(PWD) clean
	rm -f *.ko *.o *.mod.o *.mod.c *.symvers *.order .sysmonitor* .mo* .Module* .signo* sysmonitor.mod .fdstat.*

install:
	install -d -m 750 /lib/modules/sysmonitor
	install -m 640 sysmonitor.ko /lib/modules/sysmonitor
	lsmod | grep -qw sysmonitor && modprobe -r sysmonitor || true
	if [ -e "/lib/modules/sysmonitor/sysmonitor.ko" ];then \
		/sbin/depmod -aeF /boot/System.map-$(KERNELVER) $(KERNELVER) > /dev/null;\
		insmod /lib/modules/sysmonitor/sysmonitor.ko 2>/dev/null 1>/dev/null;\
		if [ $$? -ne 0 ];then { echo "sysmonitor.ko modprobe is failed.";exit 0;} fi;\
	else\
		echo "The /lib/modules/sysmonitor/sysmonitor.ko file does not exist in the sysmonitor rpm package";\
		exit 0; \
	fi

uninstall:
	if [ $(id -u) -ne 0 ]; then { echo "root permission is required to uninstall sysmonitor";exit 0;} fi
	ps h -C sysmonitor -o pid && killall sysmonitor || true
	lsmod | grep -qw sysmonitor && modprobe -r sysmonitor || true
	rm -rf /lib/modules/sysmonitor
	/sbin/depmod -aeF /boot/System.map-$(KERNELVER) $(KERNELVER) > /dev/null
