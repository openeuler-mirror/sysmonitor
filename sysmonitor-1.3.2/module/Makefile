# Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
# Description: make file of sysmonitor
# Author: xuchunmei
# Create: 2018-12-15

obj-m += sysmonitor.o
sysmonitor-objs := sysmonitor_main.o signo_catch.o fdstat.o monitor_netdev.o
KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
EXTRA_CFLAGS += -Wall -Werror

modules:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

modules_install:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules_install

clean:
	$(MAKE) -C $(KERNELDIR) SUBDIRS=$(PWD) clean

.PHONY: modules modules_install clean
