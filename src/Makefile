# -*- Makefile -*-
MODULES_DIR := /lib/modules/$(shell uname -r)
KERNEL_DIR := ${MODULES_DIR}/build

obj-m += xt_ts3init.o
xt_ts3init-objs += ts3init_module.o ts3init_match.o ts3init_cookie.o ts3init_target.o siphash24.o

all:
	$(MAKE) -C ${KERNEL_DIR} M=$$PWD;

modules:
	$(MAKE) -C ${KERNEL_DIR} M=$$PWD $@;

modules_install:
	$(MAKE) -C ${KERNEL_DIR} M=$$PWD $@;

clean:
	$(MAKE) -C ${KERNEL_DIR} M=$$PWD $@;
