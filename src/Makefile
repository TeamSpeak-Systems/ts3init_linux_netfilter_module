# -*- Makefile -*-
MODULES_DIR := /lib/modules/$(shell uname -r)
KERNEL_DIR := ${MODULES_DIR}/build

obj-m += xt_ts3init.o
xt_ts3init-objs += ts3init_module.o ts3init_match.o ts3init_cookie.o siphash24.o

all:
	make -C ${KERNEL_DIR} M=$$PWD;

modules:
	make -C ${KERNEL_DIR} M=$$PWD $@;

modules_install:
	make -C ${KERNEL_DIR} M=$$PWD $@;

clean:
	make -C ${KERNEL_DIR} M=$$PWD $@;

