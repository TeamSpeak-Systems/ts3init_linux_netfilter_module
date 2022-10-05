# -*- Makefile -*-
KVER := $(shell uname -r)
MODULES_DIR := /lib/modules/${KVER}
KERNEL_DIR := ${MODULES_DIR}/build

obj-m += xt_ts3init.o
xt_ts3init-objs += ts3init_module.o ts3init_match.o ts3init_cookie.o ts3init_target.o ts3init_cache.o siphash24.o
ccflags-$(CONFIG_CRYPTO_HASH_INFO) += -DHAS_CRYPTO_HASH_INFO=1

all:
	$(MAKE) -C ${KERNEL_DIR} M=$$PWD;

modules:
	$(MAKE) -C ${KERNEL_DIR} M=$$PWD $@;

modules_install:
	$(MAKE) -C ${KERNEL_DIR} M=$$PWD $@;

clean:
	$(MAKE) -C ${KERNEL_DIR} M=$$PWD $@;
