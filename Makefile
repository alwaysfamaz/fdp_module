# Makefile for fdp_module_patch (standalone kernel module)

KVER ?= $(shell uname -r)
KDIR ?= /lib/modules/$(KVER)/build
PWD  := $(shell pwd)

MODULE_NAME := fdp_module

# DEBUG / STAT flag
# EXTRA_CFLAGS += -DFM_DEBUG
# EXTRA_CFLAGS += -DFM_STAT

# Module
obj-m := $(MODULE_NAME).o

.PHONY: all modules clean load unload reload dmesg help

all: modules

modules:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

# Module load / unload
load: $(MODULE_NAME).ko
	@if [ -z "$(DEV_INFO)" ]; then \
	  echo "Usage: sudo make load DEV_INFO=\"tbytes:...:lba_sz:...:chnk_sz:...:max_ruh:...:decay_period:...\""; \
	  exit 1; \
	fi
	sudo insmod ./$(MODULE_NAME).ko dev_info="$(DEV_INFO)"

unload:
	- sudo rmmod $(MODULE_NAME)

reload: unload load

dmesg:
	dmesg -T | tail -n 100

help:
	@echo "Targets:"
	@echo "  make / make modules         - build module"
	@echo "  make clean                  - clean"
	@echo "  sudo make load DEV_INFO=... - insmod with parameter"
	@echo "  sudo make unload            - rmmod"
	@echo "  make dmesg                  - show recent kernel log"
	@echo "Vars:"
	@echo "  KVER=<kernel version> (default: uname -r)"
	@echo "  KDIR=<kernel build dir> (default: /lib/modules/\$$(uname -r)/build)"
	@echo "  DEV_INFO='tbytes:...:lba_sz:...:chnk_sz:...:max_ruh:...:decay_period:...'"
