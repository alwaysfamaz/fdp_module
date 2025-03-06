# FDP Kernel Module Makefile
KDIR := /lib/modules/$(shell uname -r)/build

MODULE_NAME := fdp_module
SRC := fdp_module.c

obj-m := $(MODULE_NAME).o

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install:
	sudo insmod $(MODULE_NAME).ko

uninstall:
	sudo rmmod $(MODULE_NAME)
