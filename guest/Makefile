################################################################################
# 
# Makefile for virtio_scif
#
# Stefanos Gerangelos <sgerag@cslab.ece.ntua.gr>
#
################################################################################

# C compiler to use for building userspace applications
CC = gcc

# Extra CFLAGS used to compile the userspace helpers
# # e.g., -m32 if compiling in a 64-bit environment.
USER_CFLAGS = -Wall -Werror #-m32

# Remove comment to enable verbose output from the kernel build system
KERNEL_VERBOSE = 'V=1'
#DEBUG = n
DEBUG = y

EXTRA_CFLAGS += -Wno-unused-variable -Wno-unused-function
# Add your debugging flag (or not) to CFLAGS
# Warnings are errors.
ifeq ($(DEBUG),y)
  EXTRA_CFLAGS += -g -DDEBUG=1 -Werror
else
  EXTRA_CFLAGS += -DDEBUG=0 -Werror
endif

#obj-m := virtio_scif.o
#virtio_scif-objs := virtio_scif_module.o virtio_scif_chrdev.o virtio_scif_ioctl.o virtio_scif_sysfs.o
obj-m := mic.o
mic-objs := virtio_scif_module.o virtio_scif_chrdev.o virtio_scif_ioctl.o virtio_scif_sysfs.o

#all: modules test_scif test_fork_scif
all: modules

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

modules:
	make -C $(KERNELDIR) M=$(PWD) modules

test_scif: test_scif.c
	$(CC) $(USER_CFLAGS) -o $@ $^

test_fork_scif: test_fork_scif.c
	$(CC) $(USER_CFLAGS) -o $@ $^

clean:
	make -C $(KERNELDIR) M=$(PWD) clean
	rm -f test_scif
	rm -f test_fork_scif
