#
# Makefile for the Linux eCryptfs
#

ccflags-y := -Werror -O0
obj-m += ecryptfs.o

ecryptfs-y := dentry.o file.o inode.o main.o super.o mmap.o read_write.o \
	      crypto.o keystore.o kthread.o debug.o async_io.o #messaging.o miscdev.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=`pwd`

clean:
	rm -rf *.o *.mod.c modules.* Module.* *.ko

