obj-m += kernel_monitor.o
moduleko-objs := kernel_monitor.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

m:
	sudo dmesg -C
	sudo insmod kernel_monitor.ko

u:
	sudo rmmod kernel_monitor.ko
	dmesg

a:
	sudo dmesg -C
	sudo insmod kernel_monitor.ko
	-cd test-program; ./$(program).out
	-sudo rmmod kernel_monitor.ko
	dmesg | grep $(program).out