TARGET = simple_vpn
OBJS += svpn_kernel.o netlink.o net_device.o dbg_print.o
OBJS += hooks.o crypto/crypto.o manskb.o session.o
OBJS += conntrack.o
ccflags-y += -std=gnu99 -Wno-declaration-after-statement
EXTRA_CFLAGS = -DEXPORT_SYMTAB -DDEBUG=$(DEBUG)
KVER = $(shell uname -r)
KDIR = /lib/modules/$(KVER)/build
PWD = $(shell pwd)

obj-m := $(TARGET).o
$(TARGET)-objs := $(OBJS)

svpn:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

insmod:
	insmod $(TARGET).ko
rmmod:
	rmmod $(TARGET).ko

clean:
	@$(MAKE) -C $(KDIR) M=$(PWD) clean

-include $(KDIR)/Rules.make
