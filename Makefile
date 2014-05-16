obj-m += nf_ipcomp.o
nf_ipcomp-objs := ipcomp.o zlib.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	make -C $(KDIR) M=$(PWD) modules
clean:
	make -C $(KDIR) M=$(PWD) clean
