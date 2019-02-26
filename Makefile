
export MAKE=make
export RM=/bin/rm
export DEBUG=1

all: kernel user

kernel:
	make -C kernel

user:
	make -C user

insmod:
	make -C kernel insmod

rmmod:
	make -C kernel rmmod

clean:
	make -C kernel clean
	make -C user clean

.PHONY: kernel user
