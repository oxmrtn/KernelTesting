
MAKEFLAGS += --no-print-directory
obj-m := L3SM.o
SRC_DIR := srcs
INC_DIR := includes
L3SM-y := srcs/L3SM.o srcs/parser.o srcs/rule_list.o


KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

.PHONY: all clean fclean re

all:
	@$(MAKE) -C $(KDIR) M=$(PWD) EXTRA_CFLAGS="-I$(INC_DIR)" modules
clean:
	@$(MAKE) -C $(KDIR) M=$(PWD) clean

fclean: clean
	@rm -f *.ko *.mod.* *.symvers *.order

re: fclean all

push:
	git add .
	git commit -m "sent to test"
	git push

test:
	sudo insmod L3SM.ko
	echo 'ADD{PATH("/tmp"); RIGHT("N"); UID("12345"); ALIAS("rules1")};' > /proc/L3SM/rules
	echo 'ADD{PATH("/tmp"); RIGHT("X"); UID("56789"); ALIAS("rules2")};' > /proc/L3SM/rules
