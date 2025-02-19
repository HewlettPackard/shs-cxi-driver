export TOPDIR := $(if $(TOPDIR),$(TOPDIR),$(shell readlink -e ..))

LIBNLGENL = libnl-genl-3.0
CFLAGS = -O2 -ggdb -Wall -I$(TOPDIR)/include -I$(TOPDIR)/../cassini-headers/install/include -Werror -D__user= $(shell pkg-config --cflags $(LIBNLGENL))
CC = gcc

exes = test_ucxi test_ucxi_atu test_nlmsg test_csr_access

obj-ucxi = test_ucxi.o test_ucxi_common.o
obj-atu = test_ucxi_atu.o test_ucxi_common.o
obj-rgroup = test_rgroup.o test_ucxi_common.o
obj-rx-profile = test_rx_profile.o test_ucxi_common.o
obj-tx-profile = test_tx_profile.o test_ucxi_common.o
obj-nlmsg = test_nlmsg.o
obj-csr = test_csr_access.o test_ucxi_common.o

all: $(exes)

test_ucxi: $(obj-ucxi) test_ucxi_common.h
	$(CC) $(CFLAGS) -o test_ucxi $(obj-ucxi)

test_ucxi_atu: $(obj-atu) test_ucxi_common.h
	$(CC) $(CFLAGS) -o test_ucxi_atu $(obj-atu)

test_csr_access: $(obj-csr) test_ucxi_common.h
	$(CC) $(CFLAGS) -o test_csr_access $(obj-csr)

test_nlmsg: $(obj-nlmsg) ../include/uapi/misc/cxi.h
	$(CC) $(CFLAGS) $(shell pkg-config --cflags $(LIBNLGENL)) -o test_nlmsg $(obj-nlmsg) $(shell pkg-config --libs $(LIBNLGENL))

clean:
	rm -f $(basename $(exes)) *.o
