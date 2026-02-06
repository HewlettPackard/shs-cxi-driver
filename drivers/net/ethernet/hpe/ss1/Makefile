KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

export TOPDIR := $(if $(TOPDIR),$(TOPDIR),$(shell readlink -e ..))

KNL_BUILD_ARGS += KBUILD_EXTRA_SYMBOLS="$(TOPDIR)/../slingshot_base_link/drivers/net/ethernet/hpe/sbl/Module.symvers \
	$(TOPDIR)/../sl-driver/staging_dir/lib/modules/module.symvers.sl"

.PHONY: build clean

build:
	$(MAKE) -C $(KDIR) M=$(PWD) modules $(KNL_BUILD_ARGS) W=1

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
