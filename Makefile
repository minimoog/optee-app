ROOT            ?= $(HOME)/Developer/optee-qemu
CROSS_COMPILE   ?= $(ROOT)/toolchains/aarch64/bin/aarch64-linux-gnu-
TA_DEV_KIT_DIR  ?= $(ROOT)/optee_os/out/arm/export-ta_arm64
TEEC_EXPORT     ?= $(ROOT)/optee_client/out/export/usr
SHARED          ?= $(HOME)/shared

export CROSS_COMPILE TA_DEV_KIT_DIR TEEC_EXPORT

.PHONY: all ta host clean install

all: ta host

ta:
	$(MAKE) -C ta CROSS_COMPILE=$(CROSS_COMPILE) TA_DEV_KIT_DIR=$(TA_DEV_KIT_DIR)

host:
	$(MAKE) -C host CROSS_COMPILE=$(CROSS_COMPILE) ROOT=$(ROOT)

clean:
	$(MAKE) -C ta clean
	$(MAKE) -C host clean

install: all
	mkdir -p $(SHARED)
	cp ta/*.ta host/my_app $(SHARED)/