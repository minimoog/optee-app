ROOT    ?= $(HOME)/Developer/optee-qemu
SYSROOT ?= $(ROOT)/out-br/host/aarch64-buildroot-linux-gnu/sysroot

CC      = $(CROSS_COMPILE)gcc
LD      = $(CROSS_COMPILE)ld
AR      = $(CROSS_COMPILE)ar
NM      = $(CROSS_COMPILE)nm
OBJCOPY = $(CROSS_COMPILE)objcopy
OBJDUMP = $(CROSS_COMPILE)objdump
READELF = $(CROSS_COMPILE)readelf

OBJS = main.o

CFLAGS += -Wall -I../ta/include -I./include -I$(ROOT)/optee_client/libteec/include
# Add/link other required libraries here
LDADD += $(SYSROOT)/usr/lib/libteec.so

BINARY = my_app

.PHONY: all
all: $(BINARY)

$(BINARY): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $< $(LDADD)

.PHONY: clean
clean:
	rm -f $(OBJS) $(BINARY)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@
