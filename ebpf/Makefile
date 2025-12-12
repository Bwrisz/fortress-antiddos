CLANG ?= clang
LLC ?= llc
BPFTOOL ?= bpftool

ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
KERNEL_HEADERS := /usr/src/linux-headers-$(shell uname -r)

BPF_CFLAGS := -g -O2 -target bpf
BPF_CFLAGS += -D__TARGET_ARCH_$(ARCH)
BPF_CFLAGS += -I$(KERNEL_HEADERS)/include
BPF_CFLAGS += -I$(KERNEL_HEADERS)/include/uapi
BPF_CFLAGS += -I$(KERNEL_HEADERS)/arch/$(ARCH)/include
BPF_CFLAGS += -I/usr/include/bpf
BPF_CFLAGS += -Wall -Wno-unused-value -Wno-pointer-sign
BPF_CFLAGS += -Wno-compare-distinct-pointer-types

SRCS := xdp_fortress.c
OBJS := $(SRCS:.c=.o)

all: $(OBJS)

%.o: %.c common.h maps.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

clean:
	rm -f *.o

install: all
	mkdir -p /opt/fortress/ebpf
	cp *.o /opt/fortress/ebpf/
	cp *.h /opt/fortress/ebpf/

.PHONY: all clean install
