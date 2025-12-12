CLANG ?= clang
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
CFLAGS = -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) -Wall

all: xdp_filter.o

xdp_filter.o: xdp_filter.c
	$(CLANG) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o

install: all
	mkdir -p /opt/fortress/xdp
	cp xdp_filter.o /opt/fortress/xdp/

.PHONY: all clean install
