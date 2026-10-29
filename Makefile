# axiom-lsm — governed egress for real Linux processes (BPF LSM).
CLANG ?= clang
VMLINUX ?= /sys/kernel/btf/vmlinux
# /usr/sbin/bpftool is a version shim that refuses to run on WSL's custom
# kernel; the real binary lives under linux-tools-*.
BPFTOOL ?= $(shell ls /usr/lib/linux-tools*/bpftool 2>/dev/null | head -1 || echo bpftool)

all: bpf/lsm.bpf.o src/lsm.skel.h axiom-lsm

bpf/vmlinux.h:
	$(BPFTOOL) btf dump file $(VMLINUX) format c > $@

bpf/lsm.bpf.o: bpf/lsm.bpf.c bpf/vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_x86 -Ibpf -c $< -o $@

src/lsm.skel.h: bpf/lsm.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

axiom-lsm: src/loader.c src/lsm.skel.h
	$(CC) -g -O2 -I src -o $@ src/loader.c -lbpf -lelf -lz

clean:
	rm -f bpf/lsm.bpf.o bpf/vmlinux.h src/lsm.skel.h axiom-lsm

.PHONY: all clean
