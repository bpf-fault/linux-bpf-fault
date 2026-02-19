# SPDX-License-Identifier: GPL-2.0-only
#
# Benchmark: userfaultfd vs bpf_fault
#
# Build: make
# Requires: clang, bpftool, libbpf (from the kernel tree)

KDIR     ?= $(abspath ../../../../..)
BPFTOOL  ?= $(KDIR)/tools/bpf/bpftool/bpftool
LIBBPF_SRC = $(KDIR)/tools/lib/bpf
BUILD_DIR  = $(CURDIR)/build
LIBBPF_DIR = $(BUILD_DIR)/libbpf
INCLUDE_DIR = $(BUILD_DIR)/include

CLANG    ?= clang
CC       ?= gcc
HOSTCC   ?= $(CC)

BPF_CFLAGS  = -g -O2 -target bpf -D__TARGET_ARCH_x86
USER_CFLAGS = -g -O2 -Wall -I$(INCLUDE_DIR) -I$(CURDIR)
USER_LDFLAGS = $(LIBBPF_DIR)/libbpf.a -lelf -lz -lzstd -lpthread

VMLINUX_BTF ?= /sys/kernel/btf/vmlinux

all: bench_fault bench_fault_scale bench_fault_shmem test_shmem_fault test_wp_fault bench_fault_wp

# Build libbpf from the kernel tree
$(LIBBPF_DIR)/libbpf.a: $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(LIBBPF_DIR)
	$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1 \
		OUTPUT=$(LIBBPF_DIR)/ DESTDIR=$(BUILD_DIR) prefix= \
		all install_headers

$(LIBBPF_DIR):
	mkdir -p $@

# Generate vmlinux.h from BTF
vmlinux.h: $(BPFTOOL)
	$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $@

# Build bpftool if needed
$(BPFTOOL):
	$(MAKE) -C $(KDIR)/tools/bpf/bpftool

# Compile the BPF program
fault_ops.bpf.o: fault_ops.bpf.c vmlinux.h $(LIBBPF_DIR)/libbpf.a
	$(CLANG) $(BPF_CFLAGS) -I$(INCLUDE_DIR) -c $< -o $@

# Generate BPF skeleton
fault_ops.skel.h: fault_ops.bpf.o $(BPFTOOL)
	$(BPFTOOL) gen skeleton $< > $@

# Compile the userspace benchmarks
bench_fault: bench_fault.c fault_ops.skel.h $(LIBBPF_DIR)/libbpf.a
	$(HOSTCC) $(USER_CFLAGS) -o $@ $< $(USER_LDFLAGS) -static

bench_fault_scale: bench_fault_scale.c fault_ops.skel.h $(LIBBPF_DIR)/libbpf.a
	$(HOSTCC) $(USER_CFLAGS) -o $@ $< $(USER_LDFLAGS) -static

bench_fault_shmem: bench_fault_shmem.c fault_ops.skel.h $(LIBBPF_DIR)/libbpf.a
	$(HOSTCC) $(USER_CFLAGS) -o $@ $< $(USER_LDFLAGS) -static

test_shmem_fault: test_shmem_fault.c fault_ops.skel.h $(LIBBPF_DIR)/libbpf.a
	$(HOSTCC) $(USER_CFLAGS) -o $@ $< $(USER_LDFLAGS) -static

# WP fault test: separate BPF program and skeleton
wp_fault_ops.bpf.o: wp_fault_ops.bpf.c vmlinux.h $(LIBBPF_DIR)/libbpf.a
	$(CLANG) $(BPF_CFLAGS) -I$(INCLUDE_DIR) -c $< -o $@

wp_fault_ops.skel.h: wp_fault_ops.bpf.o $(BPFTOOL)
	$(BPFTOOL) gen skeleton $< > $@

test_wp_fault: test_wp_fault.c wp_fault_ops.skel.h $(LIBBPF_DIR)/libbpf.a
	$(HOSTCC) $(USER_CFLAGS) -o $@ $< $(USER_LDFLAGS) -static

bench_fault_wp: bench_fault_wp.c wp_fault_ops.skel.h $(LIBBPF_DIR)/libbpf.a
	$(HOSTCC) $(USER_CFLAGS) -o $@ $< $(USER_LDFLAGS) -static

clean:
	rm -rf bench_fault bench_fault_scale bench_fault_shmem test_shmem_fault test_wp_fault bench_fault_wp \
		fault_ops.bpf.o fault_ops.skel.h wp_fault_ops.bpf.o wp_fault_ops.skel.h \
		vmlinux.h $(BUILD_DIR)

.PHONY: all clean
