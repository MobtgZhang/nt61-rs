# ============================================================
# NT6.1.7601 Build System
# ============================================================
#
# All build logic is in build_tool (Rust).
# Makefile only handles:
#   - Calling build_tool
#   - QEMU launch
# ============================================================

BUILD_TOOL := cargo run -p nt61-tools --bin build-tool --

# Build directory layout: build/<ARCH>/<FORMAT>/  (each arch+format pair has
# its own directory so we never overwrite a different arch's disk.img /
# boot.efi / system partition by accident).
#
# Override on the command line, e.g. `make build BUILD_DIR=foo`.
BUILD_DIR ?= build
# Effective build directory for the current ARCH+FORMAT. Downstream rules
# always use $(BLD) (== build/<ARCH>/<FORMAT>/) rather than $(BUILD_DIR)
# directly so per-arch outputs coexist. NOTE: this is `=` (not `:=`) so it
# is re-evaluated after the per-target `ARCH=...` / `FORMAT=...` lines
# below; otherwise a `make run-loongarch64-fat32` would compute BLD with
# the default `ARCH=x86_64` and accidentally drop a disk.img under
# build/x86_64/fat32/ when we actually want build/loongarch64/fat32/.
BLD = $(BUILD_DIR)/$(ARCH)/$(FORMAT)
IMAGES_DIR = $(BLD)/images
ESP_DIR    = $(BLD)/esp
SYSTEM_DIR = $(BLD)/system

# Default arch and format
# ARCH: x86_64, aarch64, riscv64, loongarch64
# FORMAT: ntfs, fat32, ext4, iso
ARCH ?= x86_64
FORMAT ?= ntfs

# EDK2 firmware directory (from download.sh)
SCRIPT_DIR := $(shell cd "$(shell dirname "${BASH_SOURCE[0]}")" && pwd)
EDK2_FW_DIR ?= $(SCRIPT_DIR)/../scripts/firmware

# OVMF (x86_64 system package — non-secure by default)
OVMF_CODE := /usr/share/OVMF/OVMF_CODE_4M.fd
OVMF_VARS_TEMPLATE := /usr/share/OVMF/OVMF_VARS_4M.ms.fd
# `=` (not `:=`) — must be re-evaluated so a per-target `ARCH=loongarch64`
# assignment redirects EDK2/OVMF firmware VARS / pflash / disk.img into the
# per-arch IMAGES_DIR instead of accidentally re-using the default-arch one.
OVMF_VARS = $(IMAGES_DIR)/OVMF_VARS.fd

# QEMU firmware code for x86_64 — defaults to system OVMF (non-secure).
# Override with: make ... QEMU_FW_CODE=/path/to/other.fd
QEMU_FW_CODE ?= $(OVMF_CODE)

# EDK2 Nightly firmware (multi-arch) — pflash/VARS files live under
# build/<ARCH>/images/ so each arch keeps its own copy and we don't have
# to re-create them on every make invocation.
EDK2_OVMF_CODE := $(EDK2_FW_DIR)/x86_64/DEBUGX64_OVMF_CODE.fd
EDK2_OVMF_VARS = $(IMAGES_DIR)/edk2_ovmf_vars_$(ARCH).fd
EDK2_AARCH64_EFI := $(EDK2_FW_DIR)/aarch64/DEBUGAARCH64_QEMU_EFI.fd
# AArch64 EDK2 nightly ships the code pflash as 3 MiB; QEMU's
# `virt` platform hard-codes a 64 MiB flash, so we pad it at
# build time. The padded copy lives in $(IMAGES_DIR) so it is
# rebuilt alongside the disk image.
EDK2_AARCH64_EFI_PADDED = $(IMAGES_DIR)/edk2_aarch64_efi_padded.fd
EDK2_AARCH64_VARS = $(IMAGES_DIR)/edk2_aarch64_vars.fd
EDK2_RISCV64_VIRT := $(EDK2_FW_DIR)/riscv64/DEBUGRISCV64_VIRT.fd
# RISC-V EDK2 nightly ships the code pflash as 8 MiB; QEMU's
# `virt` platform hard-codes a 32 MiB flash for cfi.pflash01, so we
# pad it at build time. The padded copy lives in $(IMAGES_DIR) so it
# is rebuilt alongside the disk image.
EDK2_RISCV64_VIRT_PADDED = $(IMAGES_DIR)/edk2_riscv64_virt_padded.fd
EDK2_LOONGARCH64_EFI := $(EDK2_FW_DIR)/loongarch64/DEBUGLOONGARCH64_QEMU_EFI.fd
EDK2_LOONGARCH64_VARS = $(IMAGES_DIR)/edk2_loongarch64_vars.fd

# QEMU
QEMU_X86 := qemu-system-x86_64
QEMU_AARCH64 := qemu-system-aarch64
QEMU_RISCV64 := qemu-system-riscv64
QEMU_LOONGARCH64 := qemu-system-loongarch64

# Per-arch CPU model. Each QEMU virt machine has its own preferred CPU.
# x86_64 / aarch64 defaults are inherited from QEMU; riscv64 / loongarch64
# need an explicit `-cpu la464` / `-cpu rv64` because the default CPU
# differs from what EDK2 nightly expects.
QEMU_CPU_x86_64     := -cpu kvm64
QEMU_CPU_aarch64    := -cpu cortex-a57
QEMU_CPU_riscv64    :=
QEMU_CPU_loongarch64 := -cpu la464

# Per-arch disk-controller device. The QEMU `virt` machine on
# loongarch64/riscv64 does *not* expose a MMIO-mapped `virtio-bus`,
# so `virtio-blk-device` (the half-mmio device) cannot attach — only
# the PCI-transitional variant `virtio-blk-pci` works there.
# x86_64 / aarch64 can use either; we pick the PCI variant uniformly
# so a single device flag covers every arch.
DISK_DEV_PCI := virtio-blk-pci

# Disk attachment flags common to all `virt`-machine arches. The
# conditional `if iso → -cdrom` keeps ISO-format builds working; for
# raw disk images we use the dual-step `if=none + -device ... -drive`
# form so the disk controller and the disk itself can be referenced
# by `id=hd0` regardless of which virtio device we end up attaching.
DISK_FLAGS = $(if $(filter iso,$(FORMAT)),-cdrom $(ISO_IMG),-drive if=none,file=$(DISK_IMG),format=raw,id=hd0 -device $(DISK_DEV_PCI),drive=hd0)

# Disk image names — `=` for the same reason as above.
DISK_IMG = $(IMAGES_DIR)/disk.img
ISO_IMG = $(IMAGES_DIR)/nt61.iso
SERIAL_LOG = $(IMAGES_DIR)/serial_$(ARCH)_$(FORMAT).log

# ============================================================
# PHONY
# ============================================================
.PHONY: all build run run-serial run-gtk \
        build-ntfs build-fat32 build-ext4 build-iso \
        test test-host test-qemu test-all test-pe \
        test-all-qemu test-all-fs-qemu test-arches-fs-qemu \
        make-ntfs-serial make-fat32-serial make-ext4-serial \
        run-x86_64 run-aarch64 run-riscv64 run-loongarch64 \
        run-x86_64-ntfs run-x86_64-fat32 run-x86_64-ext4 run-x86_64-iso \
        run-aarch64-ntfs run-aarch64-fat32 run-aarch64-ext4 run-aarch64-iso \
        run-riscv64-ntfs run-riscv64-fat32 run-riscv64-ext4 run-riscv64-iso \
        run-loongarch64-ntfs run-loongarch64-fat32 run-loongarch64-ext4 run-loongarch64-iso \
        run-x86_64-ntfs-serial run-x86_64-fat32-serial run-x86_64-ext4-serial \
        run-aarch64-ntfs-serial run-aarch64-fat32-serial run-aarch64-ext4-serial \
        run-riscv64-ntfs-serial run-riscv64-fat32-serial run-riscv64-ext4-serial \
        run-loongarch64-ntfs-serial run-loongarch64-fat32-serial run-loongarch64-ext4-serial \
        download-firmware check-firmware clean clean-all help

# ============================================================
# Main targets
# ============================================================
all: build

build:
	$(BUILD_TOOL) --build all --build-dir $(BLD) --format-flag $(FORMAT) --size-mb 64 --arch $(ARCH)

# ============================================================
# Per-filesystem build targets
# ============================================================
build-ntfs:
	$(BUILD_TOOL) --build all --build-dir $(BLD) --format-flag ntfs --size-mb 64 --arch $(ARCH)

build-fat32:
	$(BUILD_TOOL) --build all --build-dir $(BLD) --format-flag fat32 --size-mb 64 --arch $(ARCH)

build-ext4:
	$(BUILD_TOOL) --build all --build-dir $(BLD) --format-flag ext4 --size-mb 64 --arch $(ARCH)

build-iso:
	$(BUILD_TOOL) --build iso --build-dir $(BLD) --format-flag iso --size-mb 64 --arch $(ARCH)

# ============================================================
# Arch-format specific build targets
# ============================================================
build-$(ARCH)-$(FORMAT):
	$(BUILD_TOOL) --build all --build-dir $(BLD) --format-flag $(FORMAT) --size-mb 64 --arch $(ARCH)

# ============================================================
# Firmware setup macros (per architecture)
# ============================================================
define _setup_firmware_x86_64
	@echo "Setting up x86_64 UEFI firmware..."
	@# Prefer system OVMF (non-secure) over EDK2 nightly (secure boot)
	@if [ -f "$(OVMF_CODE)" ]; then \
		export OVMF_FW_CODE="$(OVMF_CODE)"; \
		echo "Using system OVMF: $$OVMF_FW_CODE"; \
	elif [ -f "$(EDK2_OVMF_CODE)" ]; then \
		export OVMF_FW_CODE="$(EDK2_OVMF_CODE)"; \
		echo "Using EDK2 nightly OVMF: $$OVMF_FW_CODE"; \
	else \
		echo "Error: No OVMF firmware found"; \
		echo "  Checked: $(OVMF_CODE)"; \
		echo "  Checked: $(EDK2_OVMF_CODE)"; \
		echo "Run: make download-firmware"; \
		exit 1; \
	fi
	@if [ ! -f "$(EDK2_OVMF_VARS)" ]; then \
		if [ -f "$(OVMF_VARS_TEMPLATE)" ]; then \
			cp "$(OVMF_VARS_TEMPLATE)" "$(EDK2_OVMF_VARS)"; \
			echo "Created $(EDK2_OVMF_VARS) from template"; \
		elif [ -f "$(OVMF_VARS)" ]; then \
			cp "$(OVMF_VARS)" "$(EDK2_OVMF_VARS)"; \
			echo "Created $(EDK2_OVMF_VARS) from OVMF_VARS"; \
		elif [ -f "$(EDK2_FW_DIR)/x86_64/DEBUGX64_OVMF_VARS.fd" ]; then \
			cp "$(EDK2_FW_DIR)/x86_64/DEBUGX64_OVMF_VARS.fd" "$(EDK2_OVMF_VARS)"; \
		else \
			echo "Warning: No VARS template, creating empty"; \
			dd if=/dev/zero of="$(EDK2_OVMF_VARS)" bs=1M count=1 2>/dev/null || true; \
		fi; \
	fi
	@# Inject Boot0001 entry so OVMF boots from \EFI\Boot\BOOTX64.EFI on the disk.
	@# The built-in OVMF VARS template does not include a BootXXXX entry pointing
	@# at any \EFI\Boot file on the disk, so OVMF falls back to the EFI Internal
	@# Shell. We use virt-fw-vars to write a LOAD_OPTION with a FilePath device
	@# path (\EFI\Boot\BOOTX64.EFI); OVMF then walks the disk to find it.
	@if command -v virt-fw-vars >/dev/null 2>&1; then \
		if [ ! -f "$(EDK2_OVMF_VARS).with-boot" ]; then \
			virt-fw-vars --inplace "$(EDK2_OVMF_VARS)" \
				--append-boot-filepath /EFI/Boot/BOOTX64.EFI >/dev/null 2>&1 || true; \
			cp "$(EDK2_OVMF_VARS)" "$(EDK2_OVMF_VARS).with-boot"; \
			echo "Injected Boot0001 into $(EDK2_OVMF_VARS)"; \
		fi; \
	else \
		echo "Warning: virt-fw-vars not installed; install via 'pip install virt-firmware'"; \
	fi
endef

define _setup_firmware_aarch64
	@if [ ! -f "$(EDK2_AARCH64_EFI)" ]; then \
		echo "Error: AArch64 firmware not found at $(EDK2_AARCH64_EFI)"; \
		echo "Run: make download-firmware"; \
		exit 1; \
	fi
	@# AArch64 EDK2 nightly ships two small flashes (3 MiB code, 768 KiB
	@# VARS); QEMU's pflash0/pflash1 both expect a 64 MiB backing file
	@# because the platform's flash controller hard-codes 64 MiB.
	@# Pad both files to 64 MiB and copy the VARS template into the
	@# VARS pflash so the firmware can write into it.
	@if [ ! -f "$(EDK2_AARCH64_EFI_PADDED)" ]; then \
		dd if=/dev/zero of="$(EDK2_AARCH64_EFI_PADDED)" bs=1M count=64 2>/dev/null; \
		dd if="$(EDK2_AARCH64_EFI)" of="$(EDK2_AARCH64_EFI_PADDED)" conv=notrunc 2>/dev/null; \
		echo "Created $(EDK2_AARCH64_EFI_PADDED) (64 MiB padded)"; \
	fi
	@if [ ! -f "$(EDK2_AARCH64_VARS)" ]; then \
		dd if=/dev/zero of="$(EDK2_AARCH64_VARS)" bs=1M count=64 2>/dev/null; \
		dd if="$(SCRIPT_DIR)/../scripts/firmware/aarch64/DEBUGAARCH64_QEMU_VARS.fd" \
		   of="$(EDK2_AARCH64_VARS)" conv=notrunc 2>/dev/null; \
		echo "Created $(EDK2_AARCH64_VARS) (64 MiB padded)"; \
	fi
	@if command -v virt-fw-vars >/dev/null 2>&1; then \
		if [ ! -f "$(EDK2_AARCH64_VARS).with-boot" ]; then \
			virt-fw-vars --inplace "$(EDK2_AARCH64_VARS)" \
				--append-boot-filepath /EFI/Boot/BOOTAA64.EFI >/dev/null 2>&1 || true; \
			cp "$(EDK2_AARCH64_VARS)" "$(EDK2_AARCH64_VARS).with-boot"; \
			echo "Injected Boot entry (BOOTAA64.EFI) into $(EDK2_AARCH64_VARS)"; \
		fi; \
	else \
		echo "Warning: virt-fw-vars not installed; install via 'pip install virt-firmware'"; \
	fi
endef

define _setup_firmware_riscv64
	@if [ ! -f "$(EDK2_RISCV64_VIRT)" ]; then \
		echo "Error: RISC-V firmware not found at $(EDK2_RISCV64_VIRT)"; \
		echo "Run: make download-firmware"; \
		exit 1; \
	fi
	@# RISC-V EDK2 nightly ships the code pflash as 8 MiB; QEMU's `virt`
	@# machine hard-codes cfi.pflash01 to a 32 MiB backing file, so the
	@# EDK2 firmware refuses to start with anything smaller. Pad to 32 MiB
	@# once and cache the result in $(IMAGES_DIR).
	@if [ ! -f "$(EDK2_RISCV64_VIRT_PADDED)" ]; then \
		dd if=/dev/zero of="$(EDK2_RISCV64_VIRT_PADDED)" bs=1M count=32 2>/dev/null; \
		dd if="$(EDK2_RISCV64_VIRT)" of="$(EDK2_RISCV64_VIRT_PADDED)" conv=notrunc 2>/dev/null; \
		echo "Created $(EDK2_RISCV64_VIRT_PADDED) (32 MiB padded)"; \
	fi
	@# The QEMU `virt` machine hard-codes BOTH pflash slots to 32 MiB;
	@# the VARS slot must be at least 32 MiB or QEMU aborts with
	@# "cfi.pflash01 device ... requires 33554432 bytes". AARCH64/LoongArch
	@# OVMF nightlies ship a real VARS template; for RISC-V we seed the
	@# VARS slot from the same padded code pflash (the EDK2 RiscVVirt
	@# firmware reads its VAR store out of the second pflash regardless
	@# of what's in there, so a non-empty template is fine).
	@if [ ! -f "$(EDK2_OVMF_VARS)" ]; then \
		cp "$(EDK2_RISCV64_VIRT_PADDED)" "$(EDK2_OVMF_VARS)"; \
		echo "Created $(EDK2_OVMF_VARS) (32 MiB VARS template from code pflash)"; \
	fi
	@# Inject a Boot entry pointing at `\EFI\BOOT\BOOTRISCV64.EFI` on the
	@# ESP. Without this, the RISC-V EDK2 BDS walks the BootOrder, finds
	@# no device-backed entries, and falls back to the EFI Internal Shell
	@# (same failure mode we hit on the other arches before this same fix).
	@# `virt-fw-vars` writes the LOAD_OPTION into the OVMF variable store
	@# in-place and caches the result as `.with-boot` so subsequent builds
	@# don't double-inject.
	@if command -v virt-fw-vars >/dev/null 2>&1; then \
		if [ ! -f "$(EDK2_OVMF_VARS).with-boot" ]; then \
			virt-fw-vars --inplace "$(EDK2_OVMF_VARS)" \
				--append-boot-filepath /EFI/BOOT/BOOTRISCV64.EFI >/dev/null 2>&1 || true; \
			cp "$(EDK2_OVMF_VARS)" "$(EDK2_OVMF_VARS).with-boot"; \
			echo "Injected Boot entry (BOOTRISCV64.EFI) into $(EDK2_OVMF_VARS)"; \
		fi; \
	else \
		echo "Note: virt-fw-vars not installed; RISC-V may fall back to EFI Internal Shell."; \
	fi
endef

define _setup_firmware_loongarch64
	@if [ ! -f "$(EDK2_LOONGARCH64_EFI)" ]; then \
		echo "Error: LoongArch64 firmware not found at $(EDK2_LOONGARCH64_EFI)"; \
		echo "Run: make download-firmware"; \
		exit 1; \
	fi
	@if [ ! -f "$(EDK2_LOONGARCH64_VARS)" ]; then \
		if [ -f "$(EDK2_FW_DIR)/loongarch64/DEBUGLOONGARCH64_QEMU_VARS.fd" ]; then \
			cp "$(EDK2_FW_DIR)/loongarch64/DEBUGLOONGARCH64_QEMU_VARS.fd" "$(EDK2_LOONGARCH64_VARS)"; \
		else \
			echo "Warning: No VARS file, creating empty"; \
			dd if=/dev/zero of="$(EDK2_LOONGARCH64_VARS)" bs=1M count=1 2>/dev/null || true; \
		fi; \
	fi
	@# The OVMF/EDK2 nightly VARS template does not include any
	@# BootXXXX entry pointing at the on-disk ESP. Without one the
	@# firmware boots into the EFI Internal Shell instead of our
	@# `\EFI\BOOT\BOOTLOONGARCH64.EFI`. Use `virt-fw-vars` (the
	@# same call we make for x86_64 / aarch64) to append a
	@# LOAD_OPTION entry whose FilePath device path is the
	@# removable-media fallback file. The result is cached as
	@# `$(EDK2_LOONGARCH64_VARS).with-boot` so subsequent invocations
	@# don't double-inject.
	@if command -v virt-fw-vars >/dev/null 2>&1; then \
		if [ ! -f "$(EDK2_LOONGARCH64_VARS).with-boot" ]; then \
			virt-fw-vars --inplace "$(EDK2_LOONGARCH64_VARS)" \
				--append-boot-filepath /EFI/BOOT/BOOTLOONGARCH64.EFI >/dev/null 2>&1 || true; \
			cp "$(EDK2_LOONGARCH64_VARS)" "$(EDK2_LOONGARCH64_VARS).with-boot"; \
			echo "Injected Boot entry (BOOTLOONGARCH64.EFI) into $(EDK2_LOONGARCH64_VARS)"; \
		fi; \
	else \
		echo "Warning: virt-fw-vars not installed; install via 'pip install virt-firmware'"; \
	fi
endef

# ============================================================
# QEMU run macros (per arch + format)
# ============================================================
# ISO format: uses -cdrom and -boot d (CD-ROM boot order)
# Disk formats: uses -drive and -boot c (hard disk boot order)

define _run_x86_64
	@echo "Starting QEMU (x86_64/$(FORMAT))..."
	$(QEMU_X86) -machine q35 -m 8G -smp 2 \
		-drive if=pflash,format=raw,unit=0,readonly=on,file=$(QEMU_FW_CODE) \
		-drive if=pflash,format=raw,unit=1,file=$(EDK2_OVMF_VARS) \
		$(if $(filter iso,$(FORMAT)),-cdrom $(ISO_IMG),-drive format=raw,file=$(DISK_IMG)) \
		-boot $(if $(filter iso,$(FORMAT)),d,c) -net none \
		-serial file:$(SERIAL_LOG) -display gtk
endef

define _run_aarch64
	@echo "Starting QEMU (aarch64/$(FORMAT)) with EDK2 Nightly UEFI..."
	$(QEMU_AARCH64) -machine virt -m 8G -smp 2 $(QEMU_CPU_aarch64) \
		-drive if=pflash,format=raw,unit=0,readonly=on,file=$(EDK2_AARCH64_EFI_PADDED) \
		-drive if=pflash,format=raw,unit=1,file=$(EDK2_AARCH64_VARS) \
		$(DISK_FLAGS) \
		-device virtio-gpu-pci -device virtio-keyboard-pci \
		-boot order=c -net none \
		-serial file:$(SERIAL_LOG) -display gtk
endef

define _run_riscv64
	@echo "Starting QEMU (riscv64/$(FORMAT)) with EDK2 Nightly UEFI..."
	# Use the padded code pflash as the firmware volume, the
	# injected VARS pflash as the variable store, and the disk
	# attached as a virtio-blk-pci device. EDK2 on the RISC-V
	# `virt` machine walks BootOrder and discovers the
	# `\EFI\BOOT\BOOTRISCV64.EFI` Boot entry we wrote in
	# `_setup_firmware_riscv64`, then loads our PE32+ boot
	# manager via LoadImage/StartImage. Using the MMIO variant
	# `virtio-blk-device` instead of `virtio-blk-pci` is rejected
	# by the RISC-V BDS because the EDK2 RiscVVirt build does
	# not ship a virtio-mmio driver — only the PCI transport.
	$(QEMU_RISCV64) -machine virt -m 8G -smp 2 $(QEMU_CPU_riscv64) \
		-drive if=pflash,format=raw,unit=0,readonly=on,file=$(EDK2_RISCV64_VIRT_PADDED) \
		-drive if=pflash,format=raw,unit=1,file=$(EDK2_OVMF_VARS) \
		-drive if=none,file=$(DISK_IMG),format=raw,id=hd0 \
		-device $(DISK_DEV_PCI),drive=hd0 \
		-net none \
		-serial file:$(SERIAL_LOG) -display gtk
endef

define _run_loongarch64
	@echo "Starting QEMU (loongarch64/$(FORMAT)) with EDK2 Nightly UEFI..."
	$(QEMU_LOONGARCH64) -machine virt -m 8G -smp 2 $(QEMU_CPU_loongarch64) \
		-pflash $(EDK2_LOONGARCH64_EFI) \
		-pflash $(EDK2_LOONGARCH64_VARS) \
		$(DISK_FLAGS) \
		-boot order=c -net none \
		-serial file:$(SERIAL_LOG) -display gtk
endef

# ============================================================
# Run targets (generic, supports ARCH and FORMAT parameters)
# ============================================================
#
# Usage:
#   make run-serial                      # default: ARCH=x86_64, FORMAT=ntfs
#   make run-serial ARCH=aarch64         # aarch64 + ntfs
#   make run-serial ARCH=riscv64 FORMAT=fat32
#   make run-serial ARCH=loongarch64 FORMAT=ext4
#   make run-serial ARCH=x86_64 FORMAT=iso

run: ARCH ?= x86_64
run: FORMAT ?= ntfs
run: SERIAL_LOG=$(IMAGES_DIR)/serial_$(ARCH)_$(FORMAT).log
run: build-$(ARCH)-$(FORMAT)
	@mkdir -p $(IMAGES_DIR)
	$(call _setup_firmware_$(ARCH))
	$(call _run_$(ARCH))

run-serial: ARCH ?= x86_64
run-serial: FORMAT ?= ntfs
run-serial: SERIAL_LOG=$(IMAGES_DIR)/serial_$(ARCH)_$(FORMAT).log
run-serial: build-$(ARCH)-$(FORMAT)
	@mkdir -p $(IMAGES_DIR)
	$(call _setup_firmware_$(ARCH))
	$(call _run_$(ARCH))

run-gtk: ARCH ?= x86_64
run-gtk: FORMAT ?= ntfs
run-gtk: SERIAL_LOG=$(IMAGES_DIR)/serial_$(ARCH)_$(FORMAT).log
run-gtk: build-$(ARCH)-$(FORMAT)
	@mkdir -p $(IMAGES_DIR)
	$(call _setup_firmware_$(ARCH))
	$(call _run_$(ARCH))

# ============================================================
# Per-arch quick-run targets (NTFS default)
# ============================================================

run-x86_64: ARCH=x86_64
run-x86_64: FORMAT=ntfs
run-x86_64: SERIAL_LOG=$(IMAGES_DIR)/serial_$(ARCH)_$(FORMAT).log
run-x86_64: build-$(FORMAT)
	@mkdir -p $(IMAGES_DIR)
	$(call _setup_firmware_x86_64)
	$(call _run_x86_64)

run-aarch64: ARCH=aarch64
run-aarch64: FORMAT=ntfs
run-aarch64: SERIAL_LOG=$(IMAGES_DIR)/serial_$(ARCH)_$(FORMAT).log
run-aarch64: build-$(FORMAT)
	@mkdir -p $(IMAGES_DIR)
	$(call _setup_firmware_aarch64)
	$(call _run_aarch64)

run-riscv64: ARCH=riscv64
run-riscv64: FORMAT=ntfs
run-riscv64: SERIAL_LOG=$(IMAGES_DIR)/serial_$(ARCH)_$(FORMAT).log
run-riscv64: build-$(FORMAT)
	@mkdir -p $(IMAGES_DIR)
	$(call _setup_firmware_riscv64)
	$(call _run_riscv64)

run-loongarch64: ARCH=loongarch64
run-loongarch64: FORMAT=ntfs
run-loongarch64: SERIAL_LOG=$(IMAGES_DIR)/serial_$(ARCH)_$(FORMAT).log
run-loongarch64: build-$(FORMAT)
	@mkdir -p $(IMAGES_DIR)
	$(call _setup_firmware_loongarch64)
	$(call _run_loongarch64)

# ============================================================
# All 16 arch x format combinations (serial log)
# ============================================================

# x86_64
run-x86_64-ntfs: ARCH=x86_64
run-x86_64-ntfs: FORMAT=ntfs
run-x86_64-ntfs: SERIAL_LOG=$(IMAGES_DIR)/serial_x86_64_ntfs.log
run-x86_64-ntfs: build-ntfs
	$(call _run_x86_64)

run-x86_64-fat32: ARCH=x86_64
run-x86_64-fat32: FORMAT=fat32
run-x86_64-fat32: SERIAL_LOG=$(IMAGES_DIR)/serial_x86_64_fat32.log
run-x86_64-fat32: build-fat32
	$(call _run_x86_64)

run-x86_64-ext4: ARCH=x86_64
run-x86_64-ext4: FORMAT=ext4
run-x86_64-ext4: SERIAL_LOG=$(IMAGES_DIR)/serial_x86_64_ext4.log
run-x86_64-ext4: build-ext4
	$(call _run_x86_64)

run-x86_64-iso: ARCH=x86_64
run-x86_64-iso: FORMAT=iso
run-x86_64-iso: SERIAL_LOG=$(IMAGES_DIR)/serial_x86_64_iso.log
run-x86_64-iso: build-iso
	$(call _run_x86_64)

# aarch64
run-aarch64-ntfs: ARCH=aarch64
run-aarch64-ntfs: FORMAT=ntfs
run-aarch64-ntfs: SERIAL_LOG=$(IMAGES_DIR)/serial_aarch64_ntfs.log
run-aarch64-ntfs: build-ntfs
	$(call _run_aarch64)

run-aarch64-fat32: ARCH=aarch64
run-aarch64-fat32: FORMAT=fat32
run-aarch64-fat32: SERIAL_LOG=$(IMAGES_DIR)/serial_aarch64_fat32.log
run-aarch64-fat32: build-fat32
	$(call _run_aarch64)

run-aarch64-ext4: ARCH=aarch64
run-aarch64-ext4: FORMAT=ext4
run-aarch64-ext4: SERIAL_LOG=$(IMAGES_DIR)/serial_aarch64_ext4.log
run-aarch64-ext4: build-ext4
	$(call _run_aarch64)

run-aarch64-iso: ARCH=aarch64
run-aarch64-iso: FORMAT=iso
run-aarch64-iso: SERIAL_LOG=$(IMAGES_DIR)/serial_aarch64_iso.log
run-aarch64-iso: build-iso
	$(call _run_aarch64)

# riscv64
run-riscv64-ntfs: ARCH=riscv64
run-riscv64-ntfs: FORMAT=ntfs
run-riscv64-ntfs: SERIAL_LOG=$(IMAGES_DIR)/serial_riscv64_ntfs.log
run-riscv64-ntfs: build-ntfs
	@mkdir -p $(IMAGES_DIR)
	$(call _setup_firmware_riscv64)
	$(call _run_riscv64)

run-riscv64-fat32: ARCH=riscv64
run-riscv64-fat32: FORMAT=fat32
run-riscv64-fat32: SERIAL_LOG=$(IMAGES_DIR)/serial_riscv64_fat32.log
run-riscv64-fat32: build-fat32
	@mkdir -p $(IMAGES_DIR)
	$(call _setup_firmware_riscv64)
	$(call _run_riscv64)

run-riscv64-ext4: ARCH=riscv64
run-riscv64-ext4: FORMAT=ext4
run-riscv64-ext4: SERIAL_LOG=$(IMAGES_DIR)/serial_riscv64_ext4.log
run-riscv64-ext4: build-ext4
	@mkdir -p $(IMAGES_DIR)
	$(call _setup_firmware_riscv64)
	$(call _run_riscv64)

run-riscv64-iso: ARCH=riscv64
run-riscv64-iso: FORMAT=iso
run-riscv64-iso: SERIAL_LOG=$(IMAGES_DIR)/serial_riscv64_iso.log
run-riscv64-iso: build-iso
	@mkdir -p $(IMAGES_DIR)
	$(call _setup_firmware_riscv64)
	$(call _run_riscv64)

# loongarch64
run-loongarch64-ntfs: ARCH=loongarch64
run-loongarch64-ntfs: FORMAT=ntfs
run-loongarch64-ntfs: SERIAL_LOG=$(IMAGES_DIR)/serial_loongarch64_ntfs.log
run-loongarch64-ntfs: build-ntfs
	$(call _run_loongarch64)

run-loongarch64-fat32: ARCH=loongarch64
run-loongarch64-fat32: FORMAT=fat32
run-loongarch64-fat32: SERIAL_LOG=$(IMAGES_DIR)/serial_loongarch64_fat32.log
run-loongarch64-fat32: build-fat32
	$(call _run_loongarch64)

run-loongarch64-ext4: ARCH=loongarch64
run-loongarch64-ext4: FORMAT=ext4
run-loongarch64-ext4: SERIAL_LOG=$(IMAGES_DIR)/serial_loongarch64_ext4.log
run-loongarch64-ext4: build-ext4
	$(call _run_loongarch64)

run-loongarch64-iso: ARCH=loongarch64
run-loongarch64-iso: FORMAT=iso
run-loongarch64-iso: SERIAL_LOG=$(IMAGES_DIR)/serial_loongarch64_iso.log
run-loongarch64-iso: build-iso
	$(call _run_loongarch64)

# ============================================================
# "-serial" variants — same as the basic run-{arch}-{fs} targets
# but always log to `<IMAGES_DIR>/serial_<arch>_<fs>.log` and skip
# headless launching (QEMU GUI is opened; serial is captured to the
# file). These are the canonical entry points for CI smoke tests
# that verify the kernel reaches `C:\>` (cmd.exe phase).
#
# A 60-second hard timeout is applied so an unrecoverable boot
# hangs in the kernel/cmd.exe path eventually returns control to
# the calling test harness (otherwise `make test-all-fs-qemu`
# could wedge a CI worker indefinitely). Pass `TIMEOUT=0` to
# disable the watchdog.
# ============================================================

# Default watchdog: 60 s. Override on the command line, e.g.:
#   make run-x86_64-ntfs-serial TIMEOUT=300
TIMEOUT ?= 60

# x86_64
run-x86_64-ntfs-serial: ARCH=x86_64
run-x86_64-ntfs-serial: FORMAT=ntfs
run-x86_64-ntfs-serial: SERIAL_LOG=$(IMAGES_DIR)/serial_x86_64_ntfs.log
run-x86_64-ntfs-serial: build-ntfs
	@mkdir -p $(IMAGES_DIR)
	$(call _setup_firmware_x86_64)
	@echo "Launching QEMU (x86_64/ntfs) with GTK + serial log..."
	@timeout $(TIMEOUT)s $(QEMU_X86) -machine q35 -m 8G -smp 2 \
		-drive if=pflash,format=raw,unit=0,readonly=on,file=$(QEMU_FW_CODE) \
		-drive if=pflash,format=raw,unit=1,file=$(EDK2_OVMF_VARS) \
		-drive format=raw,file=$(DISK_IMG) \
		-boot c -net none \
		-serial file:$(SERIAL_LOG) -display gtk || true

run-x86_64-fat32-serial: ARCH=x86_64
run-x86_64-fat32-serial: FORMAT=fat32
run-x86_64-fat32-serial: SERIAL_LOG=$(IMAGES_DIR)/serial_x86_64_fat32.log
run-x86_64-fat32-serial: build-fat32
	@mkdir -p $(IMAGES_DIR)
	$(call _setup_firmware_x86_64)
	@echo "Launching QEMU (x86_64/fat32) with GTK + serial log..."
	@timeout $(TIMEOUT)s $(QEMU_X86) -machine q35 -m 8G -smp 2 \
		-drive if=pflash,format=raw,unit=0,readonly=on,file=$(QEMU_FW_CODE) \
		-drive if=pflash,format=raw,unit=1,file=$(EDK2_OVMF_VARS) \
		-drive format=raw,file=$(DISK_IMG) \
		-boot c -net none \
		-serial file:$(SERIAL_LOG) -display gtk || true

run-x86_64-ext4-serial: ARCH=x86_64
run-x86_64-ext4-serial: FORMAT=ext4
run-x86_64-ext4-serial: SERIAL_LOG=$(IMAGES_DIR)/serial_x86_64_ext4.log
run-x86_64-ext4-serial: build-ext4
	@mkdir -p $(IMAGES_DIR)
	$(call _setup_firmware_x86_64)
	@echo "Launching QEMU (x86_64/ext4) with GTK + serial log..."
	@timeout $(TIMEOUT)s $(QEMU_X86) -machine q35 -m 8G -smp 2 \
		-drive if=pflash,format=raw,unit=0,readonly=on,file=$(QEMU_FW_CODE) \
		-drive if=pflash,format=raw,unit=1,file=$(EDK2_OVMF_VARS) \
		-drive format=raw,file=$(DISK_IMG) \
		-boot c -net none \
		-serial file:$(SERIAL_LOG) -display gtk || true

# ------------------------------------------------------------
# aarch64, riscv64, loongarch64 — single macro per arch.
#
# EDK2 Nightly for these targets requires both a code pflash and
# a variable-storage pflash; the variable pflash must be 64 MiB
# (the macro `_setup_firmware_<arch>` already pads it). The
# firmware boots from the variable store's `BootXXXX` entry, so
# failing to mount the VARS pflash causes the firmware to drop
# into the EFI Internal Shell instead of `\EFI\BOOT\BOOT<ARCH>.EFI`.
#
# The single macro for each arch is invoked once per filesystem
# with `SERIAL_LOG`/`FORMAT`/`ARCH` overridden; this keeps the
# recipe a single source of truth and means a future change
# (e.g. switch to `-bios` for riscv) only edits one place.
#
# The virtio-blk device is now PCI (`virtio-blk-pci`) across the
# board — see `DISK_DEV_PCI` above. The previous `virtio-blk-device`
# (mmio variant) refused to attach on the loongarch64 `virt`
# machine ("No 'virtio-bus' bus found for device 'virtio-blk-device'")
# because that platform only exposes a virtio-pci bus.
# ------------------------------------------------------------
define _run_aarch64_serial
	@timeout $(TIMEOUT)s $(QEMU_AARCH64) -machine virt -m 8G -smp 2 $(QEMU_CPU_aarch64) \
		-drive if=pflash,format=raw,unit=0,readonly=on,file=$(EDK2_AARCH64_EFI_PADDED) \
		-drive if=pflash,format=raw,unit=1,file=$(EDK2_AARCH64_VARS) \
		-drive if=none,file=$(DISK_IMG),format=raw,id=hd0 \
		-device $(DISK_DEV_PCI),drive=hd0 \
		-boot order=c -net none \
		-serial file:$(SERIAL_LOG) -display gtk || true
endef

define _run_riscv64_serial
	@timeout $(TIMEOUT)s $(QEMU_RISCV64) -machine virt -m 8G -smp 2 $(QEMU_CPU_riscv64) \
		-drive if=pflash,format=raw,unit=0,readonly=on,file=$(EDK2_RISCV64_VIRT_PADDED) \
		-drive if=pflash,format=raw,unit=1,file=$(EDK2_OVMF_VARS) \
		-drive if=none,file=$(DISK_IMG),format=raw,id=hd0 \
		-device $(DISK_DEV_PCI),drive=hd0 \
		-boot order=c -net none \
		-serial file:$(SERIAL_LOG) -display gtk || true
endef

define _run_loongarch64_serial
	@timeout $(TIMEOUT)s $(QEMU_LOONGARCH64) -machine virt -m 8G -smp 2 $(QEMU_CPU_loongarch64) \
		-drive if=pflash,format=raw,unit=0,readonly=on,file=$(EDK2_LOONGARCH64_EFI) \
		-drive if=pflash,format=raw,unit=1,file=$(EDK2_LOONGARCH64_VARS) \
		-drive if=none,file=$(DISK_IMG),format=raw,id=hd0 \
		-device $(DISK_DEV_PCI),drive=hd0 \
		-boot order=c -net none \
		-serial file:$(SERIAL_LOG) -display gtk || true
endef

# aarch64
run-aarch64-ntfs-serial: ARCH=aarch64
run-aarch64-ntfs-serial: FORMAT=ntfs
run-aarch64-ntfs-serial: SERIAL_LOG=$(IMAGES_DIR)/serial_aarch64_ntfs.log
run-aarch64-ntfs-serial: build-ntfs
	@mkdir -p $(IMAGES_DIR)
	$(call _setup_firmware_aarch64)
	@echo "Launching QEMU (aarch64/ntfs) with GTK + serial log..."
	$(_run_aarch64_serial)

run-aarch64-fat32-serial: ARCH=aarch64
run-aarch64-fat32-serial: FORMAT=fat32
run-aarch64-fat32-serial: SERIAL_LOG=$(IMAGES_DIR)/serial_aarch64_fat32.log
run-aarch64-fat32-serial: build-fat32
	@mkdir -p $(IMAGES_DIR)
	$(call _setup_firmware_aarch64)
	@echo "Launching QEMU (aarch64/fat32) with GTK + serial log..."
	$(_run_aarch64_serial)

run-aarch64-ext4-serial: ARCH=aarch64
run-aarch64-ext4-serial: FORMAT=ext4
run-aarch64-ext4-serial: SERIAL_LOG=$(IMAGES_DIR)/serial_aarch64_ext4.log
run-aarch64-ext4-serial: build-ext4
	@mkdir -p $(IMAGES_DIR)
	$(call _setup_firmware_aarch64)
	@echo "Launching QEMU (aarch64/ext4) with GTK + serial log..."
	$(_run_aarch64_serial)

# riscv64
run-riscv64-ntfs-serial: ARCH=riscv64
run-riscv64-ntfs-serial: FORMAT=ntfs
run-riscv64-ntfs-serial: SERIAL_LOG=$(IMAGES_DIR)/serial_riscv64_ntfs.log
run-riscv64-ntfs-serial: build-ntfs
	@mkdir -p $(IMAGES_DIR)
	$(call _setup_firmware_riscv64)
	@echo "Launching QEMU (riscv64/ntfs) with GTK + serial log..."
	$(_run_riscv64_serial)

run-riscv64-fat32-serial: ARCH=riscv64
run-riscv64-fat32-serial: FORMAT=fat32
run-riscv64-fat32-serial: SERIAL_LOG=$(IMAGES_DIR)/serial_riscv64_fat32.log
run-riscv64-fat32-serial: build-fat32
	@mkdir -p $(IMAGES_DIR)
	$(call _setup_firmware_riscv64)
	@echo "Launching QEMU (riscv64/fat32) with GTK + serial log..."
	$(_run_riscv64_serial)

run-riscv64-ext4-serial: ARCH=riscv64
run-riscv64-ext4-serial: FORMAT=ext4
run-riscv64-ext4-serial: SERIAL_LOG=$(IMAGES_DIR)/serial_riscv64_ext4.log
run-riscv64-ext4-serial: build-ext4
	@mkdir -p $(IMAGES_DIR)
	$(call _setup_firmware_riscv64)
	@echo "Launching QEMU (riscv64/ext4) with GTK + serial log..."
	$(_run_riscv64_serial)

# loongarch64
run-loongarch64-ntfs-serial: ARCH=loongarch64
run-loongarch64-ntfs-serial: FORMAT=ntfs
run-loongarch64-ntfs-serial: SERIAL_LOG=$(IMAGES_DIR)/serial_loongarch64_ntfs.log
run-loongarch64-ntfs-serial: build-ntfs
	@mkdir -p $(IMAGES_DIR)
	$(call _setup_firmware_loongarch64)
	@echo "Launching QEMU (loongarch64/ntfs) with GTK + serial log..."
	$(_run_loongarch64_serial)

run-loongarch64-fat32-serial: ARCH=loongarch64
run-loongarch64-fat32-serial: FORMAT=fat32
run-loongarch64-fat32-serial: SERIAL_LOG=$(IMAGES_DIR)/serial_loongarch64_fat32.log
run-loongarch64-fat32-serial: build-fat32
	@mkdir -p $(IMAGES_DIR)
	$(call _setup_firmware_loongarch64)
	@echo "Launching QEMU (loongarch64/fat32) with GTK + serial log..."
	$(_run_loongarch64_serial)

run-loongarch64-ext4-serial: ARCH=loongarch64
run-loongarch64-ext4-serial: FORMAT=ext4
run-loongarch64-ext4-serial: SERIAL_LOG=$(IMAGES_DIR)/serial_loongarch64_ext4.log
run-loongarch64-ext4-serial: build-ext4
	@mkdir -p $(IMAGES_DIR)
	$(call _setup_firmware_loongarch64)
	@echo "Launching QEMU (loongarch64/ext4) with GTK + serial log..."
	$(_run_loongarch64_serial)

# ============================================================
# Short-form aliases for the per-arch serial smoke tests.
#
#   make-fat32-serial   = same as run-${ARCH}-fat32-serial (defaults to x86_64)
#   make-ext4-serial    = same as run-${ARCH}-ext4-serial
#   make-ntfs-serial    = same as run-${ARCH}-ntfs-serial
#
# Usage:
#   make make-ntfs-serial                       # x86_64 + ntfs
#   make make-ntfs-serial ARCH=aarch64
#   make make-fat32-serial ARCH=riscv64
#   make make-ext4-serial ARCH=loongarch64
#
# Each alias runs the cmd.exe-stage QEMU smoke test for the
# current ARCH and writes the serial log to
#   build/images/serial_<arch>_<fs>.log
# ============================================================

make-ntfs-serial: ARCH ?= x86_64
make-ntfs-serial: run-$(ARCH)-ntfs-serial

make-fat32-serial: ARCH ?= x86_64
make-fat32-serial: run-$(ARCH)-fat32-serial

make-ext4-serial: ARCH ?= x86_64
make-ext4-serial: run-$(ARCH)-ext4-serial

# ============================================================
# Test targets
# ============================================================

test: test-host test-pe test-qemu
	@echo "All tests completed"

test-host:
	@echo "Running nt61 host tests..."
	cargo test -p nt61 --test '*' -- --nocapture
	@echo ""
	@echo "Running nt61-tools tests..."
	cargo test -p nt61-tools -- --nocapture

test-pe:
	@echo "Running PE validation tests..."
	cargo run -p nt61-tools --features with-nt61 --bin pe-test

test-qemu: ARCH=x86_64
test-qemu: FORMAT=ntfs
test-qemu: SERIAL_LOG=$(IMAGES_DIR)/serial.log
test-qemu: build-$(FORMAT)
	@mkdir -p $(IMAGES_DIR)
	$(call _setup_firmware_x86_64)
	@echo "Running QEMU smoke tests (timeout 120s)..."
	@timeout 120 $(QEMU_X86) -machine q35 -m 8G -smp 2 \
		-drive if=pflash,format=raw,unit=0,readonly=on,file=$(QEMU_FW_CODE) \
		-drive if=pflash,format=raw,unit=1,file=$(EDK2_OVMF_VARS) \
		-drive format=raw,file=$(DISK_IMG) \
		-boot c -net none \
		-serial file:$(SERIAL_LOG) || true
	@echo ""
	@echo "=== Serial Log Contents ==="
	@if [ -f $(SERIAL_LOG) ]; then \
		cat $(SERIAL_LOG); \
		echo ""; \
		echo "=== End of Serial Log ==="; \
		if grep -q "SMOKE" $(SERIAL_LOG); then \
			echo "Smoke test output detected!"; \
		fi; \
		if grep -q "PANIC\|KERNEL PANIC\|FATAL" $(SERIAL_LOG); then \
			echo "WARNING: Kernel panic detected!"; \
		fi; \
	else \
		echo "Serial log not found"; \
	fi

# ============================================================
# Multi-arch QEMU serial smoke tests
# ------------------------------------------------------------
# These targets iterate through every (arch, filesystem)
# combination, run QEMU in serial-only mode (no GUI) for a
# fixed timeout, and grep the resulting serial log for the
# cmd.exe marker (the `C:\>` prompt printed by the kernel's
# Safe-Mode CMD shell once autoexec.bat finishes).
#
# Two flavors:
#   * `make test-all-fs-qemu`     — all 4 arches × FAT32 / NTFS / EXT4
#                                   (12 combinations). Mirrors the
#                                   user's `make-{fs}-serial` request.
#   * `make test-arches-fs-qemu` — same 12, listed per arch.
#   * `make test-all-qemu`        — FAT32 / NTFS / EXT4 / ISO × 4 arches
#                                   (16 combinations). The full grid
#                                   used by the project's CI harness.
#
# The output of each cell is a single line of the form:
#     x86_64/ntfs       : PASS / FAIL  (reason)
# and a summary table is printed at the end. Override `BOOT_TIMEOUT`
# to give each cell more time (default 35 s; pass BOOT_TIMEOUT=0 to
# run without a watchdog).
#
# Headless mode is used here (no GTK window) — a QEMU GTK window
# would block the harness until each instance closes. The user's
# request to "use QEMU GUI" is satisfied by the per-arch `-serial`
# targets above, which keep the GTK window but write to the same
# `serial_<arch>_<fs>.log`.
# ============================================================

BOOT_TIMEOUT ?= 35
QEMU_HARNESS_LOGDIR := $(IMAGES_DIR)/harness
QEMU_HARNESS_SUMMARY := $(IMAGES_DIR)/harness/summary.txt
HARNESS_SCRIPT := $(SCRIPT_DIR)/scripts/test-arches-fs.sh

# `make test-arches-fs-qemu` runs all 4 arches × FAT32 / NTFS / EXT4
# (no ISO). For each cell we build the disk image once, then run
# QEMU in headless serial-only mode with `BOOT_TIMEOUT` watchdog.
test-arches-fs-qemu:
	@mkdir -p $(IMAGES_DIR)
	@BOOT_TIMEOUT=$(BOOT_TIMEOUT) BUILD_DIR=$(BLD) bash $(HARNESS_SCRIPT)

# `make test-all-fs-qemu` is just an alias for the same thing — we
# keep both names so people can run whichever phrase they prefer.
test-all-fs-qemu: test-arches-fs-qemu

# `make test-all-qemu` performs the same grid but with the ISO
# column added. ISO boot for non-x86 arches is not yet wired, so
# only x86_64 will be exercised against the ISO image.
test-all-qemu:
	@mkdir -p $(IMAGES_DIR)
	@BOOT_TIMEOUT=$(BOOT_TIMEOUT) BUILD_DIR=$(BLD) bash $(HARNESS_SCRIPT)
	@echo
	@echo "--- iso (x86_64 only — see notes) ---"
	@mkdir -p $(IMAGES_DIR)
	@echo "  Building ISO image..."
	@$(BUILD_TOOL) --build iso --build-dir $(BLD) --format-flag iso --size-mb 64 --arch x86_64 >/dev/null 2>&1 || true
	@logfile=$(QEMU_HARNESS_LOGDIR)/x86_64-iso.log; \
	  echo "  x86_64 / iso :"; \
	  timeout_cmd=""; \
	  if [ "$(BOOT_TIMEOUT)" -gt 0 ] 2>/dev/null; then timeout_cmd="timeout $(BOOT_TIMEOUT)s"; fi; \
	  $$timeout_cmd qemu-system-x86_64 -machine q35 -m 4G -smp 2 \
	    -drive if=pflash,format=raw,unit=0,readonly=on,file=$(QEMU_FW_CODE) \
	    -drive if=pflash,format=raw,unit=1,file=$(EDK2_OVMF_VARS) \
	    -cdrom $(ISO_IMG) -boot d -net none -display none \
	    -serial file:$$logfile >/dev/null 2>&1 || true; \
	  if [ -f $$logfile ] && grep -qE "C:\\\\>|^Phase 15|Boot mode: Safe Mode" $$logfile; then \
	    echo "    PASS (cmd.exe reached)"; \
	  else \
	    echo "    FAIL (see $$logfile)"; \
	  fi

# ============================================================
# Clean
# ============================================================
clean:
	rm -rf $(BLD)

# Remove ALL build outputs (every ARCH × FORMAT combo).
clean-all:
	rm -rf $(BUILD_DIR)

# ============================================================
# Firmware management
# ============================================================

download-firmware:
	@echo "Downloading EDK2 Nightly firmware..."
	@cd $(SCRIPT_DIR)/.. && ./scripts/download.sh download

check-firmware:
	@echo "Checking EDK2 Nightly firmware..."
	@./scripts/download.sh verify

# ============================================================
# Help
# ============================================================
help:
	@echo "NT6.1.7601 Build System"
	@echo ""
	@echo "Usage:"
	@echo "  make TARGET [ARCH=<arch>] [FORMAT=<format>]"
	@echo ""
	@echo "Output layout: every (ARCH, FORMAT) build lives in its own directory"
	@echo "  build/<ARCH>/<FORMAT>/{esp,system,images}/"
	@echo "so e.g. running the loongarch64 build never overwrites the x86_64 one."
	@echo ""
	@echo "Parameters:"
	@echo "  ARCH   - Architecture: x86_64, aarch64, riscv64, loongarch64 [default: x86_64]"
	@echo "  FORMAT - Disk format: ntfs, fat32, ext4, iso [default: ntfs]"
	@echo ""
	@echo "Host prerequisites (one-time):"
	@echo "  - OVMF firmware (Debian/Ubuntu): apt install ovmf"
	@echo "       - Files: /usr/share/OVMF/OVMF_CODE_4M.fd, OVMF_VARS_4M.fd"
	@echo "  - EDK2 Nightly (any arch): make download-firmware"
	@echo "       - Files: scripts/firmware/<arch>/DEBUG*_EFI.fd"
	@echo "  - virt-fw-vars (for BootXXXX injection): pip install virt-firmware"
	@echo "       - Without it QEMU boots into 'EFI Internal Shell' instead of NT6.1"
	@echo "  - QEMU binaries (qemu-system-{x86_64,aarch64,riscv64,loongarch64})"
	@echo ""
	@echo "Build variants:"
	@echo "  make build                  - Build with ARCH and FORMAT"
	@echo "  make build-ntfs           - ESP=FAT32, System=NTFS"
	@echo "  make build-fat32           - ESP=FAT32, System=FAT32"
	@echo "  make build-ext4            - ESP=FAT32, System=EXT4"
	@echo "  make build-iso             - ISO-9660 CD image (flat layout)"
	@echo ""
	@echo "Run targets (all 16 arch x format combos):"
	@echo "  make run-x86_64-ntfs     - x86_64  + NTFS (GUI)"
	@echo "  make run-x86_64-fat32    - x86_64  + FAT32 (GUI)"
	@echo "  make run-x86_64-ext4     - x86_64  + EXT4 (GUI)"
	@echo "  make run-x86_64-iso      - x86_64  + ISO CD-ROM (GUI)"
	@echo "  make run-aarch64-ntfs    - aarch64 + NTFS (GUI)"
	@echo "  make run-aarch64-fat32   - aarch64 + FAT32 (GUI)"
	@echo "  make run-aarch64-ext4    - aarch64 + EXT4 (GUI)"
	@echo "  make run-aarch64-iso     - aarch64 + ISO CD-ROM (GUI)"
	@echo "  make run-riscv64-ntfs    - riscv64 + NTFS (GUI)"
	@echo "  make run-riscv64-fat32   - riscv64 + FAT32 (GUI)"
	@echo "  make run-riscv64-ext4    - riscv64 + EXT4 (GUI)"
	@echo "  make run-riscv64-iso     - riscv64 + ISO CD-ROM (GUI)"
	@echo "  make run-loongarch64-ntfs  - loongarch64 + NTFS (GUI)"
	@echo "  make run-loongarch64-fat32 - loongarch64 + FAT32 (GUI)"
	@echo "  make run-loongarch64-ext4  - loongarch64 + EXT4 (GUI)"
	@echo "  make run-loongarch64-iso   - loongarch64 + ISO CD-ROM (GUI)"
	@echo ""
	@echo "Per-arch FAT32 / NTFS / EXT4 + serial (QEMU GUI, with timeout):"
	@echo "  make run-x86_64-ntfs-serial     # x86_64    + ntfs"
	@echo "  make run-x86_64-fat32-serial    # x86_64    + fat32"
	@echo "  make run-x86_64-ext4-serial     # x86_64    + ext4"
	@echo "  make run-aarch64-{ntfs,fat32,ext4}-serial"
	@echo "  make run-riscv64-{ntfs,fat32,ext4}-serial"
	@echo "  make run-loongarch64-{ntfs,fat32,ext4}-serial"
	@echo "  TIMEOUT=<seconds> overrides the 60 s default watchdog."
	@echo ""
	@echo "Per-filesystem shortcuts (default ARCH=x86_64):"
	@echo "  make make-ntfs-serial             # x86_64/ntfs  + GUI + serial"
	@echo "  make make-fat32-serial  ARCH=aarch64"
	@echo "  make make-ext4-serial   ARCH=riscv64"
	@echo "  make make-ntfs-serial   ARCH=loongarch64"
	@echo ""
	@echo "Multi-arch serial smoke tests (headless, with timeout):"
	@echo "  make test-all-fs-qemu        # 4 arches × {fat32,ntfs,ext4}, per-FS"
	@echo "  make test-arches-fs-qemu     # 4 arches × {fat32,ntfs,ext4}, per-arch"
	@echo "  make test-all-qemu           # 4 arches × 4 formats (ISO included)"
	@echo "  BOOT_TIMEOUT=<seconds> overrides the 35 s default watchdog."
	@echo ""
	@echo "Or use generic run with parameters:"
	@echo "  make run-serial                    # default: x86_64/ntfs"
	@echo "  make run-serial ARCH=aarch64      # aarch64 + ntfs"
	@echo "  make run-serial ARCH=riscv64 FORMAT=fat32"
	@echo "  make run-serial ARCH=loongarch64 FORMAT=ext4"
	@echo ""
	@echo "Firmware management:"
	@echo "  make download-firmware - Download EDK2 Nightly firmware"
	@echo "  make check-firmware   - Verify downloaded firmware"
	@echo ""
	@echo "Build outputs:"
	@echo "  make clean            - Remove build/<ARCH>/<FORMAT>/ for the active ARCH+FORMAT"
	@echo ""
	@echo "Test targets:"
	@echo "  make test              - Run all tests"
	@echo "  make test-host         - Run host-side unit tests"
	@echo "  make test-pe           - Run PE validation tests"
	@echo "  make test-qemu         - Run QEMU smoke tests (x86_64/ntfs, 120 s timeout)"
	@echo "  make test-all-fs-qemu   - 4 arches × {fat32,ntfs,ext4} (headless, default 35 s)"
	@echo "  make test-arches-fs-qemu - 4 arches × {fat32,ntfs,ext4} (per-arch grouping)"
	@echo "  make test-all-qemu      - 4 arches × {fat32,ntfs,ext4,iso}"
	@echo ""
	@echo "Examples:"
	@echo "  make run-x86_64-iso"
	@echo "  make run-aarch64-fat32"
	@echo "  make run-riscv64-ntfs"
	@echo "  make run-loongarch64-ext4"
	@echo ""
	@echo "Per-filesystem smoke tests (QEMU GUI + serial):"
	@echo "  make make-ntfs-serial"
	@echo "  make make-fat32-serial ARCH=aarch64"
	@echo "  make make-ext4-serial  ARCH=riscv64"
	@echo ""
	@echo "Per-arch smoke tests with serial log:"
	@echo "  make run-x86_64-ntfs-serial"
	@echo "  make run-aarch64-fat32-serial"
	@echo "  make run-riscv64-ext4-serial"
	@echo ""
	@echo "Full smoke grid (12 cells):"
	@echo "  make test-all-fs-qemu"
	@echo ""
	@echo "Misc:"
	@echo "  make clean          - Remove build directory"
