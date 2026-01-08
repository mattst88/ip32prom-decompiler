# IP32 PROM Decompiler Makefile
# Decompiles firmware and rebuilds it into a new image
#
# Requirements:
#   - Rust toolchain (for building the decompiler)
#   - MIPS cross-toolchain (for rebuilding the firmware)
#
# Usage:
#   make                    # Decompile and rebuild
#   make decompile          # Decompile only
#   make rebuild            # Rebuild only (after decompile)
#   make check              # Verify rebuilt image matches original
#   make clean              # Clean all generated files

PROM_IMAGE ?= ../ip32prom.rev4.18.bin
OUTPUT_DIR ?= output

# Variables to export to the generated Makefile
export CHECKSUM = $(CURDIR)/target/release/ip32prom-checksum

.PHONY: all clean decompile rebuild check

all: rebuild

# All Rust source files
RUST_SOURCES := $(shell find src -name '*.rs')

# Build all Rust binaries
target/release/ip32prom-decompiler target/release/ip32prom-checksum: $(RUST_SOURCES) Cargo.toml Cargo.lock
	cargo build --release

# Annotation files that affect decompiler output
ANNOTATION_FILES := $(wildcard annotations/*.json)

# Sentinel file to track decompiler execution
DECOMPILE_STAMP := $(OUTPUT_DIR)/.decompile.stamp

# Decompile the firmware
decompile: $(DECOMPILE_STAMP)

$(DECOMPILE_STAMP): target/release/ip32prom-decompiler $(PROM_IMAGE) $(ANNOTATION_FILES)
	@mkdir -p $(OUTPUT_DIR)
	./target/release/ip32prom-decompiler $(PROM_IMAGE) -o $(OUTPUT_DIR)
	@touch $@

# Rebuild the PROM image using the generated Makefile
rebuild: $(DECOMPILE_STAMP) target/release/ip32prom-checksum
	$(MAKE) -C $(OUTPUT_DIR) all

# Verify the rebuilt image matches the original
check: rebuild
	@echo "Comparing rebuilt PROM with original..."
	@if cmp -s $(PROM_IMAGE) $(OUTPUT_DIR)/prom.bin; then \
		echo "PASS: Rebuilt image matches original"; \
	else \
		echo "FAIL: Rebuilt image differs from original"; \
		cmp $(PROM_IMAGE) $(OUTPUT_DIR)/prom.bin || true; \
		exit 1; \
	fi

# Clean everything
clean:
	rm -rf $(OUTPUT_DIR)
	cargo clean
