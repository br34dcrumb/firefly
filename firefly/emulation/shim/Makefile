# Cross-compile the Firefly emulation shim for a target architecture.
#
# The shim must match the emulated binary's architecture, so it has to be built
# with a cross toolchain. Set CROSS to the toolchain prefix, e.g.:
#
#   make CROSS=arm-linux-gnueabi-            # 32-bit ARM
#   make CROSS=mipsel-linux-gnu-             # little-endian MIPS
#   make CROSS=aarch64-linux-gnu-            # 64-bit ARM
#
# Output: libfirefly_preload.so in this directory (or OUT=/path).

CROSS ?=
CC    := $(CROSS)gcc
OUT   ?= libfirefly_preload.so
CFLAGS := -shared -fPIC -O2 -Wall -ldl

$(OUT): libfirefly_preload.c
	$(CC) $(CFLAGS) -o $(OUT) libfirefly_preload.c

.PHONY: clean
clean:
	rm -f libfirefly_preload.so
