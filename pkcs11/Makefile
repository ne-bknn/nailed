# SPDX-License-Identifier: Apache-2.0
# Makefile for nailed PKCS#11 library

CC ?= clang
CFLAGS = -Wall -Wextra -fPIC -O2 -std=c11
LDFLAGS = -dynamiclib

# Debug build (DEBUG=1 logs to stderr, DEBUG_FILE=1 logs to /tmp/nailed.log)
ifdef DEBUG_FILE
CFLAGS += -g -DNAILED_DEBUG_FILE
else ifdef DEBUG
CFLAGS += -g -DNAILED_DEBUG
endif

# BoringSSL paths
BORINGSSL_DIR = vendor/boringssl
BORINGSSL_BUILD = $(BORINGSSL_DIR)/build
BORINGSSL_INCLUDE = $(BORINGSSL_DIR)/include
BORINGSSL_LIBS = $(BORINGSSL_BUILD)/libcrypto.a

# Include paths
INCLUDES = -I. -Ivendor/pkcs11 -I$(BORINGSSL_INCLUDE)

# Link against BoringSSL
LDFLAGS += $(BORINGSSL_LIBS) -lstdc++

# Source files
SRCS = nailed_pkcs11.c nailed_client.c
OBJS = $(SRCS:.c=.o)

# Output
DYLIB = libnailed_pkcs11.dylib

.PHONY: all clean install test boringssl

all: boringssl $(DYLIB)

# Build BoringSSL
boringssl: $(BORINGSSL_LIBS)

$(BORINGSSL_LIBS):
	@echo "Building BoringSSL..."
	mkdir -p $(BORINGSSL_BUILD)
	cd $(BORINGSSL_BUILD) && cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF .. && make -j$$(sysctl -n hw.ncpu) crypto
	@echo "BoringSSL built successfully"

$(DYLIB): $(OBJS) $(BORINGSSL_LIBS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

# Dependencies
nailed_pkcs11.o: nailed_pkcs11.c nailed_pkcs11_platform.h nailed_client.h
nailed_client.o: nailed_client.c nailed_client.h

clean:
	rm -f $(OBJS) $(DYLIB)

clean-all: clean
	rm -rf $(BORINGSSL_BUILD)

# Install to /usr/local/lib (requires sudo)
install: $(DYLIB)
	install -d /usr/local/lib
	install -m 755 $(DYLIB) /usr/local/lib/

# Test with pkcs11-tool (requires opensc)
test: $(DYLIB)
	@echo "=== Testing PKCS#11 library ==="
	@echo ""
	@echo "--- Listing slots ---"
	pkcs11-tool --module ./$(DYLIB) --list-slots || true
	@echo ""
	@echo "--- Listing mechanisms ---"
	pkcs11-tool --module ./$(DYLIB) --list-mechanisms || true
	@echo ""
	@echo "--- Listing objects ---"
	pkcs11-tool --module ./$(DYLIB) --list-objects || true
	@echo ""
	@echo "=== Test complete ==="

# Run bats tests
bats: $(DYLIB)
	bats tests/
