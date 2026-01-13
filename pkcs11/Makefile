# SPDX-License-Identifier: Apache-2.0
# Makefile for nailed PKCS#11 library

CC ?= clang
CFLAGS = -Wall -Wextra -fPIC -O2 -std=c11
LDFLAGS = -dynamiclib -lresolv

# Debug build
ifdef DEBUG
CFLAGS += -g -DNAILED_DEBUG
endif

# Source files
SRCS = nailed_pkcs11.c nailed_client.c
OBJS = $(SRCS:.c=.o)

# Output
DYLIB = libnailed_pkcs11.dylib

# Include paths
INCLUDES = -I. -Ivendor

.PHONY: all clean install test

all: $(DYLIB)

$(DYLIB): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

# Dependencies
nailed_pkcs11.o: nailed_pkcs11.c nailed_pkcs11_platform.h nailed_client.h vendor/pkcs11.h vendor/pkcs11t.h vendor/pkcs11f.h
nailed_client.o: nailed_client.c nailed_client.h

clean:
	rm -f $(OBJS) $(DYLIB)

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

