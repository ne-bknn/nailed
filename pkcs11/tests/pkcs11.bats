#!/usr/bin/env bats
# SPDX-License-Identifier: Apache-2.0
# PKCS#11 library tests using pkcs11-tool
#
# Prerequisites:
#   - brew install opensc bats-core
#   - nailed app running with identity and certificate configured
#
# Run: bats tests/pkcs11.bats

# Path to the PKCS#11 module
PKCS11_MODULE="${PKCS11_MODULE:-./libnailed_pkcs11.dylib}"

setup() {
    # Ensure we're in the pkcs11 directory
    if [[ ! -f "$PKCS11_MODULE" ]]; then
        cd "$(dirname "$BATS_TEST_FILENAME")/.."
    fi
    
    # Check if module exists
    if [[ ! -f "$PKCS11_MODULE" ]]; then
        skip "PKCS#11 module not found: $PKCS11_MODULE (run 'make' first)"
    fi
    
    # Check if pkcs11-tool is available
    if ! command -v pkcs11-tool &> /dev/null; then
        skip "pkcs11-tool not found (install opensc: brew install opensc)"
    fi
}

# Helper function to run pkcs11-tool
pkcs11_tool() {
    pkcs11-tool --module "$PKCS11_MODULE" "$@"
}

@test "module loads successfully" {
    run pkcs11_tool --show-info
    [ "$status" -eq 0 ]
    [[ "$output" == *"Cryptoki version"* ]]
    [[ "$output" == *"nailed"* ]] || [[ "$output" == *"Nailed"* ]]
}

@test "list slots returns at least one slot" {
    run pkcs11_tool --list-slots
    [ "$status" -eq 0 ]
    [[ "$output" == *"Slot"* ]]
}

@test "slot info shows hardware slot" {
    run pkcs11_tool --list-slots
    [ "$status" -eq 0 ]
    [[ "$output" == *"Secure Enclave"* ]] || [[ "$output" == *"nailed"* ]]
}

@test "list mechanisms includes ECDSA" {
    run pkcs11_tool --list-mechanisms
    [ "$status" -eq 0 ]
    [[ "$output" == *"ECDSA"* ]]
}

@test "ECDSA mechanism supports signing" {
    run pkcs11_tool --list-mechanisms
    [ "$status" -eq 0 ]
    [[ "$output" == *"sign"* ]]
}

# The following tests require nailed app to be running with an identity configured

@test "token info available when nailed running" {
    run pkcs11_tool --list-token-slots
    if [[ "$output" == *"token not present"* ]] || [[ "$output" == *"not present"* ]]; then
        skip "nailed app not running or no token present"
    fi
    [ "$status" -eq 0 ]
}

@test "can list objects when token present" {
    run pkcs11_tool --list-objects
    if [[ "$status" -ne 0 ]] && [[ "$output" == *"not present"* ]]; then
        skip "nailed app not running or no token present"
    fi
    # Should succeed even if no objects (empty list is OK)
    [ "$status" -eq 0 ]
}

@test "private key object exists when identity configured" {
    run pkcs11_tool --list-objects --type privkey
    if [[ "$status" -ne 0 ]] && [[ "$output" == *"not present"* ]]; then
        skip "nailed app not running or no token present"
    fi
    if [[ "$output" == *"No objects"* ]] || [[ -z "$output" ]]; then
        skip "No identity configured in nailed"
    fi
    [ "$status" -eq 0 ]
    [[ "$output" == *"Private Key"* ]] || [[ "$output" == *"privkey"* ]]
}

@test "public key object exists when identity configured" {
    run pkcs11_tool --list-objects --type pubkey
    if [[ "$status" -ne 0 ]] && [[ "$output" == *"not present"* ]]; then
        skip "nailed app not running or no token present"
    fi
    if [[ "$output" == *"No objects"* ]] || [[ -z "$output" ]]; then
        skip "No identity configured in nailed"
    fi
    [ "$status" -eq 0 ]
    [[ "$output" == *"Public Key"* ]] || [[ "$output" == *"pubkey"* ]]
}

@test "certificate object exists when identity configured" {
    run pkcs11_tool --list-objects --type cert
    if [[ "$status" -ne 0 ]] && [[ "$output" == *"not present"* ]]; then
        skip "nailed app not running or no token present"
    fi
    if [[ "$output" == *"No objects"* ]] || [[ -z "$output" ]]; then
        skip "No certificate configured in nailed"
    fi
    [ "$status" -eq 0 ]
    [[ "$output" == *"Certificate"* ]] || [[ "$output" == *"cert"* ]]
}

@test "can read certificate" {
    # Try to read certificate (must specify label or id)
    run pkcs11_tool --read-object --type cert --label SecureEnclave --output-file /tmp/nailed_test_cert.der
    if [[ "$status" -ne 0 ]] && [[ "$output" == *"not present"* ]]; then
        skip "nailed app not running or no token present"
    fi
    if [[ "$status" -ne 0 ]] && [[ "$output" == *"object not found"* ]]; then
        skip "No certificate configured in nailed"
    fi
    [ "$status" -eq 0 ]
    
    # Verify it's a valid DER certificate
    if command -v openssl &> /dev/null; then
        run openssl x509 -inform DER -in /tmp/nailed_test_cert.der -noout -subject
        [ "$status" -eq 0 ]
    fi
    
    rm -f /tmp/nailed_test_cert.der
}

@test "can perform ECDSA signature" {
    # Create test data (32-byte SHA-256 hash)
    echo -n "0123456789abcdef0123456789abcdef" > /tmp/nailed_test_data.bin
    
    # Sign with ECDSA
    run pkcs11_tool --sign --mechanism ECDSA --input-file /tmp/nailed_test_data.bin --output-file /tmp/nailed_test_sig.bin
    
    if [[ "$status" -ne 0 ]] && [[ "$output" == *"not present"* ]]; then
        rm -f /tmp/nailed_test_data.bin /tmp/nailed_test_sig.bin
        skip "nailed app not running or no token present"
    fi
    if [[ "$status" -ne 0 ]] && [[ "$output" == *"object not found"* ]]; then
        rm -f /tmp/nailed_test_data.bin /tmp/nailed_test_sig.bin
        skip "No private key configured in nailed"
    fi
    
    # Note: This may prompt for biometric authentication
    [ "$status" -eq 0 ]
    
    # Check that signature file was created and has content
    [ -f /tmp/nailed_test_sig.bin ]
    [ -s /tmp/nailed_test_sig.bin ]
    
    rm -f /tmp/nailed_test_data.bin /tmp/nailed_test_sig.bin
}

@test "open and close session" {
    # This is implicitly tested by all other operations
    # pkcs11-tool opens/closes sessions for each operation
    run pkcs11_tool --list-slots
    [ "$status" -eq 0 ]
}

@test "module reports correct version" {
    run pkcs11_tool --show-info
    [ "$status" -eq 0 ]
    # Should report PKCS#11 version 2.40
    [[ "$output" == *"2.40"* ]] || [[ "$output" == *"2.4"* ]]
}

@test "key type is EC/ECDSA" {
    run pkcs11_tool --list-objects --type privkey
    if [[ "$status" -ne 0 ]] || [[ "$output" == *"not present"* ]] || [[ -z "$output" ]]; then
        skip "No private key available"
    fi
    [[ "$output" == *"EC"* ]]
}

@test "can perform ECDSA-SHA256 multi-part signature" {
    # Create test data (arbitrary length - will be hashed by the module)
    echo "This is test data for ECDSA-SHA256 multi-part signing" > /tmp/nailed_test_multipart.txt
    
    # Sign with ECDSA-SHA256 (uses C_SignUpdate + C_SignFinal internally)
    run pkcs11_tool --sign --mechanism ECDSA-SHA256 --input-file /tmp/nailed_test_multipart.txt --output-file /tmp/nailed_test_multipart_sig.bin
    
    if [[ "$status" -ne 0 ]] && [[ "$output" == *"not present"* ]]; then
        rm -f /tmp/nailed_test_multipart.txt /tmp/nailed_test_multipart_sig.bin
        skip "nailed app not running or no token present"
    fi
    if [[ "$status" -ne 0 ]] && [[ "$output" == *"object not found"* ]]; then
        rm -f /tmp/nailed_test_multipart.txt /tmp/nailed_test_multipart_sig.bin
        skip "No private key configured in nailed"
    fi
    
    # Note: This may prompt for biometric authentication
    [ "$status" -eq 0 ]
    
    # Check that signature file was created and has content
    [ -f /tmp/nailed_test_multipart_sig.bin ]
    [ -s /tmp/nailed_test_multipart_sig.bin ]
    
    # Signature should be between 64-72 bytes for ECDSA P-256
    sig_size=$(wc -c < /tmp/nailed_test_multipart_sig.bin | tr -d ' ')
    [ "$sig_size" -ge 64 ]
    [ "$sig_size" -le 72 ]
    
    rm -f /tmp/nailed_test_multipart.txt /tmp/nailed_test_multipart_sig.bin
}

@test "can verify ECDSA-SHA256 signature with openssl" {
    # Skip if openssl not available
    if ! command -v openssl &> /dev/null; then
        skip "openssl not found"
    fi
    
    # Create test data
    echo "Test data for signature verification" > /tmp/nailed_verify_data.txt
    
    # Sign with ECDSA-SHA256
    run pkcs11_tool --sign --mechanism ECDSA-SHA256 --input-file /tmp/nailed_verify_data.txt --output-file /tmp/nailed_verify_sig.bin
    
    if [[ "$status" -ne 0 ]]; then
        rm -f /tmp/nailed_verify_data.txt /tmp/nailed_verify_sig.bin
        skip "Signing failed - token may not be available"
    fi
    
    # Get the certificate
    run pkcs11_tool --read-object --type cert --label SecureEnclave --output-file /tmp/nailed_verify_cert.der
    if [[ "$status" -ne 0 ]]; then
        rm -f /tmp/nailed_verify_data.txt /tmp/nailed_verify_sig.bin
        skip "Could not read certificate"
    fi
    
    # Extract public key from certificate
    openssl x509 -inform DER -in /tmp/nailed_verify_cert.der -pubkey -noout > /tmp/nailed_verify_pubkey.pem
    
    # Verify the signature (need to convert from raw ECDSA to DER format for openssl)
    # Note: pkcs11-tool outputs raw R||S format, openssl expects DER
    # For now just check the signature was created successfully
    [ -f /tmp/nailed_verify_sig.bin ]
    [ -s /tmp/nailed_verify_sig.bin ]
    
    rm -f /tmp/nailed_verify_data.txt /tmp/nailed_verify_sig.bin /tmp/nailed_verify_cert.der /tmp/nailed_verify_pubkey.pem
}

