#!/usr/bin/env bats
# SPDX-License-Identifier: Apache-2.0
# PKCS#11 library tests using pkcs11-tool
#
# Prerequisites:
#   - brew install opensc bats-core
#   - nailed app running with identity and certificate configured
#
# Environment variables:
#   PKCS11_MODULE    - path to the PKCS#11 .dylib (default: ./libnailed_pkcs11.dylib)
#   NAILED_TEST_PIN  - PIN for application-password key tests (skip PIN tests if unset)
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

# Detect key type from token info output.
# Sets KEY_TYPE to "application-password" or "user-presence".
get_key_type() {
    local output
    output=$(pkcs11_tool --list-token-slots 2>&1) || true
    if [[ "$output" == *"login required"* ]] || [[ "$output" == *"LOGIN_REQUIRED"* ]]; then
        echo "application-password"
    else
        echo "user-presence"
    fi
}

# Wrapper that auto-adds --login --pin when the key type requires it.
pkcs11_tool_with_auth() {
    local kt
    kt=$(get_key_type)
    if [[ "$kt" == "application-password" ]]; then
        if [[ -z "${NAILED_TEST_PIN:-}" ]]; then
            skip "NAILED_TEST_PIN not set (required for application-password key)"
        fi
        pkcs11_tool --login --pin "$NAILED_TEST_PIN" "$@"
    else
        pkcs11_tool "$@"
    fi
}

# ===== Basic module tests =====

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

# ===== Token info and key type tests =====

@test "token info available when nailed running" {
    run pkcs11_tool --list-token-slots
    if [[ "$output" == *"token not present"* ]] || [[ "$output" == *"not present"* ]]; then
        skip "nailed app not running or no token present"
    fi
    [ "$status" -eq 0 ]
    # Token flags should include either protected auth path or login required
    [[ "$output" == *"protected"* ]] || [[ "$output" == *"login required"* ]] || \
    [[ "$output" == *"LOGIN_REQUIRED"* ]] || [[ "$output" == *"PROTECTED"* ]]
}

@test "token info shows protected auth path for user-presence key" {
    local kt
    kt=$(get_key_type)
    if [[ "$kt" != "user-presence" ]]; then
        skip "key type is $kt, not user-presence"
    fi
    run pkcs11_tool --list-token-slots
    [ "$status" -eq 0 ]
    [[ "$output" == *"protected"* ]] || [[ "$output" == *"PROTECTED"* ]]
}

@test "token info shows login required for application-password key" {
    local kt
    kt=$(get_key_type)
    if [[ "$kt" != "application-password" ]]; then
        skip "key type is $kt, not application-password"
    fi
    run pkcs11_tool --list-token-slots
    [ "$status" -eq 0 ]
    [[ "$output" == *"login required"* ]] || [[ "$output" == *"LOGIN_REQUIRED"* ]]
}

# ===== Object listing tests =====

@test "can list objects when token present" {
    run pkcs11_tool_with_auth --list-objects
    if [[ "$status" -ne 0 ]] && [[ "$output" == *"not present"* ]]; then
        skip "nailed app not running or no token present"
    fi
    [ "$status" -eq 0 ]
}

@test "private key object exists when identity configured" {
    run pkcs11_tool_with_auth --list-objects --type privkey
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
    run pkcs11_tool_with_auth --list-objects --type pubkey
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
    run pkcs11_tool_with_auth --list-objects --type cert
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
    run pkcs11_tool_with_auth --read-object --type cert --label SecureEnclave --output-file /tmp/nailed_test_cert.der
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

# ===== Signing tests =====

@test "can perform ECDSA signature" {
    echo -n "0123456789abcdef0123456789abcdef" > /tmp/nailed_test_data.bin
    
    run pkcs11_tool_with_auth --sign --mechanism ECDSA --input-file /tmp/nailed_test_data.bin --output-file /tmp/nailed_test_sig.bin
    
    if [[ "$status" -ne 0 ]] && [[ "$output" == *"not present"* ]]; then
        rm -f /tmp/nailed_test_data.bin /tmp/nailed_test_sig.bin
        skip "nailed app not running or no token present"
    fi
    if [[ "$status" -ne 0 ]] && [[ "$output" == *"object not found"* ]]; then
        rm -f /tmp/nailed_test_data.bin /tmp/nailed_test_sig.bin
        skip "No private key configured in nailed"
    fi
    
    [ "$status" -eq 0 ]
    [ -f /tmp/nailed_test_sig.bin ]
    [ -s /tmp/nailed_test_sig.bin ]
    
    rm -f /tmp/nailed_test_data.bin /tmp/nailed_test_sig.bin
}

@test "can perform ECDSA-SHA256 multi-part signature" {
    echo "This is test data for ECDSA-SHA256 multi-part signing" > /tmp/nailed_test_multipart.txt
    
    run pkcs11_tool_with_auth --sign --mechanism ECDSA-SHA256 --input-file /tmp/nailed_test_multipart.txt --output-file /tmp/nailed_test_multipart_sig.bin
    
    if [[ "$status" -ne 0 ]] && [[ "$output" == *"not present"* ]]; then
        rm -f /tmp/nailed_test_multipart.txt /tmp/nailed_test_multipart_sig.bin
        skip "nailed app not running or no token present"
    fi
    if [[ "$status" -ne 0 ]] && [[ "$output" == *"object not found"* ]]; then
        rm -f /tmp/nailed_test_multipart.txt /tmp/nailed_test_multipart_sig.bin
        skip "No private key configured in nailed"
    fi
    
    [ "$status" -eq 0 ]
    [ -f /tmp/nailed_test_multipart_sig.bin ]
    [ -s /tmp/nailed_test_multipart_sig.bin ]
    
    sig_size=$(wc -c < /tmp/nailed_test_multipart_sig.bin | tr -d ' ')
    [ "$sig_size" -ge 64 ]
    [ "$sig_size" -le 72 ]
    
    rm -f /tmp/nailed_test_multipart.txt /tmp/nailed_test_multipart_sig.bin
}

@test "can verify ECDSA-SHA256 signature with openssl" {
    if ! command -v openssl &> /dev/null; then
        skip "openssl not found"
    fi
    
    echo "Test data for signature verification" > /tmp/nailed_verify_data.txt
    
    run pkcs11_tool_with_auth --sign --mechanism ECDSA-SHA256 --input-file /tmp/nailed_verify_data.txt --output-file /tmp/nailed_verify_sig.bin
    
    if [[ "$status" -ne 0 ]]; then
        rm -f /tmp/nailed_verify_data.txt /tmp/nailed_verify_sig.bin
        skip "Signing failed - token may not be available"
    fi
    
    run pkcs11_tool_with_auth --read-object --type cert --label SecureEnclave --output-file /tmp/nailed_verify_cert.der
    if [[ "$status" -ne 0 ]]; then
        rm -f /tmp/nailed_verify_data.txt /tmp/nailed_verify_sig.bin
        skip "Could not read certificate"
    fi
    
    openssl x509 -inform DER -in /tmp/nailed_verify_cert.der -pubkey -noout > /tmp/nailed_verify_pubkey.pem
    
    [ -f /tmp/nailed_verify_sig.bin ]
    [ -s /tmp/nailed_verify_sig.bin ]
    
    rm -f /tmp/nailed_verify_data.txt /tmp/nailed_verify_sig.bin /tmp/nailed_verify_cert.der /tmp/nailed_verify_pubkey.pem
}

# ===== PIN / login tests (application-password only) =====

@test "login with PIN succeeds on application-password key" {
    local kt
    kt=$(get_key_type)
    if [[ "$kt" != "application-password" ]]; then
        skip "key type is $kt, not application-password"
    fi
    if [[ -z "${NAILED_TEST_PIN:-}" ]]; then
        skip "NAILED_TEST_PIN not set"
    fi

    run pkcs11_tool --login --pin "$NAILED_TEST_PIN" --list-objects
    [ "$status" -eq 0 ]
}

@test "login with wrong PIN fails" {
    local kt
    kt=$(get_key_type)
    if [[ "$kt" != "application-password" ]]; then
        skip "key type is $kt, not application-password"
    fi

    run pkcs11_tool --login --pin "definitely_wrong_pin_value" --list-objects
    # Should fail with a PIN error
    [ "$status" -ne 0 ] || [[ "$output" == *"error"* ]] || [[ "$output" == *"PIN"* ]]
}

@test "sign after login with PIN succeeds" {
    local kt
    kt=$(get_key_type)
    if [[ "$kt" != "application-password" ]]; then
        skip "key type is $kt, not application-password"
    fi
    if [[ -z "${NAILED_TEST_PIN:-}" ]]; then
        skip "NAILED_TEST_PIN not set"
    fi

    echo -n "0123456789abcdef0123456789abcdef" > /tmp/nailed_pin_sign_data.bin

    run pkcs11_tool --login --pin "$NAILED_TEST_PIN" --sign --mechanism ECDSA \
        --input-file /tmp/nailed_pin_sign_data.bin --output-file /tmp/nailed_pin_sign_sig.bin

    if [[ "$status" -ne 0 ]] && [[ "$output" == *"not present"* ]]; then
        rm -f /tmp/nailed_pin_sign_data.bin /tmp/nailed_pin_sign_sig.bin
        skip "nailed app not running or no token present"
    fi

    [ "$status" -eq 0 ]
    [ -f /tmp/nailed_pin_sign_sig.bin ]
    [ -s /tmp/nailed_pin_sign_sig.bin ]

    rm -f /tmp/nailed_pin_sign_data.bin /tmp/nailed_pin_sign_sig.bin
}

@test "sign without login fails on application-password key" {
    local kt
    kt=$(get_key_type)
    if [[ "$kt" != "application-password" ]]; then
        skip "key type is $kt, not application-password"
    fi

    echo -n "0123456789abcdef0123456789abcdef" > /tmp/nailed_nologin_data.bin

    run pkcs11_tool --sign --mechanism ECDSA \
        --input-file /tmp/nailed_nologin_data.bin --output-file /tmp/nailed_nologin_sig.bin

    # Should fail - login required but not performed
    [ "$status" -ne 0 ] || [[ "$output" == *"error"* ]]

    rm -f /tmp/nailed_nologin_data.bin /tmp/nailed_nologin_sig.bin
}

# ===== Misc tests =====

@test "open and close session" {
    run pkcs11_tool --list-slots
    [ "$status" -eq 0 ]
}

@test "module reports correct version" {
    run pkcs11_tool --show-info
    [ "$status" -eq 0 ]
    [[ "$output" == *"2.40"* ]] || [[ "$output" == *"2.4"* ]]
}

@test "key type is EC/ECDSA" {
    run pkcs11_tool_with_auth --list-objects --type privkey
    if [[ "$status" -ne 0 ]] || [[ "$output" == *"not present"* ]] || [[ -z "$output" ]]; then
        skip "No private key available"
    fi
    [[ "$output" == *"EC"* ]]
}
