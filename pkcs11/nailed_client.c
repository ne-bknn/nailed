/* SPDX-License-Identifier: Apache-2.0
 * Nailed protocol client implementation
 */

#include "nailed_client.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <resolv.h>  /* b64_ntop, b64_pton */

/* Debug logging */
#ifdef NAILED_DEBUG
#define DEBUG_LOG(fmt, ...) fprintf(stderr, "[nailed] " fmt "\n", ##__VA_ARGS__)
#else
#define DEBUG_LOG(fmt, ...) ((void)0)
#endif

/* Base64 encode using BSD/macOS resolv.h */
static int base64_encode(const uint8_t *input, size_t input_len,
                         char *output, size_t output_max)
{
    /* b64_ntop returns the length of the encoded string, or -1 on error */
    int result = b64_ntop(input, input_len, output, output_max);
    return result;
}

/* Base64 decode using BSD/macOS resolv.h */
static int base64_decode(const char *input,
                         uint8_t *output, size_t output_max)
{
    /* b64_pton returns the number of bytes written, or -1 on error */
    int result = b64_pton(input, output, output_max);
    return result;
}

nailed_result_t nailed_client_init(nailed_client_t *client, const char *socket_path)
{
    if (!client) {
        return NAILED_ERROR_PROTOCOL;
    }
    
    memset(client, 0, sizeof(*client));
    client->socket_fd = -1;
    client->connected = false;
    
    if (socket_path) {
        strncpy(client->socket_path, socket_path, sizeof(client->socket_path) - 1);
    } else {
        /* Check environment variable first */
        const char *env_path = getenv("NAILED_SOCKET_PATH");
        if (env_path) {
            strncpy(client->socket_path, env_path, sizeof(client->socket_path) - 1);
        } else {
            strncpy(client->socket_path, NAILED_DEFAULT_SOCKET_PATH, sizeof(client->socket_path) - 1);
        }
    }
    
    DEBUG_LOG("Initialized client with socket path: %s", client->socket_path);
    return NAILED_OK;
}

void nailed_client_cleanup(nailed_client_t *client)
{
    if (!client) return;
    
    nailed_client_disconnect(client);
    
    if (client->certificate_der) {
        free(client->certificate_der);
        client->certificate_der = NULL;
    }
    
    if (client->ec_point) {
        free(client->ec_point);
        client->ec_point = NULL;
    }
    
    DEBUG_LOG("Client cleaned up");
}

nailed_result_t nailed_client_connect(nailed_client_t *client)
{
    if (!client) {
        return NAILED_ERROR_PROTOCOL;
    }
    
    if (client->connected && client->socket_fd >= 0) {
        return NAILED_OK;
    }
    
    /* Create Unix domain socket */
    client->socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (client->socket_fd < 0) {
        DEBUG_LOG("Failed to create socket: %s", strerror(errno));
        return NAILED_ERROR_CONNECT;
    }
    
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, client->socket_path, sizeof(addr.sun_path) - 1);
    
    if (connect(client->socket_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        DEBUG_LOG("Failed to connect to %s: %s", client->socket_path, strerror(errno));
        close(client->socket_fd);
        client->socket_fd = -1;
        return NAILED_ERROR_CONNECT;
    }
    
    client->connected = true;
    DEBUG_LOG("Connected to nailed server at %s", client->socket_path);
    return NAILED_OK;
}

void nailed_client_disconnect(nailed_client_t *client)
{
    if (!client) return;
    
    if (client->socket_fd >= 0) {
        close(client->socket_fd);
        client->socket_fd = -1;
    }
    client->connected = false;
    DEBUG_LOG("Disconnected from nailed server");
}

bool nailed_client_is_available(nailed_client_t *client)
{
    if (!client) return false;
    
    /* Try to connect if not connected */
    if (!client->connected) {
        nailed_result_t result = nailed_client_connect(client);
        if (result != NAILED_OK) {
            return false;
        }
    }
    
    return true;
}

/* Send a command and receive response */
static nailed_result_t send_command(nailed_client_t *client,
                                     const char *command,
                                     char *response,
                                     size_t response_max)
{
    if (!client || !client->connected || client->socket_fd < 0) {
        return NAILED_ERROR_CONNECT;
    }
    
    DEBUG_LOG("Sending command: %s", command);
    
    /* Send command */
    ssize_t sent = send(client->socket_fd, command, strlen(command), 0);
    if (sent < 0) {
        DEBUG_LOG("Send failed: %s", strerror(errno));
        nailed_client_disconnect(client);
        return NAILED_ERROR_SEND;
    }
    
    /* Receive response with timeout */
    struct pollfd pfd = { .fd = client->socket_fd, .events = POLLIN };
    int poll_result = poll(&pfd, 1, 30000); /* 30 second timeout for biometric auth */
    
    if (poll_result < 0) {
        DEBUG_LOG("Poll failed: %s", strerror(errno));
        nailed_client_disconnect(client);
        return NAILED_ERROR_RECEIVE;
    }
    
    if (poll_result == 0) {
        DEBUG_LOG("Timeout waiting for response");
        nailed_client_disconnect(client);
        return NAILED_ERROR_RECEIVE;
    }
    
    /* Read response in chunks until we get END or ERROR */
    size_t total_received = 0;
    while (total_received < response_max - 1) {
        ssize_t received = recv(client->socket_fd, response + total_received,
                               response_max - total_received - 1, 0);
        if (received < 0) {
            DEBUG_LOG("Receive failed: %s", strerror(errno));
            nailed_client_disconnect(client);
            return NAILED_ERROR_RECEIVE;
        }
        
        if (received == 0) {
            DEBUG_LOG("Connection closed by server");
            break;
        }
        
        total_received += received;
        response[total_received] = '\0';
        
        /* Check if we have a complete response */
        if (strstr(response, "END\r\n") || strstr(response, "END\n") ||
            strstr(response, "ERROR:") || strstr(response, "version ")) {
            break;
        }
        
        /* Poll for more data with short timeout */
        poll_result = poll(&pfd, 1, 100);
        if (poll_result <= 0) break;
    }
    
    response[total_received] = '\0';
    DEBUG_LOG("Received response (%zu bytes): %.100s...", total_received, response);
    
    return NAILED_OK;
}

nailed_result_t nailed_client_get_version(nailed_client_t *client, int *version)
{
    if (!client || !version) {
        return NAILED_ERROR_PROTOCOL;
    }
    
    nailed_result_t result = nailed_client_connect(client);
    if (result != NAILED_OK) return result;
    
    char response[256];
    result = send_command(client, ">INFO\r\n", response, sizeof(response));
    if (result != NAILED_OK) return result;
    
    /* Parse "version X" response */
    if (sscanf(response, "version %d", version) != 1) {
        DEBUG_LOG("Failed to parse version from: %s", response);
        return NAILED_ERROR_PROTOCOL;
    }
    
    return NAILED_OK;
}

nailed_result_t nailed_client_get_certificate(nailed_client_t *client,
                                               uint8_t *cert_out,
                                               size_t *cert_len)
{
    if (!client || !cert_len) {
        return NAILED_ERROR_PROTOCOL;
    }
    
    /* Return cached certificate if available */
    if (client->certificate_der && client->certificate_der_len > 0) {
        if (cert_out && *cert_len >= client->certificate_der_len) {
            memcpy(cert_out, client->certificate_der, client->certificate_der_len);
        }
        *cert_len = client->certificate_der_len;
        
        if (!cert_out) {
            return NAILED_OK; /* Just querying size */
        }
        if (*cert_len < client->certificate_der_len) {
            return NAILED_ERROR_BUFFER_TOO_SMALL;
        }
        return NAILED_OK;
    }
    
    nailed_result_t result = nailed_client_connect(client);
    if (result != NAILED_OK) return result;
    
    char response[NAILED_MAX_RESPONSE_SIZE];
    result = send_command(client, ">NEED-CERTIFICATE:enclaved\r\n", response, sizeof(response));
    if (result != NAILED_OK) return result;
    
    /* Check for error */
    if (strstr(response, "ERROR:")) {
        DEBUG_LOG("Server error: %s", response);
        if (strstr(response, "No identity") || strstr(response, "No certificate")) {
            return NAILED_ERROR_NO_IDENTITY;
        }
        return NAILED_ERROR_NO_CERTIFICATE;
    }
    
    /* Parse PEM certificate from response */
    /* Expected format:
     * certificate
     * -----BEGIN CERTIFICATE-----
     * <base64>
     * -----END CERTIFICATE-----
     * END
     */
    char *begin = strstr(response, "-----BEGIN CERTIFICATE-----");
    char *end = strstr(response, "-----END CERTIFICATE-----");
    
    if (!begin || !end || end <= begin) {
        DEBUG_LOG("Failed to find certificate markers in response");
        return NAILED_ERROR_NO_CERTIFICATE;
    }
    
    /* Extract base64 content */
    begin += strlen("-----BEGIN CERTIFICATE-----");
    while (*begin == '\r' || *begin == '\n') begin++;
    
    /* Build base64 string without whitespace */
    char base64_cert[NAILED_MAX_CERTIFICATE_SIZE * 2];
    size_t base64_len = 0;
    
    for (char *p = begin; p < end && base64_len < sizeof(base64_cert) - 1; p++) {
        if (*p != '\r' && *p != '\n' && *p != ' ') {
            base64_cert[base64_len++] = *p;
        }
    }
    base64_cert[base64_len] = '\0';
    
    /* Decode base64 to DER */
    uint8_t der_cert[NAILED_MAX_CERTIFICATE_SIZE];
    
    int decoded = base64_decode(base64_cert, der_cert, sizeof(der_cert));
    if (decoded < 0) {
        DEBUG_LOG("Failed to decode certificate base64");
        return NAILED_ERROR_PROTOCOL;
    }
    size_t der_len = (size_t)decoded;
    
    /* Cache the certificate */
    if (client->certificate_der) {
        free(client->certificate_der);
    }
    client->certificate_der = malloc(der_len);
    if (client->certificate_der) {
        memcpy(client->certificate_der, der_cert, der_len);
        client->certificate_der_len = der_len;
    }
    
    /* Copy to output */
    if (cert_out && *cert_len >= der_len) {
        memcpy(cert_out, der_cert, der_len);
    }
    *cert_len = der_len;
    
    if (!cert_out) {
        return NAILED_OK; /* Just querying size */
    }
    if (*cert_len < der_len) {
        return NAILED_ERROR_BUFFER_TOO_SMALL;
    }
    
    DEBUG_LOG("Got certificate: %zu bytes DER", der_len);
    return NAILED_OK;
}

/* Parse ASN.1 length */
static size_t parse_asn1_length(const uint8_t *data, size_t *offset)
{
    if (data[*offset] < 0x80) {
        return data[(*offset)++];
    }
    
    size_t num_bytes = data[(*offset)++] & 0x7F;
    size_t length = 0;
    for (size_t i = 0; i < num_bytes; i++) {
        length = (length << 8) | data[(*offset)++];
    }
    return length;
}

/* Extract EC point from X.509 certificate */
static nailed_result_t extract_ec_point_from_cert(const uint8_t *cert, size_t cert_len,
                                                   uint8_t *ec_point, size_t *ec_point_len)
{
    /* Simple ASN.1 parsing to find the EC public key
     * X.509 structure:
     * SEQUENCE (Certificate)
     *   SEQUENCE (TBSCertificate)
     *     ... (version, serialNumber, signature, issuer, validity, subject)
     *     SEQUENCE (SubjectPublicKeyInfo)
     *       SEQUENCE (AlgorithmIdentifier)
     *         OID (ecPublicKey: 1.2.840.10045.2.1)
     *         OID (curve)
     *       BIT STRING (public key)
     */
    
    /* Look for ecPublicKey OID: 06 07 2A 86 48 CE 3D 02 01 */
    static const uint8_t ec_pubkey_oid[] = { 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
    
    const uint8_t *p = cert;
    const uint8_t *end = cert + cert_len;
    
    /* Search for the OID */
    while (p < end - sizeof(ec_pubkey_oid)) {
        if (memcmp(p, ec_pubkey_oid, sizeof(ec_pubkey_oid)) == 0) {
            /* Found ecPublicKey OID, now find the BIT STRING */
            p += sizeof(ec_pubkey_oid);
            
            /* Skip curve OID (SEQUENCE containing the curve OID) */
            while (p < end - 2) {
                if (*p == 0x03) { /* BIT STRING */
                    p++; /* Skip tag */
                    size_t offset = 0;
                    const uint8_t *len_start = p;
                    size_t bit_string_len = parse_asn1_length(p, &offset);
                    p = len_start + offset;
                    
                    if (p >= end || bit_string_len < 2) {
                        return NAILED_ERROR_PROTOCOL;
                    }
                    
                    /* Skip unused bits byte */
                    uint8_t unused_bits = *p++;
                    bit_string_len--;
                    (void)unused_bits;
                    
                    /* The public key point */
                    if (*ec_point_len < bit_string_len) {
                        *ec_point_len = bit_string_len;
                        return NAILED_ERROR_BUFFER_TOO_SMALL;
                    }
                    
                    memcpy(ec_point, p, bit_string_len);
                    *ec_point_len = bit_string_len;
                    
                    DEBUG_LOG("Extracted EC point: %zu bytes", bit_string_len);
                    return NAILED_OK;
                }
                p++;
            }
            break;
        }
        p++;
    }
    
    return NAILED_ERROR_PROTOCOL;
}

nailed_result_t nailed_client_get_ec_point(nailed_client_t *client,
                                            uint8_t *ec_point_out,
                                            size_t *ec_point_len)
{
    if (!client || !ec_point_len) {
        return NAILED_ERROR_PROTOCOL;
    }
    
    /* Return cached EC point if available */
    if (client->ec_point && client->ec_point_len > 0) {
        if (ec_point_out && *ec_point_len >= client->ec_point_len) {
            memcpy(ec_point_out, client->ec_point, client->ec_point_len);
        }
        *ec_point_len = client->ec_point_len;
        
        if (!ec_point_out) {
            return NAILED_OK;
        }
        if (*ec_point_len < client->ec_point_len) {
            return NAILED_ERROR_BUFFER_TOO_SMALL;
        }
        return NAILED_OK;
    }
    
    /* Get certificate first if not cached */
    if (!client->certificate_der || client->certificate_der_len == 0) {
        size_t cert_len = 0;
        nailed_result_t result = nailed_client_get_certificate(client, NULL, &cert_len);
        if (result != NAILED_OK) return result;
    }
    
    /* Extract EC point from certificate */
    uint8_t ec_point[256];
    size_t point_len = sizeof(ec_point);
    
    nailed_result_t result = extract_ec_point_from_cert(
        client->certificate_der, client->certificate_der_len,
        ec_point, &point_len);
    
    if (result != NAILED_OK) return result;
    
    /* Cache the EC point */
    if (client->ec_point) {
        free(client->ec_point);
    }
    client->ec_point = malloc(point_len);
    if (client->ec_point) {
        memcpy(client->ec_point, ec_point, point_len);
        client->ec_point_len = point_len;
    }
    
    /* Copy to output */
    if (ec_point_out && *ec_point_len >= point_len) {
        memcpy(ec_point_out, ec_point, point_len);
    }
    *ec_point_len = point_len;
    
    if (!ec_point_out) {
        return NAILED_OK;
    }
    if (*ec_point_len < point_len) {
        return NAILED_ERROR_BUFFER_TOO_SMALL;
    }
    
    return NAILED_OK;
}

nailed_result_t nailed_client_sign(nailed_client_t *client,
                                    const uint8_t *digest,
                                    size_t digest_len,
                                    uint8_t *signature_out,
                                    size_t *signature_len)
{
    if (!client || !digest || !signature_len) {
        return NAILED_ERROR_PROTOCOL;
    }
    
    if (digest_len != 32) {
        DEBUG_LOG("Invalid digest length: %zu (expected 32)", digest_len);
        return NAILED_ERROR_PROTOCOL;
    }
    
    nailed_result_t result = nailed_client_connect(client);
    if (result != NAILED_OK) return result;
    
    /* Encode digest as base64 */
    char digest_base64[64];
    base64_encode(digest, digest_len, digest_base64, sizeof(digest_base64));
    
    /* Build command */
    char command[256];
    snprintf(command, sizeof(command), ">PK_SIGN:%s,ECDSA\r\n", digest_base64);
    
    char response[NAILED_MAX_RESPONSE_SIZE];
    result = send_command(client, command, response, sizeof(response));
    if (result != NAILED_OK) return result;
    
    /* Check for error */
    if (strstr(response, "ERROR:")) {
        DEBUG_LOG("Server error: %s", response);
        return NAILED_ERROR_SIGNING_FAILED;
    }
    
    /* Parse signature from response */
    /* Expected format:
     * pk-sig
     * <base64 signature>
     * END
     */
    char *sig_start = strstr(response, "pk-sig");
    if (!sig_start) {
        DEBUG_LOG("Failed to find pk-sig marker in response");
        return NAILED_ERROR_SIGNING_FAILED;
    }
    
    sig_start += strlen("pk-sig");
    while (*sig_start == '\r' || *sig_start == '\n') sig_start++;
    
    /* Find end of base64 */
    char *sig_end = sig_start;
    while (*sig_end && *sig_end != '\r' && *sig_end != '\n') sig_end++;
    
    /* Null-terminate the base64 string for b64_pton */
    char sig_base64[512];
    size_t base64_len = sig_end - sig_start;
    if (base64_len >= sizeof(sig_base64)) {
        DEBUG_LOG("Signature base64 too long");
        return NAILED_ERROR_PROTOCOL;
    }
    memcpy(sig_base64, sig_start, base64_len);
    sig_base64[base64_len] = '\0';
    
    /* Decode signature */
    uint8_t signature[NAILED_MAX_SIGNATURE_SIZE];
    int sig_decoded = base64_decode(sig_base64, signature, sizeof(signature));
    if (sig_decoded < 0) {
        DEBUG_LOG("Failed to decode signature base64");
        return NAILED_ERROR_PROTOCOL;
    }
    size_t sig_len = (size_t)sig_decoded;
    
    /* Copy to output */
    if (signature_out && *signature_len >= sig_len) {
        memcpy(signature_out, signature, sig_len);
    }
    *signature_len = sig_len;
    
    if (!signature_out) {
        return NAILED_OK; /* Just querying size */
    }
    if (*signature_len < sig_len) {
        return NAILED_ERROR_BUFFER_TOO_SMALL;
    }
    
    DEBUG_LOG("Got signature: %zu bytes", sig_len);
    return NAILED_OK;
}

