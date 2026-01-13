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

/* BoringSSL */
#include <openssl/base64.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/ec_key.h>

/* Logging */
#include "nailed_log.h"
#define DEBUG_LOG(fmt, ...) LOG_CLIENT(fmt, ##__VA_ARGS__)

/* Base64 encode using BoringSSL */
static int base64_encode(const uint8_t *input, size_t input_len,
                         char *output, size_t output_max)
{
    size_t out_len;
    if (!EVP_EncodedLength(&out_len, input_len) || out_len > output_max) {
        return -1;
    }
    return (int)EVP_EncodeBlock((uint8_t *)output, input, input_len);
}

/* Base64 decode using BoringSSL */
static int base64_decode(const char *input,
                         uint8_t *output, size_t output_max)
{
    size_t input_len = strlen(input);
    size_t out_len;
    if (!EVP_DecodedLength(&out_len, input_len) || out_len > output_max) {
        return -1;
    }
    if (!EVP_DecodeBase64(output, &out_len, output_max, (const uint8_t *)input, input_len)) {
        return -1;
    }
    return (int)out_len;
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

/* Extract EC point from X.509 certificate using BoringSSL */
static nailed_result_t extract_ec_point_from_cert(const uint8_t *cert, size_t cert_len,
                                                   uint8_t *ec_point, size_t *ec_point_len)
{
    const uint8_t *p = cert;
    X509 *x509 = d2i_X509(NULL, &p, (long)cert_len);
    if (!x509) {
        DEBUG_LOG("Failed to parse X.509 certificate");
        return NAILED_ERROR_PROTOCOL;
    }
    
    EVP_PKEY *pkey = X509_get_pubkey(x509);
    if (!pkey) {
        DEBUG_LOG("Failed to get public key from certificate");
        X509_free(x509);
        return NAILED_ERROR_PROTOCOL;
    }
    
    const EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(pkey);
    if (!ec_key) {
        DEBUG_LOG("Public key is not an EC key");
        EVP_PKEY_free(pkey);
        X509_free(x509);
        return NAILED_ERROR_PROTOCOL;
    }
    
    const EC_GROUP *group = EC_KEY_get0_group(ec_key);
    const EC_POINT *point = EC_KEY_get0_public_key(ec_key);
    if (!group || !point) {
        DEBUG_LOG("Failed to get EC group or point");
        EVP_PKEY_free(pkey);
        X509_free(x509);
        return NAILED_ERROR_PROTOCOL;
    }
    
    /* Get uncompressed point encoding */
    size_t point_len = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
    if (point_len == 0) {
        DEBUG_LOG("Failed to get EC point length");
        EVP_PKEY_free(pkey);
        X509_free(x509);
        return NAILED_ERROR_PROTOCOL;
    }
    
    if (*ec_point_len < point_len) {
        *ec_point_len = point_len;
        EVP_PKEY_free(pkey);
        X509_free(x509);
        return NAILED_ERROR_BUFFER_TOO_SMALL;
    }
    
    size_t written = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, ec_point, *ec_point_len, NULL);
    if (written == 0) {
        DEBUG_LOG("Failed to encode EC point");
        EVP_PKEY_free(pkey);
        X509_free(x509);
        return NAILED_ERROR_PROTOCOL;
    }
    
    *ec_point_len = written;
    DEBUG_LOG("Extracted EC point: %zu bytes", written);
    
    EVP_PKEY_free(pkey);
    X509_free(x509);
    return NAILED_OK;
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

