/* SPDX-License-Identifier: Apache-2.0
 * Nailed NDJSON protocol client implementation
 */

#include "nailed_client.h"
#include "cJSON.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
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
    
    if (!client->connected) {
        nailed_result_t result = nailed_client_connect(client);
        if (result != NAILED_OK) {
            return false;
        }
    }
    
    return true;
}

/* Send an NDJSON command and receive a single NDJSON response line.
 * The caller must free the returned cJSON object with cJSON_Delete(). */
static cJSON *send_json_command(nailed_client_t *client, cJSON *cmd,
                                 nailed_result_t *result)
{
    if (!client || !client->connected || client->socket_fd < 0) {
        *result = NAILED_ERROR_CONNECT;
        return NULL;
    }

    char *json_str = cJSON_PrintUnformatted(cmd);
    if (!json_str) {
        *result = NAILED_ERROR_PROTOCOL;
        return NULL;
    }

    size_t json_len = strlen(json_str);
    /* Append newline for NDJSON framing */
    char *wire = malloc(json_len + 2);
    if (!wire) {
        cJSON_free(json_str);
        *result = NAILED_ERROR_PROTOCOL;
        return NULL;
    }
    memcpy(wire, json_str, json_len);
    wire[json_len] = '\n';
    wire[json_len + 1] = '\0';
    cJSON_free(json_str);

    DEBUG_LOG("Sending: %.*s", (int)json_len, wire);

    ssize_t sent = send(client->socket_fd, wire, json_len + 1, 0);
    free(wire);
    if (sent < 0) {
        DEBUG_LOG("Send failed: %s", strerror(errno));
        nailed_client_disconnect(client);
        *result = NAILED_ERROR_SEND;
        return NULL;
    }

    /* Read response until newline (NDJSON) with 30s timeout for biometric auth */
    char buf[NAILED_MAX_RESPONSE_SIZE];
    size_t total = 0;
    struct pollfd pfd = { .fd = client->socket_fd, .events = POLLIN };

    while (total < sizeof(buf) - 1) {
        int pr = poll(&pfd, 1, 30000);
        if (pr < 0) {
            DEBUG_LOG("Poll failed: %s", strerror(errno));
            nailed_client_disconnect(client);
            *result = NAILED_ERROR_RECEIVE;
            return NULL;
        }
        if (pr == 0) {
            DEBUG_LOG("Timeout waiting for response");
            nailed_client_disconnect(client);
            *result = NAILED_ERROR_RECEIVE;
            return NULL;
        }

        ssize_t n = recv(client->socket_fd, buf + total, sizeof(buf) - total - 1, 0);
        if (n < 0) {
            DEBUG_LOG("Receive failed: %s", strerror(errno));
            nailed_client_disconnect(client);
            *result = NAILED_ERROR_RECEIVE;
            return NULL;
        }
        if (n == 0) {
            DEBUG_LOG("Connection closed by server");
            break;
        }
        total += (size_t)n;
        buf[total] = '\0';
        if (memchr(buf, '\n', total)) break;
    }

    buf[total] = '\0';
    DEBUG_LOG("Received (%zu bytes): %.200s", total, buf);

    cJSON *resp = cJSON_Parse(buf);
    if (!resp) {
        DEBUG_LOG("Failed to parse JSON response");
        *result = NAILED_ERROR_PROTOCOL;
        return NULL;
    }

    *result = NAILED_OK;
    return resp;
}

/* Check the "ok" field of a response. Returns NAILED_OK if ok==true. */
static nailed_result_t check_ok(cJSON *resp, nailed_result_t error_code)
{
    cJSON *ok = cJSON_GetObjectItemCaseSensitive(resp, "ok");
    if (!cJSON_IsTrue(ok)) {
        cJSON *err = cJSON_GetObjectItemCaseSensitive(resp, "error");
        if (cJSON_IsString(err)) {
            DEBUG_LOG("Server error: %s", err->valuestring);
        }
        return error_code;
    }
    return NAILED_OK;
}

nailed_result_t nailed_client_get_version(nailed_client_t *client, int *version)
{
    if (!client || !version) {
        return NAILED_ERROR_PROTOCOL;
    }
    
    nailed_result_t result = nailed_client_connect(client);
    if (result != NAILED_OK) return result;
    
    cJSON *cmd = cJSON_CreateObject();
    cJSON_AddStringToObject(cmd, "cmd", "VERSION");

    cJSON *resp = send_json_command(client, cmd, &result);
    cJSON_Delete(cmd);
    if (!resp) return result;

    result = check_ok(resp, NAILED_ERROR_PROTOCOL);
    if (result == NAILED_OK) {
        cJSON *proto = cJSON_GetObjectItemCaseSensitive(resp, "protocol");
        if (cJSON_IsNumber(proto)) {
            *version = proto->valueint;
        } else {
            result = NAILED_ERROR_PROTOCOL;
        }
    }

    cJSON_Delete(resp);
    return result;
}

nailed_result_t nailed_client_get_key_type(nailed_client_t *client,
                                            nailed_key_type_t *type_out)
{
    if (!client || !type_out) {
        return NAILED_ERROR_PROTOCOL;
    }

    if (client->key_type_cached) {
        *type_out = client->key_type;
        return NAILED_OK;
    }

    nailed_result_t result = nailed_client_connect(client);
    if (result != NAILED_OK) return result;

    cJSON *cmd = cJSON_CreateObject();
    cJSON_AddStringToObject(cmd, "cmd", "KEY_TYPE");

    cJSON *resp = send_json_command(client, cmd, &result);
    cJSON_Delete(cmd);
    if (!resp) return result;

    result = check_ok(resp, NAILED_ERROR_NO_IDENTITY);
    if (result == NAILED_OK) {
        cJSON *type_field = cJSON_GetObjectItemCaseSensitive(resp, "type");
        if (cJSON_IsString(type_field)) {
            if (strcmp(type_field->valuestring, "user-presence") == 0) {
                *type_out = NAILED_KEY_TYPE_USER_PRESENCE;
            } else if (strcmp(type_field->valuestring, "application-password") == 0) {
                *type_out = NAILED_KEY_TYPE_APPLICATION_PASSWORD;
            } else {
                *type_out = NAILED_KEY_TYPE_UNKNOWN;
            }
            client->key_type = *type_out;
            client->key_type_cached = true;
        } else {
            result = NAILED_ERROR_PROTOCOL;
        }
    }

    cJSON_Delete(resp);
    return result;
}

nailed_result_t nailed_client_login(nailed_client_t *client,
                                     const uint8_t *pin,
                                     size_t pin_len)
{
    if (!client || !pin || pin_len == 0) {
        return NAILED_ERROR_PROTOCOL;
    }

    nailed_result_t result = nailed_client_connect(client);
    if (result != NAILED_OK) return result;

    /* Build PIN string (may not be null-terminated) */
    char *pin_str = malloc(pin_len + 1);
    if (!pin_str) return NAILED_ERROR_PROTOCOL;
    memcpy(pin_str, pin, pin_len);
    pin_str[pin_len] = '\0';

    cJSON *cmd = cJSON_CreateObject();
    cJSON_AddStringToObject(cmd, "cmd", "LOGIN");
    cJSON_AddStringToObject(cmd, "pin", pin_str);
    free(pin_str);

    cJSON *resp = send_json_command(client, cmd, &result);
    cJSON_Delete(cmd);
    if (!resp) return result;

    result = check_ok(resp, NAILED_ERROR_PIN_INCORRECT);
    cJSON_Delete(resp);
    return result;
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
        
        if (!cert_out) return NAILED_OK;
        if (*cert_len < client->certificate_der_len) return NAILED_ERROR_BUFFER_TOO_SMALL;
        return NAILED_OK;
    }
    
    nailed_result_t result = nailed_client_connect(client);
    if (result != NAILED_OK) return result;
    
    cJSON *cmd = cJSON_CreateObject();
    cJSON_AddStringToObject(cmd, "cmd", "CERTIFICATE");

    cJSON *resp = send_json_command(client, cmd, &result);
    cJSON_Delete(cmd);
    if (!resp) return result;

    result = check_ok(resp, NAILED_ERROR_NO_CERTIFICATE);
    if (result != NAILED_OK) {
        cJSON *err = cJSON_GetObjectItemCaseSensitive(resp, "error");
        if (cJSON_IsString(err) &&
            (strstr(err->valuestring, "identity") || strstr(err->valuestring, "No identity"))) {
            result = NAILED_ERROR_NO_IDENTITY;
        }
        cJSON_Delete(resp);
        return result;
    }

    cJSON *cert_field = cJSON_GetObjectItemCaseSensitive(resp, "certificate");
    if (!cJSON_IsString(cert_field)) {
        cJSON_Delete(resp);
        return NAILED_ERROR_PROTOCOL;
    }

    /* Decode base64 DER certificate */
    uint8_t der_cert[NAILED_MAX_CERTIFICATE_SIZE];
    int decoded = base64_decode(cert_field->valuestring, der_cert, sizeof(der_cert));
    if (decoded < 0) {
        DEBUG_LOG("Failed to decode certificate base64");
        cJSON_Delete(resp);
        return NAILED_ERROR_PROTOCOL;
    }
    size_t der_len = (size_t)decoded;
    cJSON_Delete(resp);

    /* Cache the certificate */
    if (client->certificate_der) free(client->certificate_der);
    client->certificate_der = malloc(der_len);
    if (client->certificate_der) {
        memcpy(client->certificate_der, der_cert, der_len);
        client->certificate_der_len = der_len;
    }
    
    if (cert_out && *cert_len >= der_len) {
        memcpy(cert_out, der_cert, der_len);
    }
    *cert_len = der_len;
    
    if (!cert_out) return NAILED_OK;
    if (*cert_len < der_len) return NAILED_ERROR_BUFFER_TOO_SMALL;
    
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
        
        if (!ec_point_out) return NAILED_OK;
        if (*ec_point_len < client->ec_point_len) return NAILED_ERROR_BUFFER_TOO_SMALL;
        return NAILED_OK;
    }
    
    /* Get certificate first if not cached */
    if (!client->certificate_der || client->certificate_der_len == 0) {
        size_t cert_len = 0;
        nailed_result_t result = nailed_client_get_certificate(client, NULL, &cert_len);
        if (result != NAILED_OK) return result;
    }
    
    uint8_t ec_point[256];
    size_t point_len = sizeof(ec_point);
    
    nailed_result_t result = extract_ec_point_from_cert(
        client->certificate_der, client->certificate_der_len,
        ec_point, &point_len);
    
    if (result != NAILED_OK) return result;
    
    /* Cache the EC point */
    if (client->ec_point) free(client->ec_point);
    client->ec_point = malloc(point_len);
    if (client->ec_point) {
        memcpy(client->ec_point, ec_point, point_len);
        client->ec_point_len = point_len;
    }
    
    if (ec_point_out && *ec_point_len >= point_len) {
        memcpy(ec_point_out, ec_point, point_len);
    }
    *ec_point_len = point_len;
    
    if (!ec_point_out) return NAILED_OK;
    if (*ec_point_len < point_len) return NAILED_ERROR_BUFFER_TOO_SMALL;
    
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
    
    char digest_base64[64];
    base64_encode(digest, digest_len, digest_base64, sizeof(digest_base64));
    
    cJSON *cmd = cJSON_CreateObject();
    cJSON_AddStringToObject(cmd, "cmd", "SIGN");
    cJSON_AddStringToObject(cmd, "digest", digest_base64);
    cJSON_AddStringToObject(cmd, "algorithm", "ECDSA");

    cJSON *resp = send_json_command(client, cmd, &result);
    cJSON_Delete(cmd);
    if (!resp) return result;

    result = check_ok(resp, NAILED_ERROR_SIGNING_FAILED);
    if (result != NAILED_OK) {
        cJSON_Delete(resp);
        return result;
    }

    cJSON *sig_field = cJSON_GetObjectItemCaseSensitive(resp, "signature");
    if (!cJSON_IsString(sig_field)) {
        cJSON_Delete(resp);
        return NAILED_ERROR_PROTOCOL;
    }

    uint8_t signature[NAILED_MAX_SIGNATURE_SIZE];
    int sig_decoded = base64_decode(sig_field->valuestring, signature, sizeof(signature));
    cJSON_Delete(resp);

    if (sig_decoded < 0) {
        DEBUG_LOG("Failed to decode signature base64");
        return NAILED_ERROR_PROTOCOL;
    }
    size_t sig_len = (size_t)sig_decoded;
    
    if (signature_out && *signature_len >= sig_len) {
        memcpy(signature_out, signature, sig_len);
    }
    *signature_len = sig_len;
    
    if (!signature_out) return NAILED_OK;
    if (*signature_len < sig_len) return NAILED_ERROR_BUFFER_TOO_SMALL;
    
    DEBUG_LOG("Got signature: %zu bytes", sig_len);
    return NAILED_OK;
}
