/* SPDX-License-Identifier: Apache-2.0
 * Nailed protocol client for PKCS#11
 */

#ifndef _NAILED_CLIENT_H_
#define _NAILED_CLIENT_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Default socket path */
#define NAILED_DEFAULT_SOCKET_PATH "/tmp/nailed_signing.sock"

/* Maximum sizes */
#define NAILED_MAX_RESPONSE_SIZE 16384
#define NAILED_MAX_SIGNATURE_SIZE 256
#define NAILED_MAX_CERTIFICATE_SIZE 8192

/* Result codes */
typedef enum {
    NAILED_OK = 0,
    NAILED_ERROR_CONNECT = -1,
    NAILED_ERROR_SEND = -2,
    NAILED_ERROR_RECEIVE = -3,
    NAILED_ERROR_PROTOCOL = -4,
    NAILED_ERROR_NO_CERTIFICATE = -5,
    NAILED_ERROR_SIGNING_FAILED = -6,
    NAILED_ERROR_BUFFER_TOO_SMALL = -7,
    NAILED_ERROR_NO_IDENTITY = -8,
} nailed_result_t;

/* Client context */
typedef struct nailed_client {
    int socket_fd;
    char socket_path[256];
    bool connected;
    
    /* Cached certificate (DER format) */
    uint8_t *certificate_der;
    size_t certificate_der_len;
    
    /* Cached public key info */
    uint8_t *ec_point;
    size_t ec_point_len;
} nailed_client_t;

/* Initialize client with socket path (NULL for default) */
nailed_result_t nailed_client_init(nailed_client_t *client, const char *socket_path);

/* Clean up client resources */
void nailed_client_cleanup(nailed_client_t *client);

/* Connect to nailed server */
nailed_result_t nailed_client_connect(nailed_client_t *client);

/* Disconnect from nailed server */
void nailed_client_disconnect(nailed_client_t *client);

/* Check if server is available */
bool nailed_client_is_available(nailed_client_t *client);

/* Get certificate (DER format) */
nailed_result_t nailed_client_get_certificate(nailed_client_t *client,
                                               uint8_t *cert_out,
                                               size_t *cert_len);

/* Sign a digest (32 bytes for SHA-256) */
nailed_result_t nailed_client_sign(nailed_client_t *client,
                                    const uint8_t *digest,
                                    size_t digest_len,
                                    uint8_t *signature_out,
                                    size_t *signature_len);

/* Get EC point from certificate (for public key) */
nailed_result_t nailed_client_get_ec_point(nailed_client_t *client,
                                            uint8_t *ec_point_out,
                                            size_t *ec_point_len);

/* Get protocol version */
nailed_result_t nailed_client_get_version(nailed_client_t *client, int *version);

#ifdef __cplusplus
}
#endif

#endif /* _NAILED_CLIENT_H_ */

