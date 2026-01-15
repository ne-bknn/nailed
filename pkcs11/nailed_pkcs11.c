/* SPDX-License-Identifier: Apache-2.0
 * PKCS#11 implementation for nailed Secure Enclave signing
 */

#include "nailed_pkcs11_platform.h"
#include "nailed_client.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

/* BoringSSL for certificate parsing and hashing */
#include <openssl/x509.h>
#include <openssl/mem.h>
#include <openssl/sha.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>

/* Logging */
#include "nailed_log.h"
#define DEBUG_LOG(fmt, ...) LOG_PKCS11(fmt, ##__VA_ARGS__)
#define TRACE_FUNC() DEBUG_LOG("%s called", __func__)
#define TRACE_RV(rv) do { CK_RV _rv = (rv); DEBUG_LOG("%s -> 0x%lx", __func__, (unsigned long)_rv); return _rv; } while(0)
#define NOT_SUPPORTED() do { DEBUG_LOG("%s -> CKR_FUNCTION_NOT_SUPPORTED", __func__); return CKR_FUNCTION_NOT_SUPPORTED; } while(0)

/* Convert DER-encoded ECDSA signature to raw R||S format (64 bytes for P-256)
 * Returns the size of the raw signature, or 0 on error */
static size_t der_sig_to_raw(const uint8_t *der_sig, size_t der_len, 
                              uint8_t *raw_sig, size_t raw_max) {
    /* P-256 uses 32-byte R and S values */
    const size_t component_size = 32;
    const size_t raw_size = component_size * 2;
    
    if (raw_max < raw_size) {
        DEBUG_LOG("der_sig_to_raw: buffer too small (%zu < %zu)", raw_max, raw_size);
        return 0;
    }
    
    /* Parse DER signature using BoringSSL */
    const uint8_t *p = der_sig;
    ECDSA_SIG *sig = d2i_ECDSA_SIG(NULL, &p, (long)der_len);
    if (!sig) {
        DEBUG_LOG("der_sig_to_raw: failed to parse DER signature");
        return 0;
    }
    
    const BIGNUM *r = NULL, *s = NULL;
    ECDSA_SIG_get0(sig, &r, &s);
    
    /* Zero-initialize the output buffer */
    memset(raw_sig, 0, raw_size);
    
    /* Copy R with proper padding (big-endian, right-aligned) */
    size_t r_len = BN_num_bytes(r);
    if (r_len > component_size) {
        DEBUG_LOG("der_sig_to_raw: R too large (%zu > %zu)", r_len, component_size);
        ECDSA_SIG_free(sig);
        return 0;
    }
    BN_bn2bin(r, raw_sig + (component_size - r_len));
    
    /* Copy S with proper padding */
    size_t s_len = BN_num_bytes(s);
    if (s_len > component_size) {
        DEBUG_LOG("der_sig_to_raw: S too large (%zu > %zu)", s_len, component_size);
        ECDSA_SIG_free(sig);
        return 0;
    }
    BN_bn2bin(s, raw_sig + component_size + (component_size - s_len));
    
    ECDSA_SIG_free(sig);
    
    DEBUG_LOG("der_sig_to_raw: converted %zu DER bytes to %zu raw bytes", der_len, raw_size);
    return raw_size;
}

/* Library info */
#define NAILED_MANUFACTURER_ID    "nailed                          "
#define NAILED_LIBRARY_DESC       "Nailed Secure Enclave PKCS#11   "
#define NAILED_SLOT_DESC          "Nailed Secure Enclave Slot                                      "
#define NAILED_TOKEN_LABEL        "Secure Enclave                  "
#define NAILED_TOKEN_MODEL        "Apple T2/M1    "
#define NAILED_TOKEN_SERIAL       "0000000000000001"

/* Object handles */
#define HANDLE_PRIVATE_KEY  1
#define HANDLE_PUBLIC_KEY   2
#define HANDLE_CERTIFICATE  3

/* Max data size for multi-part signing (should be enough for TLS handshake) */
#define MAX_SIGN_DATA_SIZE 65536

/* Session state */
typedef struct {
    CK_SESSION_HANDLE handle;
    CK_SLOT_ID slotID;
    CK_FLAGS flags;
    CK_STATE state;
    CK_BBOOL is_open;
    
    /* Find operation state */
    CK_BBOOL find_active;
    CK_OBJECT_CLASS find_class;
    CK_ULONG find_index;
    
    /* Sign operation state */
    CK_BBOOL sign_active;
    CK_MECHANISM_TYPE sign_mechanism;
    CK_OBJECT_HANDLE sign_key;
    
    /* Multi-part sign data buffer */
    uint8_t *sign_data;
    size_t sign_data_len;
} session_t;

/* Global state */
static CK_BBOOL g_initialized = CK_FALSE;
static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;
static nailed_client_t g_client;
static session_t g_sessions[16];
static CK_ULONG g_session_count = 0;
static CK_SESSION_HANDLE g_next_session_handle = 1;

/* secp256r1 curve OID: 1.2.840.10045.3.1.7 */
static const CK_BYTE SECP256R1_OID[] = {
    0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07
};

/* Supported mechanisms */
static const CK_MECHANISM_TYPE g_mechanisms[] = {
    CKM_ECDSA,
    CKM_ECDSA_SHA256,
};
static const CK_ULONG g_num_mechanisms = sizeof(g_mechanisms) / sizeof(g_mechanisms[0]);

/* Helper to pad a string with spaces */
static void pad_string(CK_UTF8CHAR *dest, const char *src, size_t len)
{
    size_t src_len = strlen(src);
    if (src_len > len) src_len = len;
    memcpy(dest, src, src_len);
    memset(dest + src_len, ' ', len - src_len);
}

/* Find session by handle */
static session_t* find_session(CK_SESSION_HANDLE hSession)
{
    for (CK_ULONG i = 0; i < g_session_count; i++) {
        if (g_sessions[i].is_open && g_sessions[i].handle == hSession) {
            return &g_sessions[i];
        }
    }
    return NULL;
}

/* ===== General purpose functions ===== */

CK_RV C_Initialize(CK_VOID_PTR pInitArgs)
{
    pthread_mutex_lock(&g_mutex);
    
    if (g_initialized) {
        pthread_mutex_unlock(&g_mutex);
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    }
    
    /* Initialize nailed client */
    nailed_result_t result = nailed_client_init(&g_client, NULL);
    if (result != NAILED_OK) {
        pthread_mutex_unlock(&g_mutex);
        return CKR_DEVICE_ERROR;
    }
    
    memset(g_sessions, 0, sizeof(g_sessions));
    g_session_count = 0;
    g_next_session_handle = 1;
    g_initialized = CK_TRUE;
    
    DEBUG_LOG("PKCS#11 initialized");
    pthread_mutex_unlock(&g_mutex);
    return CKR_OK;
}

CK_RV C_Finalize(CK_VOID_PTR pReserved)
{
    if (pReserved != NULL_PTR) {
        return CKR_ARGUMENTS_BAD;
    }
    
    pthread_mutex_lock(&g_mutex);
    
    if (!g_initialized) {
        pthread_mutex_unlock(&g_mutex);
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    
    nailed_client_cleanup(&g_client);
    g_initialized = CK_FALSE;
    
    DEBUG_LOG("PKCS#11 finalized");
    pthread_mutex_unlock(&g_mutex);
    return CKR_OK;
}

CK_RV C_GetInfo(CK_INFO_PTR pInfo)
{
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (pInfo == NULL_PTR) return CKR_ARGUMENTS_BAD;
    
    pInfo->cryptokiVersion.major = 2;
    pInfo->cryptokiVersion.minor = 40;
    pad_string(pInfo->manufacturerID, NAILED_MANUFACTURER_ID, 32);
    pInfo->flags = 0;
    pad_string(pInfo->libraryDescription, NAILED_LIBRARY_DESC, 32);
    pInfo->libraryVersion.major = 1;
    pInfo->libraryVersion.minor = 0;
    
    return CKR_OK;
}

/* Function list - forward declarations */
static CK_FUNCTION_LIST g_function_list;

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
    if (ppFunctionList == NULL_PTR) return CKR_ARGUMENTS_BAD;
    *ppFunctionList = &g_function_list;
    return CKR_OK;
}

/* ===== Slot and token management ===== */

CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
    DEBUG_LOG("C_GetSlotList: tokenPresent=%d, pSlotList=%p", tokenPresent, (void*)pSlotList);
    
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (pulCount == NULL_PTR) return CKR_ARGUMENTS_BAD;
    
    /* We always have exactly one slot */
    if (pSlotList == NULL_PTR) {
        *pulCount = 1;
        DEBUG_LOG("  -> returning count=1");
        return CKR_OK;
    }
    
    if (*pulCount < 1) {
        *pulCount = 1;
        return CKR_BUFFER_TOO_SMALL;
    }
    
    pSlotList[0] = 0;
    *pulCount = 1;
    DEBUG_LOG("  -> slot[0]=0, count=1");
    return CKR_OK;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
    DEBUG_LOG("C_GetSlotInfo: slotID=%lu", (unsigned long)slotID);
    
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (slotID != 0) return CKR_SLOT_ID_INVALID;
    if (pInfo == NULL_PTR) return CKR_ARGUMENTS_BAD;
    
    pad_string(pInfo->slotDescription, NAILED_SLOT_DESC, 64);
    pad_string(pInfo->manufacturerID, NAILED_MANUFACTURER_ID, 32);
    
    /* Check if nailed server is available */
    CK_FLAGS flags = CKF_HW_SLOT;
    if (nailed_client_is_available(&g_client)) {
        flags |= CKF_TOKEN_PRESENT;
    }
    pInfo->flags = flags;
    
    pInfo->hardwareVersion.major = 1;
    pInfo->hardwareVersion.minor = 0;
    pInfo->firmwareVersion.major = 1;
    pInfo->firmwareVersion.minor = 0;
    
    DEBUG_LOG("  -> flags=0x%lx, token_present=%d", (unsigned long)flags, (flags & CKF_TOKEN_PRESENT) ? 1 : 0);
    return CKR_OK;
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
    DEBUG_LOG("C_GetTokenInfo: slotID=%lu", (unsigned long)slotID);
    
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (slotID != 0) return CKR_SLOT_ID_INVALID;
    if (pInfo == NULL_PTR) return CKR_ARGUMENTS_BAD;
    
    if (!nailed_client_is_available(&g_client)) {
        DEBUG_LOG("  -> CKR_TOKEN_NOT_PRESENT");
        return CKR_TOKEN_NOT_PRESENT;
    }
    
    pad_string(pInfo->label, NAILED_TOKEN_LABEL, 32);
    pad_string(pInfo->manufacturerID, NAILED_MANUFACTURER_ID, 32);
    pad_string(pInfo->model, NAILED_TOKEN_MODEL, 16);
    memcpy(pInfo->serialNumber, NAILED_TOKEN_SERIAL, 16);
    
    /* Note: CKF_HW_SLOT is a slot flag, not a token flag - don't use it here!
     * CKF_LOGIN_REQUIRED (0x04) is NOT set - login is optional for this token */
    pInfo->flags = CKF_TOKEN_INITIALIZED | CKF_PROTECTED_AUTHENTICATION_PATH | CKF_USER_PIN_INITIALIZED;
    
    pInfo->ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
    pInfo->ulSessionCount = g_session_count;
    pInfo->ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE;
    pInfo->ulRwSessionCount = 0;
    pInfo->ulMaxPinLen = 0;
    pInfo->ulMinPinLen = 0;
    pInfo->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->hardwareVersion.major = 1;
    pInfo->hardwareVersion.minor = 0;
    pInfo->firmwareVersion.major = 1;
    pInfo->firmwareVersion.minor = 0;
    memset(pInfo->utcTime, ' ', 16);
    
    DEBUG_LOG("  -> label='%.32s', model='%.16s', serial='%.16s', flags=0x%lx",
              pInfo->label, pInfo->model, pInfo->serialNumber, (unsigned long)pInfo->flags);
    return CKR_OK;
}

CK_RV C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)
{
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (slotID != 0) return CKR_SLOT_ID_INVALID;
    if (pulCount == NULL_PTR) return CKR_ARGUMENTS_BAD;
    
    if (pMechanismList == NULL_PTR) {
        *pulCount = g_num_mechanisms;
        return CKR_OK;
    }
    
    if (*pulCount < g_num_mechanisms) {
        *pulCount = g_num_mechanisms;
        return CKR_BUFFER_TOO_SMALL;
    }
    
    memcpy(pMechanismList, g_mechanisms, g_num_mechanisms * sizeof(CK_MECHANISM_TYPE));
    *pulCount = g_num_mechanisms;
    return CKR_OK;
}

CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
{
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (slotID != 0) return CKR_SLOT_ID_INVALID;
    if (pInfo == NULL_PTR) return CKR_ARGUMENTS_BAD;
    
    switch (type) {
        case CKM_ECDSA:
        case CKM_ECDSA_SHA256:
            pInfo->ulMinKeySize = 256;
            pInfo->ulMaxKeySize = 256;
            pInfo->flags = CKF_SIGN | CKF_HW | CKF_EC_F_P | CKF_EC_NAMEDCURVE;
            return CKR_OK;
        default:
            return CKR_MECHANISM_INVALID;
    }
}

CK_RV C_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel)
{
    (void)slotID; (void)pPin; (void)ulPinLen; (void)pLabel;
    NOT_SUPPORTED();
}

CK_RV C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    (void)hSession; (void)pPin; (void)ulPinLen;
    NOT_SUPPORTED();
}

CK_RV C_SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen,
               CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
    (void)hSession; (void)pOldPin; (void)ulOldLen; (void)pNewPin; (void)ulNewLen;
    NOT_SUPPORTED();
}

/* ===== Session management ===== */

CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication,
                    CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession)
{
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (slotID != 0) return CKR_SLOT_ID_INVALID;
    if (phSession == NULL_PTR) return CKR_ARGUMENTS_BAD;
    if (!(flags & CKF_SERIAL_SESSION)) return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
    
    pthread_mutex_lock(&g_mutex);
    
    if (!nailed_client_is_available(&g_client)) {
        pthread_mutex_unlock(&g_mutex);
        return CKR_TOKEN_NOT_PRESENT;
    }
    
    /* Find a free session slot */
    session_t *session = NULL;
    for (CK_ULONG i = 0; i < sizeof(g_sessions)/sizeof(g_sessions[0]); i++) {
        if (!g_sessions[i].is_open) {
            session = &g_sessions[i];
            break;
        }
    }
    
    if (!session) {
        pthread_mutex_unlock(&g_mutex);
        return CKR_SESSION_COUNT;
    }
    
    session->handle = g_next_session_handle++;
    session->slotID = slotID;
    session->flags = flags;
    session->state = (flags & CKF_RW_SESSION) ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;
    session->is_open = CK_TRUE;
    session->find_active = CK_FALSE;
    session->sign_active = CK_FALSE;
    
    g_session_count++;
    *phSession = session->handle;
    
    DEBUG_LOG("Opened session %lu", (unsigned long)session->handle);
    pthread_mutex_unlock(&g_mutex);
    return CKR_OK;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession)
{
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    
    pthread_mutex_lock(&g_mutex);
    
    session_t *session = find_session(hSession);
    if (!session) {
        pthread_mutex_unlock(&g_mutex);
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    session->is_open = CK_FALSE;
    g_session_count--;
    
    DEBUG_LOG("Closed session %lu", (unsigned long)hSession);
    pthread_mutex_unlock(&g_mutex);
    return CKR_OK;
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID)
{
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (slotID != 0) return CKR_SLOT_ID_INVALID;
    
    pthread_mutex_lock(&g_mutex);
    
    for (CK_ULONG i = 0; i < sizeof(g_sessions)/sizeof(g_sessions[0]); i++) {
        if (g_sessions[i].is_open && g_sessions[i].slotID == slotID) {
            g_sessions[i].is_open = CK_FALSE;
        }
    }
    g_session_count = 0;
    
    pthread_mutex_unlock(&g_mutex);
    return CKR_OK;
}

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (pInfo == NULL_PTR) return CKR_ARGUMENTS_BAD;
    
    pthread_mutex_lock(&g_mutex);
    
    session_t *session = find_session(hSession);
    if (!session) {
        pthread_mutex_unlock(&g_mutex);
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    pInfo->slotID = session->slotID;
    pInfo->state = session->state;
    pInfo->flags = session->flags;
    pInfo->ulDeviceError = 0;
    
    pthread_mutex_unlock(&g_mutex);
    return CKR_OK;
}

CK_RV C_GetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState,
                          CK_ULONG_PTR pulOperationStateLen)
{
    (void)hSession; (void)pOperationState; (void)pulOperationStateLen;
    NOT_SUPPORTED();
}

CK_RV C_SetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState,
                          CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey,
                          CK_OBJECT_HANDLE hAuthenticationKey)
{
    (void)hSession; (void)pOperationState; (void)ulOperationStateLen; (void)hEncryptionKey; (void)hAuthenticationKey;
    NOT_SUPPORTED();
}

CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    /* We use protected authentication path (biometrics), so PIN is ignored */
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    
    pthread_mutex_lock(&g_mutex);
    
    session_t *session = find_session(hSession);
    if (!session) {
        pthread_mutex_unlock(&g_mutex);
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    /* Update session state */
    if (session->flags & CKF_RW_SESSION) {
        session->state = (userType == CKU_SO) ? CKS_RW_SO_FUNCTIONS : CKS_RW_USER_FUNCTIONS;
    } else {
        session->state = CKS_RO_USER_FUNCTIONS;
    }
    
    pthread_mutex_unlock(&g_mutex);
    return CKR_OK;
}

CK_RV C_Logout(CK_SESSION_HANDLE hSession)
{
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    
    pthread_mutex_lock(&g_mutex);
    
    session_t *session = find_session(hSession);
    if (!session) {
        pthread_mutex_unlock(&g_mutex);
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    session->state = (session->flags & CKF_RW_SESSION) ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;
    
    pthread_mutex_unlock(&g_mutex);
    return CKR_OK;
}

/* ===== Object management ===== */

CK_RV C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate,
                     CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject)
{
    (void)hSession; (void)pTemplate; (void)ulCount; (void)phObject;
    NOT_SUPPORTED();
}

CK_RV C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                   CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject)
{
    (void)hSession; (void)hObject; (void)pTemplate; (void)ulCount; (void)phNewObject;
    NOT_SUPPORTED();
}

CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
    (void)hSession; (void)hObject;
    NOT_SUPPORTED();
}

CK_RV C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize)
{
    (void)hSession; (void)hObject; (void)pulSize;
    NOT_SUPPORTED();
}

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                          CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    DEBUG_LOG("C_GetAttributeValue: session=%lu, object=%lu, count=%lu", 
              (unsigned long)hSession, (unsigned long)hObject, (unsigned long)ulCount);
    
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (pTemplate == NULL_PTR) return CKR_ARGUMENTS_BAD;
    
    pthread_mutex_lock(&g_mutex);
    
    session_t *session = find_session(hSession);
    if (!session) {
        pthread_mutex_unlock(&g_mutex);
        DEBUG_LOG("  -> session not found");
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    CK_RV rv = CKR_OK;
    
    for (CK_ULONG i = 0; i < ulCount; i++) {
        CK_ATTRIBUTE *attr = &pTemplate[i];
        DEBUG_LOG("  attr[%lu]: type=0x%lx, pValue=%p, len=%lu", 
                  (unsigned long)i, (unsigned long)attr->type, attr->pValue, (unsigned long)attr->ulValueLen);
        
        switch (hObject) {
            case HANDLE_PRIVATE_KEY: {
                switch (attr->type) {
                    case CKA_CLASS: {
                        CK_OBJECT_CLASS class = CKO_PRIVATE_KEY;
                        if (attr->pValue && attr->ulValueLen >= sizeof(class)) {
                            memcpy(attr->pValue, &class, sizeof(class));
                        }
                        attr->ulValueLen = sizeof(class);
                        break;
                    }
                    case CKA_KEY_TYPE: {
                        CK_KEY_TYPE type = CKK_EC;
                        if (attr->pValue && attr->ulValueLen >= sizeof(type)) {
                            memcpy(attr->pValue, &type, sizeof(type));
                        }
                        attr->ulValueLen = sizeof(type);
                        break;
                    }
                    case CKA_TOKEN: {
                        CK_BBOOL val = CK_TRUE;
                        if (attr->pValue && attr->ulValueLen >= sizeof(val)) {
                            memcpy(attr->pValue, &val, sizeof(val));
                        }
                        attr->ulValueLen = sizeof(val);
                        break;
                    }
                    case CKA_PRIVATE: {
                        CK_BBOOL val = CK_TRUE;
                        if (attr->pValue && attr->ulValueLen >= sizeof(val)) {
                            memcpy(attr->pValue, &val, sizeof(val));
                        }
                        attr->ulValueLen = sizeof(val);
                        break;
                    }
                    case CKA_SENSITIVE: {
                        CK_BBOOL val = CK_TRUE;
                        if (attr->pValue && attr->ulValueLen >= sizeof(val)) {
                            memcpy(attr->pValue, &val, sizeof(val));
                        }
                        attr->ulValueLen = sizeof(val);
                        break;
                    }
                    case CKA_EXTRACTABLE: {
                        CK_BBOOL val = CK_FALSE;
                        if (attr->pValue && attr->ulValueLen >= sizeof(val)) {
                            memcpy(attr->pValue, &val, sizeof(val));
                        }
                        attr->ulValueLen = sizeof(val);
                        break;
                    }
                    case CKA_SIGN: {
                        CK_BBOOL val = CK_TRUE;
                        if (attr->pValue && attr->ulValueLen >= sizeof(val)) {
                            memcpy(attr->pValue, &val, sizeof(val));
                        }
                        attr->ulValueLen = sizeof(val);
                        break;
                    }
                    case CKA_EC_PARAMS: {
                        if (attr->pValue && attr->ulValueLen >= sizeof(SECP256R1_OID)) {
                            memcpy(attr->pValue, SECP256R1_OID, sizeof(SECP256R1_OID));
                        }
                        attr->ulValueLen = sizeof(SECP256R1_OID);
                        break;
                    }
                    case CKA_ID:
                    case CKA_LABEL: {
                        const char *label = "SecureEnclave";
                        size_t len = strlen(label);
                        if (attr->pValue && attr->ulValueLen >= len) {
                            memcpy(attr->pValue, label, len);
                        }
                        attr->ulValueLen = len;
                        break;
                    }
                    case CKA_ALWAYS_AUTHENTICATE: {
                        /* Set to FALSE - biometric auth happens at Secure Enclave level,
                         * not via PKCS#11 C_Login. Setting TRUE would cause apps to
                         * prompt for PIN before every signing operation. */
                        CK_BBOOL val = CK_FALSE;
                        if (attr->pValue && attr->ulValueLen >= sizeof(val)) {
                            memcpy(attr->pValue, &val, sizeof(val));
                        }
                        attr->ulValueLen = sizeof(val);
                        break;
                    }
                    default:
                        attr->ulValueLen = CK_UNAVAILABLE_INFORMATION;
                        rv = CKR_ATTRIBUTE_TYPE_INVALID;
                        break;
                }
                break;
            }
            
            case HANDLE_PUBLIC_KEY: {
                switch (attr->type) {
                    case CKA_CLASS: {
                        CK_OBJECT_CLASS class = CKO_PUBLIC_KEY;
                        if (attr->pValue && attr->ulValueLen >= sizeof(class)) {
                            memcpy(attr->pValue, &class, sizeof(class));
                        }
                        attr->ulValueLen = sizeof(class);
                        break;
                    }
                    case CKA_KEY_TYPE: {
                        CK_KEY_TYPE type = CKK_EC;
                        if (attr->pValue && attr->ulValueLen >= sizeof(type)) {
                            memcpy(attr->pValue, &type, sizeof(type));
                        }
                        attr->ulValueLen = sizeof(type);
                        break;
                    }
                    case CKA_TOKEN: {
                        CK_BBOOL val = CK_TRUE;
                        if (attr->pValue && attr->ulValueLen >= sizeof(val)) {
                            memcpy(attr->pValue, &val, sizeof(val));
                        }
                        attr->ulValueLen = sizeof(val);
                        break;
                    }
                    case CKA_EC_PARAMS: {
                        if (attr->pValue && attr->ulValueLen >= sizeof(SECP256R1_OID)) {
                            memcpy(attr->pValue, SECP256R1_OID, sizeof(SECP256R1_OID));
                        }
                        attr->ulValueLen = sizeof(SECP256R1_OID);
                        break;
                    }
                    case CKA_EC_POINT: {
                        /* Get EC point from certificate */
                        uint8_t ec_point[256];
                        size_t ec_point_len = sizeof(ec_point);
                        nailed_result_t result = nailed_client_get_ec_point(&g_client, ec_point, &ec_point_len);
                        if (result != NAILED_OK) {
                            attr->ulValueLen = CK_UNAVAILABLE_INFORMATION;
                            rv = CKR_DEVICE_ERROR;
                            break;
                        }
                        /* Wrap in OCTET STRING for PKCS#11 */
                        size_t wrapped_len = ec_point_len + 2;
                        if (attr->pValue && attr->ulValueLen >= wrapped_len) {
                            CK_BYTE *out = (CK_BYTE *)attr->pValue;
                            out[0] = 0x04; /* OCTET STRING tag */
                            out[1] = (CK_BYTE)ec_point_len;
                            memcpy(out + 2, ec_point, ec_point_len);
                        }
                        attr->ulValueLen = wrapped_len;
                        break;
                    }
                    case CKA_ID:
                    case CKA_LABEL: {
                        const char *label = "SecureEnclave";
                        size_t len = strlen(label);
                        if (attr->pValue && attr->ulValueLen >= len) {
                            memcpy(attr->pValue, label, len);
                        }
                        attr->ulValueLen = len;
                        break;
                    }
                    default:
                        attr->ulValueLen = CK_UNAVAILABLE_INFORMATION;
                        rv = CKR_ATTRIBUTE_TYPE_INVALID;
                        break;
                }
                break;
            }
            
            case HANDLE_CERTIFICATE: {
                switch (attr->type) {
                    case CKA_CLASS: {
                        CK_OBJECT_CLASS class = CKO_CERTIFICATE;
                        if (attr->pValue && attr->ulValueLen >= sizeof(class)) {
                            memcpy(attr->pValue, &class, sizeof(class));
                        }
                        attr->ulValueLen = sizeof(class);
                        break;
                    }
                    case CKA_CERTIFICATE_TYPE: {
                        CK_CERTIFICATE_TYPE type = CKC_X_509;
                        if (attr->pValue && attr->ulValueLen >= sizeof(type)) {
                            memcpy(attr->pValue, &type, sizeof(type));
                        }
                        attr->ulValueLen = sizeof(type);
                        break;
                    }
                    case CKA_TOKEN: {
                        CK_BBOOL val = CK_TRUE;
                        if (attr->pValue && attr->ulValueLen >= sizeof(val)) {
                            memcpy(attr->pValue, &val, sizeof(val));
                        }
                        attr->ulValueLen = sizeof(val);
                        break;
                    }
                    case CKA_VALUE: {
                        /* Get certificate from nailed */
                        size_t cert_len = 0;
                        nailed_result_t result = nailed_client_get_certificate(&g_client, NULL, &cert_len);
                        if (result != NAILED_OK) {
                            attr->ulValueLen = CK_UNAVAILABLE_INFORMATION;
                            rv = CKR_DEVICE_ERROR;
                            break;
                        }
                        if (attr->pValue && attr->ulValueLen >= cert_len) {
                            nailed_client_get_certificate(&g_client, (uint8_t *)attr->pValue, &cert_len);
                        }
                        attr->ulValueLen = cert_len;
                        break;
                    }
                    case CKA_SUBJECT:
                    case CKA_ISSUER: {
                        /* Get certificate and extract subject/issuer using BoringSSL */
                        uint8_t cert_der[4096];
                        size_t cert_len = sizeof(cert_der);
                        nailed_result_t result = nailed_client_get_certificate(&g_client, cert_der, &cert_len);
                        if (result != NAILED_OK) {
                            attr->ulValueLen = CK_UNAVAILABLE_INFORMATION;
                            rv = CKR_DEVICE_ERROR;
                            break;
                        }
                        
                        const uint8_t *p = cert_der;
                        X509 *x509 = d2i_X509(NULL, &p, (long)cert_len);
                        if (!x509) {
                            attr->ulValueLen = CK_UNAVAILABLE_INFORMATION;
                            rv = CKR_DEVICE_ERROR;
                            break;
                        }
                        
                        X509_NAME *name = (attr->type == CKA_SUBJECT) ? 
                            X509_get_subject_name(x509) : X509_get_issuer_name(x509);
                        
                        /* Get DER encoded name */
                        uint8_t *name_der = NULL;
                        int name_len = i2d_X509_NAME(name, &name_der);
                        if (name_len <= 0) {
                            X509_free(x509);
                            attr->ulValueLen = CK_UNAVAILABLE_INFORMATION;
                            rv = CKR_DEVICE_ERROR;
                            break;
                        }
                        
                        if (attr->pValue && attr->ulValueLen >= (CK_ULONG)name_len) {
                            memcpy(attr->pValue, name_der, name_len);
                        }
                        attr->ulValueLen = name_len;
                        
                        OPENSSL_free(name_der);
                        X509_free(x509);
                        break;
                    }
                    case CKA_SERIAL_NUMBER: {
                        /* Get certificate and extract serial number */
                        uint8_t cert_der[4096];
                        size_t cert_len = sizeof(cert_der);
                        nailed_result_t result = nailed_client_get_certificate(&g_client, cert_der, &cert_len);
                        if (result != NAILED_OK) {
                            attr->ulValueLen = CK_UNAVAILABLE_INFORMATION;
                            rv = CKR_DEVICE_ERROR;
                            break;
                        }
                        
                        const uint8_t *p = cert_der;
                        X509 *x509 = d2i_X509(NULL, &p, (long)cert_len);
                        if (!x509) {
                            attr->ulValueLen = CK_UNAVAILABLE_INFORMATION;
                            rv = CKR_DEVICE_ERROR;
                            break;
                        }
                        
                        const ASN1_INTEGER *serial = X509_get0_serialNumber(x509);
                        uint8_t *serial_der = NULL;
                        int serial_len = i2d_ASN1_INTEGER((ASN1_INTEGER *)serial, &serial_der);
                        if (serial_len <= 0) {
                            X509_free(x509);
                            attr->ulValueLen = CK_UNAVAILABLE_INFORMATION;
                            rv = CKR_DEVICE_ERROR;
                            break;
                        }
                        
                        if (attr->pValue && attr->ulValueLen >= (CK_ULONG)serial_len) {
                            memcpy(attr->pValue, serial_der, serial_len);
                        }
                        attr->ulValueLen = serial_len;
                        
                        OPENSSL_free(serial_der);
                        X509_free(x509);
                        break;
                    }
                    case CKA_ID:
                    case CKA_LABEL: {
                        const char *label = "SecureEnclave";
                        size_t len = strlen(label);
                        if (attr->pValue && attr->ulValueLen >= len) {
                            memcpy(attr->pValue, label, len);
                        }
                        attr->ulValueLen = len;
                        break;
                    }
                    default:
                        attr->ulValueLen = CK_UNAVAILABLE_INFORMATION;
                        rv = CKR_ATTRIBUTE_TYPE_INVALID;
                        break;
                }
                break;
            }
            
            default:
                pthread_mutex_unlock(&g_mutex);
                return CKR_OBJECT_HANDLE_INVALID;
        }
    }
    
    pthread_mutex_unlock(&g_mutex);
    return rv;
}

CK_RV C_SetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                          CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    (void)hSession; (void)hObject; (void)pTemplate; (void)ulCount;
    NOT_SUPPORTED();
}

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    DEBUG_LOG("C_FindObjectsInit: session=%lu, template_count=%lu", (unsigned long)hSession, (unsigned long)ulCount);
    
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    
    pthread_mutex_lock(&g_mutex);
    
    session_t *session = find_session(hSession);
    if (!session) {
        pthread_mutex_unlock(&g_mutex);
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    if (session->find_active) {
        pthread_mutex_unlock(&g_mutex);
        return CKR_OPERATION_ACTIVE;
    }
    
    /* Parse template to find object class filter */
    session->find_class = (CK_OBJECT_CLASS)-1; /* Match all */
    for (CK_ULONG i = 0; i < ulCount; i++) {
        DEBUG_LOG("  template[%lu]: type=0x%lx", (unsigned long)i, (unsigned long)pTemplate[i].type);
        if (pTemplate[i].type == CKA_CLASS && pTemplate[i].pValue && pTemplate[i].ulValueLen == sizeof(CK_OBJECT_CLASS)) {
            session->find_class = *(CK_OBJECT_CLASS *)pTemplate[i].pValue;
            DEBUG_LOG("  -> filtering by class=0x%lx", (unsigned long)session->find_class);
        }
    }
    
    session->find_active = CK_TRUE;
    session->find_index = 0;
    
    pthread_mutex_unlock(&g_mutex);
    return CKR_OK;
}

CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject,
                    CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
    DEBUG_LOG("C_FindObjects: session=%lu, max=%lu", (unsigned long)hSession, (unsigned long)ulMaxObjectCount);
    
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (phObject == NULL_PTR || pulObjectCount == NULL_PTR) return CKR_ARGUMENTS_BAD;
    
    pthread_mutex_lock(&g_mutex);
    
    session_t *session = find_session(hSession);
    if (!session) {
        pthread_mutex_unlock(&g_mutex);
        DEBUG_LOG("  -> session not found");
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    if (!session->find_active) {
        pthread_mutex_unlock(&g_mutex);
        DEBUG_LOG("  -> find not active");
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    
    *pulObjectCount = 0;
    
    /* Check if nailed server has a certificate/key */
    size_t cert_len = 0;
    nailed_result_t result = nailed_client_get_certificate(&g_client, NULL, &cert_len);
    if (result != NAILED_OK) {
        pthread_mutex_unlock(&g_mutex);
        DEBUG_LOG("  -> no certificate available (result=%d)", result);
        return CKR_OK; /* No objects available */
    }
    
    DEBUG_LOG("  -> certificate available, %zu bytes", cert_len);
    
    /* Objects: private key, public key, certificate */
    CK_OBJECT_HANDLE objects[3];
    CK_ULONG num_objects = 0;
    
    if (session->find_class == (CK_OBJECT_CLASS)-1 || session->find_class == CKO_PRIVATE_KEY) {
        objects[num_objects++] = HANDLE_PRIVATE_KEY;
    }
    if (session->find_class == (CK_OBJECT_CLASS)-1 || session->find_class == CKO_PUBLIC_KEY) {
        objects[num_objects++] = HANDLE_PUBLIC_KEY;
    }
    if (session->find_class == (CK_OBJECT_CLASS)-1 || session->find_class == CKO_CERTIFICATE) {
        objects[num_objects++] = HANDLE_CERTIFICATE;
    }
    
    /* Return objects starting from find_index */
    CK_ULONG count = 0;
    while (session->find_index < num_objects && count < ulMaxObjectCount) {
        phObject[count++] = objects[session->find_index++];
    }
    *pulObjectCount = count;
    
    DEBUG_LOG("  -> returning %lu objects", (unsigned long)count);
    
    pthread_mutex_unlock(&g_mutex);
    return CKR_OK;
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    
    pthread_mutex_lock(&g_mutex);
    
    session_t *session = find_session(hSession);
    if (!session) {
        pthread_mutex_unlock(&g_mutex);
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    if (!session->find_active) {
        pthread_mutex_unlock(&g_mutex);
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    
    session->find_active = CK_FALSE;
    
    pthread_mutex_unlock(&g_mutex);
    return CKR_OK;
}

/* ===== Encryption functions (not supported) ===== */

CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{ (void)hSession; (void)pMechanism; (void)hKey; NOT_SUPPORTED(); }

CK_RV C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{ (void)hSession; (void)pData; (void)ulDataLen; (void)pEncryptedData; (void)pulEncryptedDataLen; NOT_SUPPORTED(); }

CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen,
                      CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{ (void)hSession; (void)pPart; (void)ulPartLen; (void)pEncryptedPart; (void)pulEncryptedPartLen; NOT_SUPPORTED(); }

CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart,
                     CK_ULONG_PTR pulLastEncryptedPartLen)
{ (void)hSession; (void)pLastEncryptedPart; (void)pulLastEncryptedPartLen; NOT_SUPPORTED(); }

/* ===== Decryption functions (not supported) ===== */

CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{ (void)hSession; (void)pMechanism; (void)hKey; NOT_SUPPORTED(); }

CK_RV C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen,
                CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{ (void)hSession; (void)pEncryptedData; (void)ulEncryptedDataLen; (void)pData; (void)pulDataLen; NOT_SUPPORTED(); }

CK_RV C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen,
                      CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{ (void)hSession; (void)pEncryptedPart; (void)ulEncryptedPartLen; (void)pPart; (void)pulPartLen; NOT_SUPPORTED(); }

CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen)
{ (void)hSession; (void)pLastPart; (void)pulLastPartLen; NOT_SUPPORTED(); }

/* ===== Digest functions (not supported) ===== */

CK_RV C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{ (void)hSession; (void)pMechanism; NOT_SUPPORTED(); }

CK_RV C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
               CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{ (void)hSession; (void)pData; (void)ulDataLen; (void)pDigest; (void)pulDigestLen; NOT_SUPPORTED(); }

CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{ (void)hSession; (void)pPart; (void)ulPartLen; NOT_SUPPORTED(); }

CK_RV C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{ (void)hSession; (void)hKey; NOT_SUPPORTED(); }

CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{ (void)hSession; (void)pDigest; (void)pulDigestLen; NOT_SUPPORTED(); }

/* ===== Signing functions ===== */

CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;
    
    /* Only support ECDSA */
    if (pMechanism->mechanism != CKM_ECDSA && pMechanism->mechanism != CKM_ECDSA_SHA256) {
        return CKR_MECHANISM_INVALID;
    }
    
    /* Only support our private key */
    if (hKey != HANDLE_PRIVATE_KEY) {
        return CKR_KEY_HANDLE_INVALID;
    }
    
    pthread_mutex_lock(&g_mutex);
    
    session_t *session = find_session(hSession);
    if (!session) {
        pthread_mutex_unlock(&g_mutex);
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    if (session->sign_active) {
        pthread_mutex_unlock(&g_mutex);
        return CKR_OPERATION_ACTIVE;
    }
    
    session->sign_active = CK_TRUE;
    session->sign_mechanism = pMechanism->mechanism;
    session->sign_key = hKey;
    session->sign_data = NULL;
    session->sign_data_len = 0;
    
    DEBUG_LOG("SignInit: mechanism=%lu, key=%lu", (unsigned long)pMechanism->mechanism, (unsigned long)hKey);
    
    pthread_mutex_unlock(&g_mutex);
    return CKR_OK;
}

CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
             CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (pData == NULL_PTR || pulSignatureLen == NULL_PTR) return CKR_ARGUMENTS_BAD;
    
    pthread_mutex_lock(&g_mutex);
    
    session_t *session = find_session(hSession);
    if (!session) {
        pthread_mutex_unlock(&g_mutex);
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    if (!session->sign_active) {
        pthread_mutex_unlock(&g_mutex);
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    
    /* For CKM_ECDSA, data should be a pre-hashed digest (32 bytes for SHA-256) */
    if (ulDataLen != 32) {
        session->sign_active = CK_FALSE;
        pthread_mutex_unlock(&g_mutex);
        return CKR_DATA_LEN_RANGE;
    }
    
    /* Query signature size */
    if (pSignature == NULL_PTR) {
        /* ECDSA P-256 raw R||S signature is exactly 64 bytes */
        *pulSignatureLen = 64;
        pthread_mutex_unlock(&g_mutex);
        return CKR_OK;
    }
    
    /* Sign via nailed */
    uint8_t signature[256];
    size_t sig_len = sizeof(signature);
    
    nailed_result_t result = nailed_client_sign(&g_client, pData, ulDataLen, signature, &sig_len);
    
    session->sign_active = CK_FALSE;
    
    if (result != NAILED_OK) {
        pthread_mutex_unlock(&g_mutex);
        DEBUG_LOG("Sign failed: %d", result);
        return CKR_DEVICE_ERROR;
    }
    
    /* Convert DER signature to raw R||S format for PKCS#11 */
    uint8_t raw_sig[64];
    size_t raw_len = der_sig_to_raw(signature, sig_len, raw_sig, sizeof(raw_sig));
    if (raw_len == 0) {
        pthread_mutex_unlock(&g_mutex);
        DEBUG_LOG("Sign failed: DER to raw conversion error");
        return CKR_DEVICE_ERROR;
    }
    
    if (*pulSignatureLen < raw_len) {
        *pulSignatureLen = raw_len;
        pthread_mutex_unlock(&g_mutex);
        return CKR_BUFFER_TOO_SMALL;
    }
    
    memcpy(pSignature, raw_sig, raw_len);
    *pulSignatureLen = raw_len;
    
    DEBUG_LOG("Sign successful: %zu bytes (converted from %zu DER)", raw_len, sig_len);
    
    pthread_mutex_unlock(&g_mutex);
    return CKR_OK;
}

CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    DEBUG_LOG("C_SignUpdate: session=%lu, len=%lu", (unsigned long)hSession, (unsigned long)ulPartLen);
    
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (pPart == NULL_PTR && ulPartLen > 0) return CKR_ARGUMENTS_BAD;
    
    pthread_mutex_lock(&g_mutex);
    
    session_t *session = find_session(hSession);
    if (!session) {
        pthread_mutex_unlock(&g_mutex);
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    if (!session->sign_active) {
        pthread_mutex_unlock(&g_mutex);
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    
    /* Only support multi-part for CKM_ECDSA_SHA256 */
    if (session->sign_mechanism != CKM_ECDSA_SHA256) {
        pthread_mutex_unlock(&g_mutex);
        return CKR_FUNCTION_NOT_SUPPORTED;
    }
    
    /* Allocate or extend buffer */
    if (ulPartLen > 0) {
        size_t new_len = session->sign_data_len + ulPartLen;
        if (new_len > MAX_SIGN_DATA_SIZE) {
            pthread_mutex_unlock(&g_mutex);
            return CKR_DATA_LEN_RANGE;
        }
        
        uint8_t *new_buf = realloc(session->sign_data, new_len);
        if (!new_buf) {
            pthread_mutex_unlock(&g_mutex);
            return CKR_HOST_MEMORY;
        }
        
        memcpy(new_buf + session->sign_data_len, pPart, ulPartLen);
        session->sign_data = new_buf;
        session->sign_data_len = new_len;
    }
    
    DEBUG_LOG("  -> accumulated %zu bytes total", session->sign_data_len);
    
    pthread_mutex_unlock(&g_mutex);
    return CKR_OK;
}

CK_RV C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    DEBUG_LOG("C_SignFinal: session=%lu, pSignature=%p", (unsigned long)hSession, (void*)pSignature);
    
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (pulSignatureLen == NULL_PTR) return CKR_ARGUMENTS_BAD;
    
    pthread_mutex_lock(&g_mutex);
    
    session_t *session = find_session(hSession);
    if (!session) {
        pthread_mutex_unlock(&g_mutex);
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    if (!session->sign_active) {
        pthread_mutex_unlock(&g_mutex);
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    
    /* Only support multi-part for CKM_ECDSA_SHA256 */
    if (session->sign_mechanism != CKM_ECDSA_SHA256) {
        session->sign_active = CK_FALSE;
        pthread_mutex_unlock(&g_mutex);
        return CKR_FUNCTION_NOT_SUPPORTED;
    }
    
    /* Query signature size */
    if (pSignature == NULL_PTR) {
        *pulSignatureLen = 64; /* ECDSA P-256 raw R||S signature */
        pthread_mutex_unlock(&g_mutex);
        return CKR_OK;
    }
    
    /* Hash the accumulated data with SHA-256 */
    uint8_t digest[SHA256_DIGEST_LENGTH];
    SHA256(session->sign_data, session->sign_data_len, digest);
    
    DEBUG_LOG("  -> hashed %zu bytes to SHA256 digest", session->sign_data_len);
    
    /* Sign the digest via nailed */
    uint8_t signature[256];
    size_t sig_len = sizeof(signature);
    
    nailed_result_t result = nailed_client_sign(&g_client, digest, sizeof(digest), signature, &sig_len);
    
    /* Clean up sign state */
    free(session->sign_data);
    session->sign_data = NULL;
    session->sign_data_len = 0;
    session->sign_active = CK_FALSE;
    
    if (result != NAILED_OK) {
        pthread_mutex_unlock(&g_mutex);
        DEBUG_LOG("  -> sign failed: %d", result);
        return CKR_DEVICE_ERROR;
    }
    
    /* Convert DER signature to raw R||S format for PKCS#11 */
    uint8_t raw_sig[64];
    size_t raw_len = der_sig_to_raw(signature, sig_len, raw_sig, sizeof(raw_sig));
    if (raw_len == 0) {
        pthread_mutex_unlock(&g_mutex);
        DEBUG_LOG("  -> sign failed: DER to raw conversion error");
        return CKR_DEVICE_ERROR;
    }
    
    if (*pulSignatureLen < raw_len) {
        *pulSignatureLen = raw_len;
        pthread_mutex_unlock(&g_mutex);
        return CKR_BUFFER_TOO_SMALL;
    }
    
    memcpy(pSignature, raw_sig, raw_len);
    *pulSignatureLen = raw_len;
    
    DEBUG_LOG("  -> signature: %zu raw bytes (from %zu DER)", raw_len, sig_len);
    
    pthread_mutex_unlock(&g_mutex);
    return CKR_OK;
}

CK_RV C_SignRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{ (void)hSession; (void)pMechanism; (void)hKey; NOT_SUPPORTED(); }

CK_RV C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                    CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{ (void)hSession; (void)pData; (void)ulDataLen; (void)pSignature; (void)pulSignatureLen; NOT_SUPPORTED(); }

/* ===== Verification functions (not supported - use public key directly) ===== */

CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{ (void)hSession; (void)pMechanism; (void)hKey; NOT_SUPPORTED(); }

CK_RV C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
               CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{ (void)hSession; (void)pData; (void)ulDataLen; (void)pSignature; (void)ulSignatureLen; NOT_SUPPORTED(); }

CK_RV C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{ (void)hSession; (void)pPart; (void)ulPartLen; NOT_SUPPORTED(); }

CK_RV C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{ (void)hSession; (void)pSignature; (void)ulSignatureLen; NOT_SUPPORTED(); }

CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{ (void)hSession; (void)pMechanism; (void)hKey; NOT_SUPPORTED(); }

CK_RV C_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen,
                      CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{ (void)hSession; (void)pSignature; (void)ulSignatureLen; (void)pData; (void)pulDataLen; NOT_SUPPORTED(); }

/* ===== Dual-purpose functions (not supported) ===== */

CK_RV C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen,
                            CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{ (void)hSession; (void)pPart; (void)ulPartLen; (void)pEncryptedPart; (void)pulEncryptedPartLen; NOT_SUPPORTED(); }

CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart,
                            CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{ (void)hSession; (void)pEncryptedPart; (void)ulEncryptedPartLen; (void)pPart; (void)pulPartLen; NOT_SUPPORTED(); }

CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen,
                          CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{ (void)hSession; (void)pPart; (void)ulPartLen; (void)pEncryptedPart; (void)pulEncryptedPartLen; NOT_SUPPORTED(); }

CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart,
                            CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{ (void)hSession; (void)pEncryptedPart; (void)ulEncryptedPartLen; (void)pPart; (void)pulPartLen; NOT_SUPPORTED(); }

/* ===== Key management (not supported) ===== */

CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey)
{ (void)hSession; (void)pMechanism; (void)pTemplate; (void)ulCount; (void)phKey; NOT_SUPPORTED(); }

CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                        CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount,
                        CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount,
                        CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey)
{ (void)hSession; (void)pMechanism; (void)pPublicKeyTemplate; (void)ulPublicKeyAttributeCount;
  (void)pPrivateKeyTemplate; (void)ulPrivateKeyAttributeCount; (void)phPublicKey; (void)phPrivateKey; NOT_SUPPORTED(); }

CK_RV C_WrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey,
                CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen)
{ (void)hSession; (void)pMechanism; (void)hWrappingKey; (void)hKey; (void)pWrappedKey; (void)pulWrappedKeyLen; NOT_SUPPORTED(); }

CK_RV C_UnwrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                  CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen,
                  CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{ (void)hSession; (void)pMechanism; (void)hUnwrappingKey; (void)pWrappedKey; (void)ulWrappedKeyLen;
  (void)pTemplate; (void)ulAttributeCount; (void)phKey; NOT_SUPPORTED(); }

CK_RV C_DeriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                  CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate,
                  CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{ (void)hSession; (void)pMechanism; (void)hBaseKey; (void)pTemplate; (void)ulAttributeCount; (void)phKey; NOT_SUPPORTED(); }

/* ===== Random number generation (not supported) ===== */

CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)
{ (void)hSession; (void)pSeed; (void)ulSeedLen; NOT_SUPPORTED(); }

CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen)
{ (void)hSession; (void)pRandomData; (void)ulRandomLen; NOT_SUPPORTED(); }

/* ===== Parallel function management (legacy) ===== */

CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE hSession)
{ (void)hSession; DEBUG_LOG("%s -> CKR_FUNCTION_NOT_PARALLEL", __func__); return CKR_FUNCTION_NOT_PARALLEL; }

CK_RV C_CancelFunction(CK_SESSION_HANDLE hSession)
{ (void)hSession; DEBUG_LOG("%s -> CKR_FUNCTION_NOT_PARALLEL", __func__); return CKR_FUNCTION_NOT_PARALLEL; }

CK_RV C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved)
{ (void)flags; (void)pSlot; (void)pReserved; NOT_SUPPORTED(); }

/* ===== Function list ===== */

static CK_FUNCTION_LIST g_function_list = {
    .version = { 2, 40 },
    .C_Initialize = C_Initialize,
    .C_Finalize = C_Finalize,
    .C_GetInfo = C_GetInfo,
    .C_GetFunctionList = C_GetFunctionList,
    .C_GetSlotList = C_GetSlotList,
    .C_GetSlotInfo = C_GetSlotInfo,
    .C_GetTokenInfo = C_GetTokenInfo,
    .C_GetMechanismList = C_GetMechanismList,
    .C_GetMechanismInfo = C_GetMechanismInfo,
    .C_InitToken = C_InitToken,
    .C_InitPIN = C_InitPIN,
    .C_SetPIN = C_SetPIN,
    .C_OpenSession = C_OpenSession,
    .C_CloseSession = C_CloseSession,
    .C_CloseAllSessions = C_CloseAllSessions,
    .C_GetSessionInfo = C_GetSessionInfo,
    .C_GetOperationState = C_GetOperationState,
    .C_SetOperationState = C_SetOperationState,
    .C_Login = C_Login,
    .C_Logout = C_Logout,
    .C_CreateObject = C_CreateObject,
    .C_CopyObject = C_CopyObject,
    .C_DestroyObject = C_DestroyObject,
    .C_GetObjectSize = C_GetObjectSize,
    .C_GetAttributeValue = C_GetAttributeValue,
    .C_SetAttributeValue = C_SetAttributeValue,
    .C_FindObjectsInit = C_FindObjectsInit,
    .C_FindObjects = C_FindObjects,
    .C_FindObjectsFinal = C_FindObjectsFinal,
    .C_EncryptInit = C_EncryptInit,
    .C_Encrypt = C_Encrypt,
    .C_EncryptUpdate = C_EncryptUpdate,
    .C_EncryptFinal = C_EncryptFinal,
    .C_DecryptInit = C_DecryptInit,
    .C_Decrypt = C_Decrypt,
    .C_DecryptUpdate = C_DecryptUpdate,
    .C_DecryptFinal = C_DecryptFinal,
    .C_DigestInit = C_DigestInit,
    .C_Digest = C_Digest,
    .C_DigestUpdate = C_DigestUpdate,
    .C_DigestKey = C_DigestKey,
    .C_DigestFinal = C_DigestFinal,
    .C_SignInit = C_SignInit,
    .C_Sign = C_Sign,
    .C_SignUpdate = C_SignUpdate,
    .C_SignFinal = C_SignFinal,
    .C_SignRecoverInit = C_SignRecoverInit,
    .C_SignRecover = C_SignRecover,
    .C_VerifyInit = C_VerifyInit,
    .C_Verify = C_Verify,
    .C_VerifyUpdate = C_VerifyUpdate,
    .C_VerifyFinal = C_VerifyFinal,
    .C_VerifyRecoverInit = C_VerifyRecoverInit,
    .C_VerifyRecover = C_VerifyRecover,
    .C_DigestEncryptUpdate = C_DigestEncryptUpdate,
    .C_DecryptDigestUpdate = C_DecryptDigestUpdate,
    .C_SignEncryptUpdate = C_SignEncryptUpdate,
    .C_DecryptVerifyUpdate = C_DecryptVerifyUpdate,
    .C_GenerateKey = C_GenerateKey,
    .C_GenerateKeyPair = C_GenerateKeyPair,
    .C_WrapKey = C_WrapKey,
    .C_UnwrapKey = C_UnwrapKey,
    .C_DeriveKey = C_DeriveKey,
    .C_SeedRandom = C_SeedRandom,
    .C_GenerateRandom = C_GenerateRandom,
    .C_GetFunctionStatus = C_GetFunctionStatus,
    .C_CancelFunction = C_CancelFunction,
    .C_WaitForSlotEvent = C_WaitForSlotEvent,
};

