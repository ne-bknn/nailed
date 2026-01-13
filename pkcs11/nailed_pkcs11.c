/* SPDX-License-Identifier: Apache-2.0
 * PKCS#11 implementation for nailed Secure Enclave signing
 */

#include "nailed_pkcs11_platform.h"
#include "nailed_client.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

/* Debug logging */
#ifdef NAILED_DEBUG
#define DEBUG_LOG(fmt, ...) fprintf(stderr, "[pkcs11] " fmt "\n", ##__VA_ARGS__)
#else
#define DEBUG_LOG(fmt, ...) ((void)0)
#endif

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
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (pulCount == NULL_PTR) return CKR_ARGUMENTS_BAD;
    
    /* We always have exactly one slot */
    if (pSlotList == NULL_PTR) {
        *pulCount = 1;
        return CKR_OK;
    }
    
    if (*pulCount < 1) {
        *pulCount = 1;
        return CKR_BUFFER_TOO_SMALL;
    }
    
    pSlotList[0] = 0;
    *pulCount = 1;
    return CKR_OK;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
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
    
    return CKR_OK;
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (slotID != 0) return CKR_SLOT_ID_INVALID;
    if (pInfo == NULL_PTR) return CKR_ARGUMENTS_BAD;
    
    if (!nailed_client_is_available(&g_client)) {
        return CKR_TOKEN_NOT_PRESENT;
    }
    
    pad_string(pInfo->label, NAILED_TOKEN_LABEL, 32);
    pad_string(pInfo->manufacturerID, NAILED_MANUFACTURER_ID, 32);
    pad_string(pInfo->model, NAILED_TOKEN_MODEL, 16);
    memcpy(pInfo->serialNumber, NAILED_TOKEN_SERIAL, 16);
    
    pInfo->flags = CKF_TOKEN_INITIALIZED | CKF_PROTECTED_AUTHENTICATION_PATH | CKF_HW_SLOT;
    
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
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen,
               CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
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
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState,
                          CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey,
                          CK_OBJECT_HANDLE hAuthenticationKey)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
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
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                   CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                          CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (pTemplate == NULL_PTR) return CKR_ARGUMENTS_BAD;
    
    pthread_mutex_lock(&g_mutex);
    
    session_t *session = find_session(hSession);
    if (!session) {
        pthread_mutex_unlock(&g_mutex);
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    CK_RV rv = CKR_OK;
    
    for (CK_ULONG i = 0; i < ulCount; i++) {
        CK_ATTRIBUTE *attr = &pTemplate[i];
        
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
                        CK_BBOOL val = CK_TRUE;
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
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
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
        if (pTemplate[i].type == CKA_CLASS && pTemplate[i].pValue && pTemplate[i].ulValueLen == sizeof(CK_OBJECT_CLASS)) {
            session->find_class = *(CK_OBJECT_CLASS *)pTemplate[i].pValue;
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
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (phObject == NULL_PTR || pulObjectCount == NULL_PTR) return CKR_ARGUMENTS_BAD;
    
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
    
    *pulObjectCount = 0;
    
    /* Check if nailed server has a certificate/key */
    size_t cert_len = 0;
    nailed_result_t result = nailed_client_get_certificate(&g_client, NULL, &cert_len);
    if (result != NAILED_OK) {
        pthread_mutex_unlock(&g_mutex);
        return CKR_OK; /* No objects available */
    }
    
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
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen,
                      CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart,
                     CK_ULONG_PTR pulLastEncryptedPartLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* ===== Decryption functions (not supported) ===== */

CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen,
                CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen,
                      CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* ===== Digest functions (not supported) ===== */

CK_RV C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
               CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

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
        /* ECDSA P-256 signature is at most 72 bytes (DER encoded) or 64 bytes (raw R||S) */
        *pulSignatureLen = 72;
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
    
    if (*pulSignatureLen < sig_len) {
        *pulSignatureLen = sig_len;
        pthread_mutex_unlock(&g_mutex);
        return CKR_BUFFER_TOO_SMALL;
    }
    
    memcpy(pSignature, signature, sig_len);
    *pulSignatureLen = sig_len;
    
    DEBUG_LOG("Sign successful: %zu bytes", sig_len);
    
    pthread_mutex_unlock(&g_mutex);
    return CKR_OK;
}

CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                    CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* ===== Verification functions (not supported - use public key directly) ===== */

CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
               CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen,
                      CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* ===== Dual-purpose functions (not supported) ===== */

CK_RV C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen,
                            CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart,
                            CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen,
                          CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart,
                            CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* ===== Key management (not supported) ===== */

CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                        CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount,
                        CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount,
                        CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_WrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey,
                CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_UnwrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                  CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen,
                  CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DeriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                  CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate,
                  CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* ===== Random number generation (not supported) ===== */

CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* ===== Parallel function management (legacy) ===== */

CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE hSession)
{
    return CKR_FUNCTION_NOT_PARALLEL;
}

CK_RV C_CancelFunction(CK_SESSION_HANDLE hSession)
{
    return CKR_FUNCTION_NOT_PARALLEL;
}

CK_RV C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

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

