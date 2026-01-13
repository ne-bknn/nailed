/* SPDX-License-Identifier: Apache-2.0
 * Platform-specific definitions for PKCS#11 on macOS/UNIX
 * This file must be included before the OASIS PKCS#11 headers
 */

#ifndef _NAILED_PKCS11_PLATFORM_H_
#define _NAILED_PKCS11_PLATFORM_H_

/* Platform-specific macros required by PKCS#11 headers */

/* 1. CK_PTR: pointer indirection */
#define CK_PTR *

/* 2. CK_DECLARE_FUNCTION: for library function declarations */
#define CK_DECLARE_FUNCTION(returnType, name) \
    returnType name

/* 3. CK_DECLARE_FUNCTION_POINTER: for function pointer types */
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
    returnType (* name)

/* 4. CK_CALLBACK_FUNCTION: for callback function types */
#define CK_CALLBACK_FUNCTION(returnType, name) \
    returnType (* name)

/* 5. NULL_PTR: null pointer value */
#ifndef NULL_PTR
#define NULL_PTR 0
#endif

/* Now include the official OASIS PKCS#11 headers */
#include "vendor/pkcs11/pkcs11.h"

#endif /* _NAILED_PKCS11_PLATFORM_H_ */

