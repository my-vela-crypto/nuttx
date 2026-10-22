/****************************************************************************
 * include/nuttx/crypto/hkdf.h
 *
 * SPDX-License-Identifier: Apache-2.0
 ****************************************************************************/

#ifndef __INCLUDE_NUTTX_CRYPTO_HKDF_H
#define __INCLUDE_NUTTX_CRYPTO_HKDF_H

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>
#include <nuttx/compiler.h>

#include <stddef.h>
#include <stdint.h>

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

#define HKDF_SHA256_MAX_OUTPUT (255 * 32)

/****************************************************************************
 * Public Function Prototypes
 ****************************************************************************/

#ifdef __cplusplus
extern "C"
{
#endif

/* RFC 5869 Extract-and-Expand using HMAC-SHA256.  Empty salt is equivalent
 * to 32 zero bytes.  A zero length buffer may be NULL.  Output must not
 * overlap info; it may overlap IKM or salt.  Return zero on success,
 * -EINVAL for invalid pointers or an output length above 255 * 32 bytes.
 */

int hkdf_sha256(FAR const uint8_t *ikm, size_t ikmlen,
                FAR const uint8_t *salt, size_t saltlen,
                FAR const uint8_t *info, size_t infolen,
                FAR uint8_t *out, size_t outlen);

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_NUTTX_CRYPTO_HKDF_H */
