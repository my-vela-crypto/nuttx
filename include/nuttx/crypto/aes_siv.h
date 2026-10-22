/****************************************************************************
 * include/nuttx/crypto/aes_siv.h
 *
 * SPDX-License-Identifier: Apache-2.0
 ****************************************************************************/

#ifndef __INCLUDE_NUTTX_CRYPTO_AES_SIV_H
#define __INCLUDE_NUTTX_CRYPTO_AES_SIV_H

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

#define AES_SIV_KEY_SIZE 32
#define AES_SIV_TAG_SIZE 16

/****************************************************************************
 * Public Function Prototypes
 ****************************************************************************/

#ifdef __cplusplus
extern "C"
{
#endif

/* RFC 5297 AES-SIV-CMAC-256, using two AES-128 keys and exactly one AD
 * string (including when adlen is zero).  sealed has plainlen + 16 bytes:
 * the unmasked SIV followed by the ciphertext.  The caller supplies output
 * space.  Input and output text may overlap; key and AD must not overlap
 * output.  A zero length input text or AD may have a NULL pointer.
 *
 * Return zero on success, -EINVAL for invalid pointers/lengths, -EOVERFLOW
 * for encryption length overflow, or -EBADMSG for failed authentication.
 * Decrypt clears the entire plaintext output on authentication failure.
 */

int aes_siv_encrypt(FAR const uint8_t key[AES_SIV_KEY_SIZE],
                    FAR const uint8_t *ad, size_t adlen,
                    FAR const uint8_t *plain, size_t plainlen,
                    FAR uint8_t *sealed);
int aes_siv_decrypt(FAR const uint8_t key[AES_SIV_KEY_SIZE],
                    FAR const uint8_t *ad, size_t adlen,
                    FAR const uint8_t *sealed, size_t sealedlen,
                    FAR uint8_t *plain);

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_NUTTX_CRYPTO_AES_SIV_H */
