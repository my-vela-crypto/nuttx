/****************************************************************************
 * include/nuttx/fs/encpathfs.h
 *
 * SPDX-License-Identifier: Apache-2.0
 ****************************************************************************/

#ifndef __INCLUDE_NUTTX_FS_ENCPATHFS_H
#define __INCLUDE_NUTTX_FS_ENCPATHFS_H

#include <nuttx/config.h>
#include <nuttx/compiler.h>
#include <stddef.h>
#include <stdint.h>

#define ENCPATHFS_KEY_SIZE       32
#define ENCPATHFS_NAME_MAX       128
#define ENCPATHFS_ENCODED_MAX    234

#ifdef __cplusplus
extern "C"
{
#endif

/* Slot zero is consumed and erased by bind, including failed bind attempts.
 * While a mount is being created or exists, changing slots returns -EBUSY.
 * initialize is an explicit, non-overwriting operation on visible lower FAT.
 */

int encpathfs_setkey(unsigned int slot, FAR const uint8_t *key,
                    size_t keylen);
int encpathfs_clearkey(unsigned int slot);
int encpathfs_initialize(FAR const char *lower, FAR const uint8_t *key,
                        size_t keylen);

/* Retry a failed metadata close/initialization rollback before unmounting
 * a still-visible lower volume.  Failure preserves its inode and handles;
 * normal mounted-volume cleanup remains the responsibility of unbind.
 */

int encpathfs_recover(void);

/* Authenticated component codec.  Capacities include a terminating NUL.
 * Names are printable ASCII excluding '/' and the structural . and .. .
 * Success returns zero; invalid/corrupt encodings return a negative errno.
 */

int encpathfs_encode_name(FAR const uint8_t *key, FAR const char *name,
                        FAR char *encoded, size_t capacity);
int encpathfs_decode_name(FAR const uint8_t *key, FAR const char *encoded,
                        FAR char *name, size_t capacity);

#ifdef __cplusplus
}
#endif
#endif /* __INCLUDE_NUTTX_FS_ENCPATHFS_H */
