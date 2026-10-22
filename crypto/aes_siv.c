/****************************************************************************
 * crypto/aes_siv.c
 *
 * SPDX-License-Identifier: Apache-2.0
 ****************************************************************************/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>

#include <crypto/aes.h>
#include <crypto/cmac.h>
#include <nuttx/crypto/aes_siv.h>

/****************************************************************************
 * Private Functions
 ****************************************************************************/

/* Adapt the existing CMAC API without narrowing size_t lengths. */

static void siv_cmac_update(FAR AES_CMAC_CTX *ctx,
                            FAR const uint8_t *data, size_t len)
{
  unsigned int chunk;

  while (len != 0)
    {
      chunk = len > UINT_MAX ? UINT_MAX : (unsigned int)len;
      aes_cmac_update(ctx, data, chunk);
      data += chunk;
      len -= chunk;
    }
}

static void siv_cmac_start(FAR AES_CMAC_CTX *ctx, FAR const uint8_t *key)
{
  memset(ctx, 0, sizeof(*ctx));
  aes_cmac_init(ctx);
  aes_cmac_setkey(ctx, key);
}

/* Multiply a big-endian 128-bit value by x in GF(2^128). */

static void siv_double(FAR uint8_t *block)
{
  uint8_t carry = block[0] >> 7;
  int i;

  for (i = 0; i < AES_SIV_TAG_SIZE - 1; i++)
    {
      block[i] = (block[i] << 1) | (block[i + 1] >> 7);
    }

  block[AES_SIV_TAG_SIZE - 1] =
    (block[AES_SIV_TAG_SIZE - 1] << 1) ^ (0x87 & (0 - carry));
}

/* S2V with two strings: AD, followed by plaintext.  For a long plaintext
 * xorend applies to its final 16 bytes, even across a CMAC block boundary.
 */

static void siv_s2v(FAR const uint8_t *key, FAR const uint8_t *ad,
                    size_t adlen, FAR const uint8_t *plain,
                    size_t plainlen, FAR uint8_t *tag)
{
  AES_CMAC_CTX ctx;
  uint8_t d[AES_SIV_TAG_SIZE];
  uint8_t block[AES_SIV_TAG_SIZE];
  size_t i;

  memset(block, 0, sizeof(block));
  siv_cmac_start(&ctx, key);
  siv_cmac_update(&ctx, block, sizeof(block));
  aes_cmac_final(d, &ctx);

  siv_double(d);
  siv_cmac_start(&ctx, key);
  siv_cmac_update(&ctx, ad, adlen);
  aes_cmac_final(block, &ctx);

  for (i = 0; i < sizeof(d); i++)
    {
      d[i] ^= block[i];
    }

  siv_cmac_start(&ctx, key);
  if (plainlen >= sizeof(block))
    {
      siv_cmac_update(&ctx, plain, plainlen - sizeof(block));
      for (i = 0; i < sizeof(block); i++)
        {
          block[i] = plain[plainlen - sizeof(block) + i] ^ d[i];
        }
    }
  else
    {
      siv_double(d);
      memset(block, 0, sizeof(block));
      if (plainlen != 0)
        {
          memcpy(block, plain, plainlen);
        }

      block[plainlen] = 0x80;
      for (i = 0; i < sizeof(block); i++)
        {
          block[i] ^= d[i];
        }
    }

  siv_cmac_update(&ctx, block, sizeof(block));
  aes_cmac_final(tag, &ctx);
  explicit_bzero(&ctx, sizeof(ctx));
  explicit_bzero(d, sizeof(d));
  explicit_bzero(block, sizeof(block));
}

/* RFC 5297 clears bits 31 and 63 (numbered from the right) before CTR.
 * Increment all 128 bits, so there is no 32-bit counter length restriction.
 */

static void siv_ctr(FAR const uint8_t *key, FAR const uint8_t *tag,
                    FAR uint8_t *text, size_t len)
{
  AES_CTX ctx;
  uint8_t counter[AES_SIV_TAG_SIZE];
  uint8_t stream[AES_SIV_TAG_SIZE];
  size_t chunk;
  size_t i;
  int j;

  memset(&ctx, 0, sizeof(ctx));
  aes_setkey(&ctx, key, 16);
  memcpy(counter, tag, sizeof(counter));
  counter[8] &= 0x7f;
  counter[12] &= 0x7f;

  while (len != 0)
    {
      aes_encrypt(&ctx, counter, stream);
      chunk = len < sizeof(stream) ? len : sizeof(stream);
      for (i = 0; i < chunk; i++)
        {
          text[i] ^= stream[i];
        }

      text += chunk;
      len -= chunk;
      for (j = sizeof(counter) - 1; j >= 0; j--)
        {
          if (++counter[j] != 0)
            {
              break;
            }
        }
    }

  explicit_bzero(&ctx, sizeof(ctx));
  explicit_bzero(counter, sizeof(counter));
  explicit_bzero(stream, sizeof(stream));
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

int aes_siv_encrypt(FAR const uint8_t key[AES_SIV_KEY_SIZE],
                    FAR const uint8_t *ad, size_t adlen,
                    FAR const uint8_t *plain, size_t plainlen,
                    FAR uint8_t *sealed)
{
  uint8_t tag[AES_SIV_TAG_SIZE];

  if (key == NULL || sealed == NULL ||
      (ad == NULL && adlen != 0) || (plain == NULL && plainlen != 0))
    {
      return -EINVAL;
    }

  if (plainlen > SIZE_MAX - AES_SIV_TAG_SIZE)
    {
      return -EOVERFLOW;
    }

  siv_s2v(key, ad, adlen, plain, plainlen, tag);
  if (plainlen != 0)
    {
      memmove(sealed + AES_SIV_TAG_SIZE, plain, plainlen);
    }

  siv_ctr(key + AES_SIV_KEY_SIZE / 2, tag,
          sealed + AES_SIV_TAG_SIZE, plainlen);
  memcpy(sealed, tag, sizeof(tag));
  explicit_bzero(tag, sizeof(tag));
  return 0;
}

int aes_siv_decrypt(FAR const uint8_t key[AES_SIV_KEY_SIZE],
                    FAR const uint8_t *ad, size_t adlen,
                    FAR const uint8_t *sealed, size_t sealedlen,
                    FAR uint8_t *plain)
{
  uint8_t tag[AES_SIV_TAG_SIZE];
  uint8_t check[AES_SIV_TAG_SIZE];
  unsigned int difference = 0;
  size_t plainlen;
  size_t i;
  int ret = 0;

  if (key == NULL || sealed == NULL || sealedlen < AES_SIV_TAG_SIZE ||
      (ad == NULL && adlen != 0))
    {
      return -EINVAL;
    }

  plainlen = sealedlen - AES_SIV_TAG_SIZE;
  if (plain == NULL && plainlen != 0)
    {
      return -EINVAL;
    }

  memcpy(tag, sealed, sizeof(tag));
  if (plainlen != 0)
    {
      memmove(plain, sealed + AES_SIV_TAG_SIZE, plainlen);
    }

  siv_ctr(key + AES_SIV_KEY_SIZE / 2, tag, plain, plainlen);
  siv_s2v(key, ad, adlen, plain, plainlen, check);
  for (i = 0; i < sizeof(tag); i++)
    {
      difference |= tag[i] ^ check[i];
    }

  if (difference != 0)
    {
      if (plainlen != 0)
        {
          explicit_bzero(plain, plainlen);
        }

      ret = -EBADMSG;
    }

  explicit_bzero(tag, sizeof(tag));
  explicit_bzero(check, sizeof(check));
  return ret;
}
