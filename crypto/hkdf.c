/****************************************************************************
 * crypto/hkdf.c
 *
 * SPDX-License-Identifier: Apache-2.0
 ****************************************************************************/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <crypto/md5.h>
#include <crypto/sha1.h>
#include <crypto/sha2.h>
#include <crypto/hmac.h>
#include <nuttx/crypto/hkdf.h>

/****************************************************************************
 * Private Functions
 ****************************************************************************/

static void hkdf_update(FAR HMAC_SHA256_CTX *ctx, FAR const uint8_t *data,
                        size_t len)
{
  unsigned int chunk;

  while (len != 0)
    {
      chunk = len > UINT_MAX ? UINT_MAX : (unsigned int)len;
      hmac_sha256_update(ctx, data, chunk);
      data += chunk;
      len -= chunk;
    }
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

int hkdf_sha256(FAR const uint8_t *ikm, size_t ikmlen,
                FAR const uint8_t *salt, size_t saltlen,
                FAR const uint8_t *info, size_t infolen,
                FAR uint8_t *out, size_t outlen)
{
  HMAC_SHA256_CTX ctx;
  SHA2_CTX hash;
  uint8_t saltkey[SHA256_DIGEST_LENGTH];
  uint8_t prk[SHA256_DIGEST_LENGTH];
  uint8_t block[SHA256_DIGEST_LENGTH];
  uint8_t counter = 1;
  size_t blocklen = 0;
  size_t chunk;

  if ((ikm == NULL && ikmlen != 0) ||
      (salt == NULL && saltlen != 0) ||
      (info == NULL && infolen != 0) ||
      (out == NULL && outlen != 0) || outlen > HKDF_SHA256_MAX_OUTPUT)
    {
      return -EINVAL;
    }

  if (outlen == 0)
    {
      return 0;
    }

  memset(&ctx, 0, sizeof(ctx));
  memset(&hash, 0, sizeof(hash));
  memset(saltkey, 0, sizeof(saltkey));
  if (saltlen == 0)
    {
      salt = saltkey;
      saltlen = sizeof(saltkey);
    }
  else if (saltlen > SHA256_BLOCK_LENGTH)
    {
      /* HMAC hashes a long key first.  Do it with the size_t SHA API so
       * that hmac_sha256_init's unsigned int key length cannot truncate.
       */

      sha256init(&hash);
      sha256update(&hash, salt, saltlen);
      sha256final(saltkey, &hash);
      salt = saltkey;
      saltlen = sizeof(saltkey);
    }

  hmac_sha256_init(&ctx, salt, saltlen);
  hkdf_update(&ctx, ikm, ikmlen);
  hmac_sha256_final(prk, &ctx);

  while (outlen != 0)
    {
      memset(&ctx, 0, sizeof(ctx));
      hmac_sha256_init(&ctx, prk, sizeof(prk));
      hkdf_update(&ctx, block, blocklen);
      hkdf_update(&ctx, info, infolen);
      hmac_sha256_update(&ctx, &counter, sizeof(counter));
      hmac_sha256_final(block, &ctx);
      blocklen = sizeof(block);
      chunk = outlen < blocklen ? outlen : blocklen;
      memcpy(out, block, chunk);
      out += chunk;
      outlen -= chunk;
      counter++;
    }

  explicit_bzero(&ctx, sizeof(ctx));
  explicit_bzero(&hash, sizeof(hash));
  explicit_bzero(saltkey, sizeof(saltkey));
  explicit_bzero(prk, sizeof(prk));
  explicit_bzero(block, sizeof(block));
  return 0;
}
