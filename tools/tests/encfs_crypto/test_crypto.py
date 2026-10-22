#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compile the actual NuttX crypto sources and check RFC/negative vectors.

Only the host compiler and Python standard library are required.  OpenSSL 3,
if available, additionally supplies an independent AES-SIV implementation.
No copied or substitute implementation of AES, CMAC, SHA or HKDF is tested.
"""

import ctypes as C
import ctypes.util
import errno
import hashlib
import hmac
import os
from pathlib import Path
import random
import subprocess
import tempfile


NUTTX = Path(__file__).resolve().parents[3]
BYTE = C.c_ubyte
PTR = C.c_void_p
SIZE = C.c_size_t
CHECKS = 0
SANITIZERS = os.environ.get("ENCFS_CRYPTO_SANITIZERS", "undefined")


def check(value, description):
    global CHECKS
    CHECKS += 1
    if not value:
        raise AssertionError(description)


def buf(value):
    return C.create_string_buffer(value, max(1, len(value)))


def compile_library(directory):
    inc = directory / "include"
    (inc / "nuttx").mkdir(parents=True)
    (inc / "nuttx" / "config.h").write_text("#define CONFIG_CRYPTO 1\n")
    (inc / "nuttx" / "compiler.h").write_text("#define FAR\n")
    (inc / "nuttx" / "crypto").symlink_to(NUTTX / "include/nuttx/crypto")
    (inc / "crypto").symlink_to(NUTTX / "include/crypto")
    prelude = directory / "host.h"
    prelude.write_text("#include <stdint.h>\n#define FAR\n"
                       "#define swap32 __builtin_bswap32\n"
                       "#define swap64 __builtin_bswap64\n")
    sources = ["aes_siv", "hkdf", "aes", "cmac", "hmac", "sha2",
               "sha1", "md5"]
    output = directory / "crypto.so"
    subprocess.run([
        os.environ.get("CC", "cc"), "-std=gnu11", "-O2", "-g", "-fPIC",
        "-shared", "-Wall", "-Wextra", "-Werror", "-Wno-old-style-declaration",
        "-fsanitize=" + SANITIZERS,
        "-fno-sanitize-recover=all", "-include", str(prelude),
        "-I", str(inc), "-o", str(output),
        *[str(NUTTX / "crypto" / (name + ".c")) for name in sources],
    ], check=True)
    lib = C.CDLL(str(output))
    lib.aes_siv_encrypt.argtypes = [PTR, PTR, SIZE, PTR, SIZE, PTR]
    lib.aes_siv_encrypt.restype = C.c_int
    lib.aes_siv_decrypt.argtypes = [PTR, PTR, SIZE, PTR, SIZE, PTR]
    lib.aes_siv_decrypt.restype = C.c_int
    lib.hkdf_sha256.argtypes = [PTR, SIZE, PTR, SIZE, PTR, SIZE, PTR, SIZE]
    lib.hkdf_sha256.restype = C.c_int
    return lib


def seal(lib, key, ad, plain):
    output = C.create_string_buffer(len(plain) + 16)
    check(lib.aes_siv_encrypt(buf(key), buf(ad), len(ad), buf(plain),
                              len(plain), output) == 0, "encrypt success")
    return output.raw


def unseal(lib, key, ad, sealed, expected=0):
    n = len(sealed) - 16
    output = C.create_string_buffer(b"\xa5" * max(n, 1), max(n, 1))
    result = lib.aes_siv_decrypt(buf(key), buf(ad), len(ad), buf(sealed),
                                 len(sealed), output)
    check(result == expected, "decrypt return code")
    if expected:
        check(output.raw[:n] == b"\0" * n, "authentication failure wipes output")
    return output.raw[:n]


def derive(lib, ikm, salt, info, length):
    output = C.create_string_buffer(max(1, length))
    check(lib.hkdf_sha256(buf(ikm), len(ikm), buf(salt), len(salt),
                           buf(info), len(info), output, length) == 0,
          "HKDF return code")
    return output.raw[:length]


def reference_hkdf(ikm, salt, info, length):
    prk = hmac.digest(salt or bytes(32), ikm, hashlib.sha256)
    output, block = b"", b""
    for i in range(1, (length + 31) // 32 + 1):
        block = hmac.digest(prk, block + info + bytes([i]), hashlib.sha256)
        output += block
    return output[:length]


class OpenSSLSIV:
    """The system OpenSSL 3 provider, independent of the tested C sources."""

    def __init__(self):
        self.lib = C.CDLL(ctypes.util.find_library("crypto"))
        for name, args, result in [
            ("EVP_CIPHER_fetch", [PTR, C.c_char_p, C.c_char_p], PTR),
            ("EVP_CIPHER_free", [PTR], None),
            ("EVP_CIPHER_CTX_new", [], PTR),
            ("EVP_CIPHER_CTX_free", [PTR], None),
            ("EVP_EncryptInit_ex2", [PTR, PTR, PTR, PTR, PTR], C.c_int),
            ("EVP_EncryptUpdate", [PTR, PTR, C.POINTER(C.c_int), PTR, C.c_int],
             C.c_int),
            ("EVP_EncryptFinal_ex", [PTR, PTR, C.POINTER(C.c_int)], C.c_int),
            ("EVP_CIPHER_CTX_ctrl", [PTR, C.c_int, C.c_int, PTR], C.c_int),
        ]:
            func = getattr(self.lib, name)
            func.argtypes, func.restype = args, result
        self.cipher = self.lib.EVP_CIPHER_fetch(None, b"AES-128-SIV", None)
        if not self.cipher:
            raise RuntimeError("OpenSSL AES-128-SIV unavailable")

    def seal(self, key, ads, plain):
        ctx = self.lib.EVP_CIPHER_CTX_new()
        output = C.create_string_buffer(len(plain) + 16)
        tag = C.create_string_buffer(16)
        count = C.c_int()
        try:
            check(self.lib.EVP_EncryptInit_ex2(ctx, self.cipher, buf(key),
                                              None, None) == 1,
                  "OpenSSL SIV init")
            for ad in ads:
                check(self.lib.EVP_EncryptUpdate(ctx, None, C.byref(count),
                                                 buf(ad), len(ad)) == 1,
                      "OpenSSL AD update")
            check(self.lib.EVP_EncryptUpdate(ctx, output, C.byref(count),
                                             buf(plain), len(plain)) == 1,
                  "OpenSSL encrypt")
            size = count.value
            check(self.lib.EVP_EncryptFinal_ex(ctx, C.byref(output, size),
                                               C.byref(count)) == 1,
                  "OpenSSL encrypt final")
            check(self.lib.EVP_CIPHER_CTX_ctrl(ctx, 0x10, 16, tag) == 1,
                  "OpenSSL get tag")
            return tag.raw + output.raw[:size + count.value]
        finally:
            self.lib.EVP_CIPHER_CTX_free(ctx)

    def close(self):
        self.lib.EVP_CIPHER_free(self.cipher)


def test_rfc5297(lib, reference):
    key = bytes.fromhex("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0"
                        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    ad = bytes.fromhex("101112131415161718191a1b1c1d1e1f2021222324252627")
    plain = bytes.fromhex("112233445566778899aabbccddee")
    expected = bytes.fromhex("85632d07c6e8f37f950acd320a2ecc93"
                             "40c02b9690c4dc04daef7f6afe5c")
    check(seal(lib, key, ad, plain) == expected, "RFC 5297 A.1")
    check(unseal(lib, key, ad, expected) == plain, "RFC 5297 A.1 decrypt")
    if reference:
        check(reference.seal(key, [ad], plain) == expected,
              "RFC 5297 A.1 independent OpenSSL reference")
    print("PASS RFC 5297 A.1 encryption/decryption")


def test_rfc5869(lib):
    cases = [
        (bytes([11]) * 22, bytes(range(13)), bytes(range(240, 250)), 42,
         "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
         "34007208d5b887185865"),
        (bytes(range(80)), bytes(range(96, 176)), bytes(range(176, 256)), 82,
         "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
         "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
         "cc30c58179ec3e87c14c01d5c1f3434f1d87"),
        (bytes([11]) * 22, b"", b"", 42,
         "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
         "9d201395faa4b61a96c8"),
    ]
    for i, (ikm, salt, info, size, expected) in enumerate(cases, 1):
        check(derive(lib, ikm, salt, info, size) == bytes.fromhex(expected),
              "RFC 5869 A.%d" % i)
    for length in [0, 1, 31, 32, 33, 64, 65, 8160]:
        ikm, salt, info = bytes(range(255)), bytes(range(100)), b"encpathfs"
        check(derive(lib, ikm, salt, info, length) ==
              reference_hkdf(ikm, salt, info, length), "HKDF output boundary")
    check(derive(lib, b"", b"", b"", 32) ==
          reference_hkdf(b"", b"", b"", 32), "empty HKDF input")
    print("PASS RFC 5869 A.1/A.2/A.3 and HKDF 0..8160 byte boundaries")


def test_boundaries(lib, reference):
    rng = random.Random(52975869)
    lengths = list(range(66)) + [127, 128, 129, 140, 255, 256, 257, 1024, 4097]
    for length in lengths:
        key = rng.randbytes(32)
        for adlen in [0, 1, 15, 16, 17, 31, 32, 33, 100]:
            ad, plain = rng.randbytes(adlen), rng.randbytes(length)
            sealed = seal(lib, key, ad, plain)
            check(seal(lib, key, ad, plain) == sealed, "deterministic SIV")
            check(unseal(lib, key, ad, sealed) == plain, "SIV round trip")
            # OpenSSL's SIV provider rejects an empty plaintext.  The local
            # empty-message behavior is covered by a fixed reference below.
            if reference and plain:
                check(reference.seal(key, [ad], plain) == sealed,
                      "independent OpenSSL SIV differential")
            for pos in [0, 15, len(sealed) - 1]:
                modified = bytearray(sealed)
                modified[pos] ^= 1
                unseal(lib, key, ad, bytes(modified), -errno.EBADMSG)
            wrongkey = bytes([key[0] ^ 1]) + key[1:]
            unseal(lib, wrongkey, ad, sealed, -errno.EBADMSG)
            unseal(lib, key, ad + b"!", sealed, -errno.EBADMSG)
            overlap = C.create_string_buffer(max(length + 32, 64))
            C.memmove(overlap, plain, length)
            check(lib.aes_siv_encrypt(buf(key), buf(ad), adlen, overlap,
                                      length, overlap) == 0, "overlap encrypt")
            check(overlap.raw[:length + 16] == sealed, "overlap ciphertext")
            check(lib.aes_siv_decrypt(buf(key), buf(ad), adlen, overlap,
                                      length + 16, overlap) == 0,
                  "overlap decrypt")
            check(overlap.raw[:length] == plain, "overlap plaintext")
    # Empty plaintext, one empty AD; generated independently using the
    # RFC S2V equations with the cryptography/OpenSSL CMAC implementation.
    check(seal(lib, bytes(range(32)), b"", b"") ==
          bytes.fromhex("646a1c3efeb7d2589bfdd0892cc86923"), "empty SIV vector")
    print("PASS 675 SIV boundary cases, OpenSSL differential, tamper/wrong-key/AD,")
    print("     deterministic output, zeroization, and overlapping buffers")


def test_arguments(lib):
    key = buf(bytes(32))
    storage = C.create_string_buffer(64)
    enc, dec, hkdf = lib.aes_siv_encrypt, lib.aes_siv_decrypt, lib.hkdf_sha256
    check(enc(None, None, 0, None, 0, storage) == -errno.EINVAL, "NULL key")
    check(enc(key, None, 1, None, 0, storage) == -errno.EINVAL, "NULL AD")
    check(enc(key, None, 0, None, 1, storage) == -errno.EINVAL, "NULL plaintext")
    check(enc(key, None, 0, None, 0, None) == -errno.EINVAL, "NULL sealed")
    check(enc(key, None, 0, storage, SIZE(-1).value, storage) ==
          -errno.EOVERFLOW, "encrypt length overflow")
    for length in range(16):
        check(dec(key, None, 0, storage, length, storage) == -errno.EINVAL,
              "short ciphertext")
    check(dec(key, None, 0, storage, 17, None) == -errno.EINVAL, "NULL output")
    check(dec(key, None, 1, storage, 16, None) == -errno.EINVAL, "NULL AD")
    check(dec(key, None, 0, None, 16, None) == -errno.EINVAL, "NULL sealed")
    check(enc(key, None, 0, None, 0, storage) == 0, "empty NULL plaintext")
    check(dec(key, None, 0, storage, 16, None) == 0, "empty NULL output")
    check(hkdf(None, 0, None, 0, None, 0, None, 0) == 0, "empty HKDF")
    for args in [(None, 1, None, 0, None, 0, storage, 32),
                 (None, 0, None, 1, None, 0, storage, 32),
                 (None, 0, None, 0, None, 1, storage, 32),
                 (None, 0, None, 0, None, 0, None, 32),
                 (None, 0, None, 0, None, 0, storage, 8161)]:
        check(hkdf(*args) == -errno.EINVAL, "invalid HKDF argument")
    print("PASS invalid pointers, short ciphertext, overflow, and NULL empty inputs")


def main():
    with tempfile.TemporaryDirectory(prefix="encfs-crypto-") as directory:
        lib = compile_library(Path(directory))
        try:
            reference = OpenSSLSIV()
        except (AttributeError, OSError, RuntimeError) as error:
            print("SKIP OpenSSL differential:", error)
            reference = None
        try:
            test_rfc5297(lib, reference)
            test_rfc5869(lib)
            test_boundaries(lib, reference)
            test_arguments(lib)
        finally:
            if reference:
                reference.close()
    print("PASS all %d assertions (production sources, sanitizers: %s)" %
          (CHECKS, SANITIZERS))


if __name__ == "__main__":
    main()
