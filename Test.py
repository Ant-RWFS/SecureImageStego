"""Known-answer tests (KAT) for the native crypto DLLs used by SecureImageStego.

Builds under test
-----------------
Two independent builds of the same C sources are expected:

    test/msvc_dll/   built with MSVC   (tools/build_msvc_cl.bat)
    test/gcc_dll/    built with GCC    (tools/build_gcc.bat)

Each root must contain:

    aes/dll/aes.dll    CPUID probe, AES-128 key expansion, single-block encrypt/decrypt
    aes/dll/ctr.dll    AES-128-CTR  (128-bit big-endian counter)
    aes/dll/cbc.dll    AES-128-CBC  (PKCS#7 padding)
    aes/dll/gcm.dll    AES-128-GCM  (96-bit nonce, 128-bit tag, AAD support)
    sha3/dll/sha3.dll  SHA3-256

Every available root gets its own full set of test classes, so one run reports
both toolchains next to each other (e.g. MsvcGcmTests / GccGcmTests). When two
or more roots are available, Cross*Tests additionally feed random inputs to both
builds and assert that the outputs are bit-identical.

Usage
-----
    python Test.py                       # every root that exists
    python Test.py -v                    # verbose
    python Test.py --dll-root test/msvc_dll
    python Test.py --dll-root test/msvc_dll --dll-root test/gcc_dll
    python Test.py --list-vectors        # print the reference vectors and sources

References (all vectors below are copied verbatim from these documents)
----------------------------------------------------------------------
1. FIPS 197, "Advanced Encryption Standard (AES)", 2001-11-26
   - Appendix B   AES-128 single-block encrypt/decrypt
   - Appendix C.1 AES-128 key expansion (last round key)
   https://csrc.nist.gov/pubs/fips/197/final

2. NIST SP 800-38A, "Recommendation for Block Cipher Modes of Operation", 2001-12
   - F.2.1 CBC-AES128.Encrypt (four blocks, 64 bytes)
   - F.5.1 CTR-AES128.Encrypt (128-bit big-endian counter, byte carry)
   https://csrc.nist.gov/pubs/sp/800/38/a/final

3. NIST SP 800-38D, "Recommendation for Block Cipher Modes of Operation:
   Galois/Counter Mode (GCM) and GMAC", 2007-11
   https://csrc.nist.gov/pubs/sp/800/38/d/final

4. D. McGrew, J. Viega, "The Galois/Counter Mode of Operation (GCM)",
   Appendix B, Test Case 2 / 3 / 4 (96-bit IV, including an AAD case)
   https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf

5. FIPS 202, "SHA-3 Standard: Permutation-Based Hash and Extendable-Output
   Functions", 2015-08 (SHA3-256 of "", "abc" and a 448-bit message); random
   inputs are additionally cross-checked against hashlib.sha3_256.
   https://csrc.nist.gov/pubs/fips/202/final

6. PKCS #7 v1.5 / RFC 5652 section 6.3 - the padding scheme used by the CBC
   implementation.
   https://www.rfc-editor.org/rfc/rfc5652#section-6.3
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import os
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MSVC_DLL_ROOT = ROOT / "test" / "msvc_dll"
GCC_DLL_ROOT = ROOT / "test" / "gcc_dll"

U8P = ctypes.POINTER(ctypes.c_ubyte)

# FIPS 197 Appendix B
AES_KEY_B = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
AES_PT_B = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
AES_CT_B = bytes.fromhex("3925841d02dc09fbdc118597196a0b32")

# FIPS 197 Appendix C.1 (key 000102..0f, plaintext 00112233..eeff)
AES_KEY_C1 = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
AES_PT_C1 = bytes.fromhex("00112233445566778899aabbccddeeff")
AES_CT_C1 = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
AES_RK10_C1 = bytes.fromhex("13111d7fe3944a17f307a78b4d2b30c5")

# Shared by NIST SP 800-38A F.2.1 and F.5.1
NIST_KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
NIST_PT = bytes.fromhex(
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710"
)

# NIST SP 800-38A F.2.1 CBC-AES128
CBC_IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
CBC_CT = bytes.fromhex(
    "7649abac8119b246cee98e9b12e9197d"
    "5086cb9b507219ee95db113a917678b2"
    "73bed6b8e3c1743b7116e69e22229516"
    "3ff1caa1681fac09120eca307586e1a7"
)

# NIST SP 800-38A F.5.1 CTR-AES128
CTR_IV = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
CTR_CT = bytes.fromhex(
    "874d6191b620e3261bef6864990db6ce"
    "9806f66b7970fdff8617187bb9fffdff"
    "5ae4df3edbd5d35e5b4f09020db03eab"
    "1e031dda2fbe03d1792170a0f3009cee"
)

# GCM spec Appendix B, Test Case 2
GCM2_KEY = bytes.fromhex("00000000000000000000000000000000")
GCM2_IV = bytes.fromhex("000000000000000000000000")
GCM2_PT = bytes.fromhex("00000000000000000000000000000000")
GCM2_CT = bytes.fromhex("0388dace60b6a392f328c2b971b2fe78")
GCM2_TAG = bytes.fromhex("ab6e47d42cec13bdf53a67b21257bddf")

# Test Case 3: 64-byte plaintext, no AAD
GCM3_KEY = bytes.fromhex("feffe9928665731c6d6a8f9467308308")
GCM3_IV = bytes.fromhex("cafebabefacedbaddecaf888")
GCM3_PT = bytes.fromhex(
    "d9313225f88406e5a55909c5aff5269a"
    "86a7a9531534f7da2e4c303d8a318a72"
    "1c3c0c95956809532fcf0e2449a6b525"
    "b16aedf5aa0de657ba637b391aafd255"
)
GCM3_CT = bytes.fromhex(
    "42831ec2217774244b7221b784d0d49c"
    "e3aa212f2c02a4e035c17e2329aca12e"
    "21d514b25466931c7d8f6a5aac84aa05"
    "1ba30b396a0aac973d58e091473f5985"
)
GCM3_TAG = bytes.fromhex("4d5c2af327cd64a62cf35abd2ba6fab4")

# Test Case 4: 60-byte plaintext + 20-byte AAD
GCM4_KEY = bytes.fromhex("feffe9928665731c6d6a8f9467308308")
GCM4_IV = bytes.fromhex("cafebabefacedbaddecaf888")
GCM4_AAD = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
GCM4_PT = bytes.fromhex(
    "d9313225f88406e5a55909c5aff5269a"
    "86a7a9531534f7da2e4c303d8a318a72"
    "1c3c0c95956809532fcf0e2449a6b525"
    "b16aedf5aa0de657ba637b39"
)
GCM4_CT = bytes.fromhex(
    "42831ec2217774244b7221b784d0d49c"
    "e3aa212f2c02a4e035c17e2329aca12e"
    "21d514b25466931c7d8f6a5aac84aa05"
    "1ba30b396a0aac973d58e091"
)
GCM4_TAG = bytes.fromhex("5bc94fbc3221a5db94fae95ae7121a47")

# FIPS 202 / NIST SHA-3 examples
SHA3_EMPTY = bytes.fromhex("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")
SHA3_ABC = bytes.fromhex("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532")
SHA3_448 = bytes.fromhex("41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376")
SHA3_448_MSG = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"

VECTOR_SOURCES = [
    ("FIPS 197 App. B", "AES-128 block encrypt/decrypt", "128-bit key/plaintext/ciphertext"),
    ("FIPS 197 App. C.1", "AES-128 key expansion", "w[40..43] = 13111d7f...4d2b30c5"),
    ("NIST SP 800-38A F.2.1", "AES-128-CBC encrypt", "4 blocks, 64 bytes, plus IV"),
    ("NIST SP 800-38A F.5.1", "AES-128-CTR encrypt", "128-bit counter, byte carry"),
    ("GCM spec App. B Test Case 2", "AES-128-GCM, empty AAD", "16 zero bytes"),
    ("GCM spec App. B Test Case 3", "AES-128-GCM, 64 bytes", "96-bit IV"),
    ("GCM spec App. B Test Case 4", "AES-128-GCM with AAD", "20-byte AAD, 60-byte payload"),
    ("FIPS 202", "SHA3-256", "empty / 'abc' / 448-bit message"),
    ("hashlib.sha3_256", "SHA3-256 random cross-check", "independent implementation"),
    ("RFC 5652 section 6.3", "PKCS#7 padding", "CBC pad/unpad rules"),
]



def dll_paths(root: Path) -> dict[str, Path]:
    """Map logical name -> expected DLL path for one build root."""
    return {
        "aes": Path(root) / "aes" / "dll" / "aes.dll",
        "ctr": Path(root) / "aes" / "dll" / "ctr.dll",
        "cbc": Path(root) / "aes" / "dll" / "cbc.dll",
        "gcm": Path(root) / "aes" / "dll" / "gcm.dll",
        "sha3": Path(root) / "sha3" / "dll" / "sha3.dll",
    }


def has_all_dlls(root: Path) -> bool:
    return all(path.is_file() for path in dll_paths(root).values())


def _in(data) -> "U8P | None":
    """bytes -> read-only pointer. Empty data becomes NULL (valid with length 0)."""
    if data is None:
        return None
    data = bytes(data)
    if not data:
        return None
    return ctypes.cast((ctypes.c_ubyte * len(data)).from_buffer_copy(data), U8P)


def _out(size: int):
    return (ctypes.c_ubyte * max(size, 1))()


def _take(buf, size: int) -> bytes:
    return bytes(bytearray(buf[:size]))


class NativeCrypto:
    """Load the five DLLs of one build and bind their signatures."""

    def __init__(self, root: Path):
        self.root = Path(root)
        paths = dll_paths(self.root)
        missing = [str(p) for p in paths.values() if not p.is_file()]
        if missing:
            raise FileNotFoundError(
                "missing DLLs:\n  " + "\n  ".join(missing) +
                f"\ncheck that --dll-root points at a directory containing "
                f"aes/dll and sha3/dll (got: {self.root})"
            )
        # aes.dll must be loaded first: ctr/cbc/gcm import it.
        self.aes_lib = ctypes.CDLL(str(paths["aes"]))
        self.ctr_lib = ctypes.CDLL(str(paths["ctr"]))
        self.cbc_lib = ctypes.CDLL(str(paths["cbc"]))
        self.gcm_lib = ctypes.CDLL(str(paths["gcm"]))
        self.sha3_lib = ctypes.CDLL(str(paths["sha3"]))
        self._bind()

    def _bind(self) -> None:
        self.aes_lib.cpu_has_aes_ni.restype = ctypes.c_int
        self.aes_lib.cpu_has_aes_ni.argtypes = []
        self.aes_lib.aes128_expand_key_enc.restype = None
        self.aes_lib.aes128_expand_key_enc.argtypes = [U8P, U8P]
        self.aes_lib.aes128_expand_key_dec.restype = None
        self.aes_lib.aes128_expand_key_dec.argtypes = [U8P, U8P]
        self.aes_lib.aes128_encrypt_block.restype = None
        self.aes_lib.aes128_encrypt_block.argtypes = [U8P, U8P, U8P]
        self.aes_lib.aes128_decrypt_block.restype = None
        self.aes_lib.aes128_decrypt_block.argtypes = [U8P, U8P, U8P]

        self.ctr_lib.ctr_crypt.restype = ctypes.c_int
        self.ctr_lib.ctr_crypt.argtypes = [
            U8P, U8P, U8P, ctypes.c_size_t, U8P, ctypes.POINTER(ctypes.c_size_t)
        ]

        for fn in (self.cbc_lib.cbc_encrypt, self.cbc_lib.cbc_decrypt):
            fn.restype = ctypes.c_int
            fn.argtypes = [U8P, U8P, U8P, ctypes.c_size_t, U8P,
                           ctypes.POINTER(ctypes.c_size_t)]

        self.gcm_lib.gcm_encrypt.restype = ctypes.c_int
        self.gcm_lib.gcm_encrypt.argtypes = [
            U8P, U8P, U8P, ctypes.c_size_t, U8P, ctypes.c_size_t, U8P, U8P
        ]
        self.gcm_lib.gcm_decrypt.restype = ctypes.c_int
        self.gcm_lib.gcm_decrypt.argtypes = [
            U8P, U8P, U8P, ctypes.c_size_t, U8P, ctypes.c_size_t, U8P, U8P
        ]

        self.sha3_lib.sha3_256.restype = ctypes.c_int
        self.sha3_lib.sha3_256.argtypes = [U8P, ctypes.c_size_t, U8P]

    # -- AES block layer ---------------------------------------------------
    def cpu_has_aes_ni(self) -> bool:
        return bool(self.aes_lib.cpu_has_aes_ni())

    def expand_key_enc(self, key: bytes) -> bytes:
        out = _out(176)
        self.aes_lib.aes128_expand_key_enc(_in(key), out)
        return _take(out, 176)

    def expand_key_dec(self, key: bytes) -> bytes:
        out = _out(176)
        self.aes_lib.aes128_expand_key_dec(_in(key), out)
        return _take(out, 176)

    def encrypt_block(self, round_keys: bytes, block: bytes) -> bytes:
        out = _out(16)
        self.aes_lib.aes128_encrypt_block(_in(round_keys), _in(block), out)
        return _take(out, 16)

    def decrypt_block(self, round_keys: bytes, block: bytes) -> bytes:
        out = _out(16)
        self.aes_lib.aes128_decrypt_block(_in(round_keys), _in(block), out)
        return _take(out, 16)

    # -- mode layer --------------------------------------------------------
    def ctr(self, key: bytes, iv: bytes, data: bytes):
        out = _out(len(data))
        out_len = ctypes.c_size_t(0)
        rc = self.ctr_lib.ctr_crypt(_in(key), _in(iv), _in(data), len(data),
                                    out, ctypes.byref(out_len))
        return rc, _take(out, out_len.value), out_len.value

    def cbc_encrypt(self, key: bytes, iv: bytes, pt: bytes):
        out = _out(len(pt) + 16)
        out_len = ctypes.c_size_t(0)
        rc = self.cbc_lib.cbc_encrypt(_in(key), _in(iv), _in(pt), len(pt), out,
                                      ctypes.byref(out_len))
        return rc, _take(out, out_len.value)

    def cbc_decrypt(self, key: bytes, iv: bytes, ct: bytes):
        out = _out(len(ct))
        out_len = ctypes.c_size_t(0)
        rc = self.cbc_lib.cbc_decrypt(_in(key), _in(iv), _in(ct), len(ct), out,
                                      ctypes.byref(out_len))
        return rc, _take(out, out_len.value)

    def gcm_encrypt(self, key: bytes, nonce: bytes, pt: bytes, aad: bytes = b""):
        ct = _out(len(pt))
        tag = _out(16)
        rc = self.gcm_lib.gcm_encrypt(_in(key), _in(nonce), _in(aad), len(aad),
                                      _in(pt), len(pt), ct, tag)
        return rc, _take(ct, len(pt)), _take(tag, 16)

    def gcm_decrypt(self, key: bytes, nonce: bytes, ct: bytes, tag: bytes,
                    aad: bytes = b""):
        pt = _out(len(ct))
        rc = self.gcm_lib.gcm_decrypt(_in(key), _in(nonce), _in(aad), len(aad),
                                      _in(ct), len(ct), _in(tag), pt)
        return rc, _take(pt, len(ct))

    def sha3_256(self, data: bytes) -> bytes:
        out = _out(32)
        rc = self.sha3_lib.sha3_256(_in(data), len(data), out)
        if rc != 0:
            raise RuntimeError(f"sha3_256 returned {rc}")
        return _take(out, 32)


_NATIVE_CACHE: dict[Path, NativeCrypto] = {}


def native_for(root: Path) -> NativeCrypto:
    root = Path(root)
    if root not in _NATIVE_CACHE:
        _NATIVE_CACHE[root] = NativeCrypto(root)
    return _NATIVE_CACHE[root]


class DllTestCase(unittest.TestCase):
    """Base class: loads the DLLs of `dll_root` once per class."""

    dll_root: Path = None

    @classmethod
    def setUpClass(cls):
        cls.native = native_for(cls.dll_root)
        if not cls.native.cpu_has_aes_ni():
            raise unittest.SkipTest("CPU does not support AES-NI")


def _hex(data: bytes) -> str:
    return data.hex()


class AesBlockTests:
    """AES-128 single block and key expansion (FIPS 197)."""

    def test_fips197_appendix_b_encrypt(self):
        """FIPS 197 App. B: key 2b7e.., plaintext 3243.., ciphertext 3925.."""
        rk = self.native.expand_key_enc(AES_KEY_B)
        self.assertEqual(_hex(self.native.encrypt_block(rk, AES_PT_B)), _hex(AES_CT_B))

    def test_fips197_appendix_b_decrypt(self):
        rk = self.native.expand_key_dec(AES_KEY_B)
        self.assertEqual(_hex(self.native.decrypt_block(rk, AES_CT_B)), _hex(AES_PT_B))

    def test_fips197_appendix_c1_encrypt(self):
        rk = self.native.expand_key_enc(AES_KEY_C1)
        self.assertEqual(_hex(self.native.encrypt_block(rk, AES_PT_C1)), _hex(AES_CT_C1))

    def test_fips197_appendix_c1_key_expansion(self):
        """FIPS 197 App. C.1: last round key w[40..43]."""
        rk = self.native.expand_key_enc(AES_KEY_C1)
        self.assertEqual(_hex(rk[160:176]), _hex(AES_RK10_C1))

    def test_encrypt_decrypt_roundtrip(self):
        """Deterministic keys/blocks: decrypt(encrypt(x)) == x."""
        for seed in range(8):
            key = hashlib.sha256(bytes([seed])).digest()[:16]
            block = hashlib.md5(bytes([seed])).digest()
            rk_e = self.native.expand_key_enc(key)
            rk_d = self.native.expand_key_dec(key)
            ct = self.native.encrypt_block(rk_e, block)
            self.assertEqual(self.native.decrypt_block(rk_d, ct), block, f"seed={seed}")


class CtrTests:
    """AES-128-CTR (NIST SP 800-38A F.5.1)."""

    def test_nist_sp800_38a_f51(self):
        """Four blocks, 128-bit big-endian counter with byte carry."""
        rc, ct, out_len = self.native.ctr(NIST_KEY, CTR_IV, NIST_PT)
        self.assertEqual(rc, 0)
        self.assertEqual(out_len, len(NIST_PT))
        self.assertEqual(_hex(ct), _hex(CTR_CT))

    def test_ctr_is_involutive(self):
        """CTR uses the same operation for encrypt and decrypt."""
        rc1, ct, _ = self.native.ctr(NIST_KEY, CTR_IV, NIST_PT)
        rc2, back, _ = self.native.ctr(NIST_KEY, CTR_IV, ct)
        self.assertEqual((rc1, rc2), (0, 0))
        self.assertEqual(back, NIST_PT)

    def test_partial_block(self):
        """Unaligned lengths must produce exact-length output matching the vector."""
        for length in (1, 5, 15, 17, 31):
            rc, ct, out_len = self.native.ctr(NIST_KEY, CTR_IV, NIST_PT[:length])
            self.assertEqual(rc, 0)
            self.assertEqual(out_len, length)
            self.assertEqual(_hex(ct), _hex(CTR_CT[:length]), f"length={length}")

    def test_empty_input(self):
        rc, ct, out_len = self.native.ctr(NIST_KEY, CTR_IV, b"")
        self.assertEqual((rc, ct, out_len), (0, b"", 0))


class CbcTests:
    """AES-128-CBC with PKCS#7 padding (NIST SP 800-38A F.2.1)."""

    def test_nist_sp800_38a_f21_first_blocks(self):
        """The first four ciphertext blocks must match the vector; block 5 is padding."""
        rc, ct = self.native.cbc_encrypt(NIST_KEY, CBC_IV, NIST_PT)
        self.assertEqual(rc, 0)
        self.assertEqual(len(ct), len(NIST_PT) + 16)
        self.assertEqual(_hex(ct[:64]), _hex(CBC_CT))

    def test_pkcs7_padding_block(self):
        """Block 5 must be E_k(0x10 * 16 XOR C[3])."""
        _, ct = self.native.cbc_encrypt(NIST_KEY, CBC_IV, NIST_PT)
        pad_plain = bytes([16]) * 16
        xor_block = bytes(a ^ b for a, b in zip(pad_plain, ct[48:64]))
        rk = self.native.expand_key_enc(NIST_KEY)
        expected = self.native.encrypt_block(rk, xor_block)
        self.assertEqual(_hex(ct[64:80]), _hex(expected))

    def test_decrypt_roundtrip_and_strip(self):
        """Encrypt then decrypt must return the original and strip the padding."""
        for length in (0, 1, 15, 16, 17, 63, 64, 100):
            pt = (NIST_PT * 4)[:length]
            rc_e, ct = self.native.cbc_encrypt(NIST_KEY, CBC_IV, pt)
            rc_d, back = self.native.cbc_decrypt(NIST_KEY, CBC_IV, ct)
            self.assertEqual((rc_e, rc_d), (0, 0), f"length={length}")
            self.assertEqual(back, pt, f"length={length}")

    def test_decrypt_rejects_unaligned_ciphertext(self):
        """A length that is not a multiple of 16 must be rejected."""
        rc, _ = self.native.cbc_decrypt(NIST_KEY, CBC_IV, CBC_CT[:15])
        self.assertNotEqual(rc, 0)

    def test_decrypt_rejects_out_of_range_padding(self):
        """A trailing byte greater than 16 must be rejected."""
        rk = self.native.expand_key_enc(NIST_KEY)
        bad_plain = bytes([0x00] * 15 + [0x11])  # padding length 17: invalid
        prev = bytes(16)
        xor_block = bytes(a ^ b for a, b in zip(bad_plain, prev))
        ct = self.native.encrypt_block(rk, xor_block)
        rc, _ = self.native.cbc_decrypt(NIST_KEY, prev, ct)
        self.assertNotEqual(rc, 0)

    def test_pkcs7_padding_accepts_valid_rejects_tampered(self):
        """PKCS#7 regression test (RFC 5652 section 6.3)"""
        rk = self.native.expand_key_enc(NIST_KEY)
        prev = bytes(16)

        for pad_len in range(1, 17):
            good = bytes(16 - pad_len) + bytes([pad_len]) * pad_len
            ct = self.native.encrypt_block(rk, bytes(a ^ b for a, b in zip(good, prev)))

            rc, pt = self.native.cbc_decrypt(NIST_KEY, prev, ct)
            self.assertEqual(rc, 0, f"valid padding rejected (pad_len={pad_len})")
            self.assertEqual(pt, good[:-pad_len], f"wrong strip length (pad_len={pad_len})")

            if pad_len == 1:
                continue  # no interior padding bytes to corrupt

            bad = bytearray(good)
            bad[-pad_len] ^= 0x01  # corrupt first padding byte, keep the last one
            ct_bad = self.native.encrypt_block(
                rk, bytes(a ^ b for a, b in zip(bad, prev))
            )
            rc_bad, _ = self.native.cbc_decrypt(NIST_KEY, prev, ct_bad)
            self.assertNotEqual(rc_bad, 0, f"tampered padding accepted (pad_len={pad_len})")


class GcmTests:
    """AES-128-GCM (SP 800-38D / GCM spec Appendix B)."""

    def test_case2_empty_aad(self):
        rc, ct, tag = self.native.gcm_encrypt(GCM2_KEY, GCM2_IV, GCM2_PT)
        self.assertEqual(rc, 0)
        self.assertEqual(_hex(ct), _hex(GCM2_CT))
        self.assertEqual(_hex(tag), _hex(GCM2_TAG))

    def test_case3_64_bytes(self):
        rc, ct, tag = self.native.gcm_encrypt(GCM3_KEY, GCM3_IV, GCM3_PT)
        self.assertEqual(rc, 0)
        self.assertEqual(_hex(ct), _hex(GCM3_CT))
        self.assertEqual(_hex(tag), _hex(GCM3_TAG))

    def test_case4_with_aad(self):
        rc, ct, tag = self.native.gcm_encrypt(GCM4_KEY, GCM4_IV, GCM4_PT, GCM4_AAD)
        self.assertEqual(rc, 0)
        self.assertEqual(_hex(ct), _hex(GCM4_CT))
        self.assertEqual(_hex(tag), _hex(GCM4_TAG))

    def test_decrypt_kat(self):
        """Decrypting the standard vector must return the plaintext."""
        rc, pt = self.native.gcm_decrypt(GCM4_KEY, GCM4_IV, GCM4_CT, GCM4_TAG, GCM4_AAD)
        self.assertEqual(rc, 0)
        self.assertEqual(pt, GCM4_PT)

    def test_tag_tamper_rejected(self):
        bad = bytearray(GCM4_TAG)
        bad[0] ^= 0x01
        rc, _ = self.native.gcm_decrypt(GCM4_KEY, GCM4_IV, GCM4_CT, bytes(bad), GCM4_AAD)
        self.assertNotEqual(rc, 0)

    def test_ciphertext_tamper_rejected(self):
        bad = bytearray(GCM4_CT)
        bad[-1] ^= 0x80
        rc, _ = self.native.gcm_decrypt(GCM4_KEY, GCM4_IV, bytes(bad), GCM4_TAG, GCM4_AAD)
        self.assertNotEqual(rc, 0)

    def test_aad_is_authenticated(self):
        """A different AAD must fail authentication."""
        rc, _ = self.native.gcm_decrypt(GCM4_KEY, GCM4_IV, GCM4_CT, GCM4_TAG,
                                        b"\x00" * len(GCM4_AAD))
        self.assertNotEqual(rc, 0)

    def test_empty_plaintext_tag(self):
        """With empty plaintext and AAD the tag must equal E_k(J0)."""
        key, nonce = GCM3_KEY, GCM3_IV
        rc, ct, tag = self.native.gcm_encrypt(key, nonce, b"")
        self.assertEqual((rc, ct), (0, b""))
        rk = self.native.expand_key_enc(key)
        j0 = nonce + b"\x00\x00\x00\x01"
        self.assertEqual(_hex(tag), _hex(self.native.encrypt_block(rk, j0)))

    def test_roundtrip_random_sizes(self):
        for length in (0, 1, 15, 16, 17, 64, 129):
            pt = hashlib.shake_128(str(length).encode()).digest(length)
            rc_e, ct, tag = self.native.gcm_encrypt(GCM3_KEY, GCM3_IV, pt)
            rc_d, back = self.native.gcm_decrypt(GCM3_KEY, GCM3_IV, ct, tag)
            self.assertEqual((rc_e, rc_d), (0, 0), f"length={length}")
            self.assertEqual(back, pt, f"length={length}")


class Sha3Tests:
    """SHA3-256 (FIPS 202)."""

    def test_empty(self):
        self.assertEqual(_hex(self.native.sha3_256(b"")), _hex(SHA3_EMPTY))

    def test_abc(self):
        self.assertEqual(_hex(self.native.sha3_256(b"abc")), _hex(SHA3_ABC))

    def test_448bit_message(self):
        self.assertEqual(_hex(self.native.sha3_256(SHA3_448_MSG)), _hex(SHA3_448))

    def test_against_hashlib(self):
        """Cross-check against CPython's hashlib (OpenSSL) over many lengths."""
        if not hasattr(hashlib, "sha3_256"):
            self.skipTest("hashlib has no sha3_256")
        rng = hashlib.sha512(b"seed").digest()
        cases = [b"", b"\x00", b"a" * 135, b"a" * 136, b"a" * 137, rng * 8]
        for i in range(1, 65):
            cases.append(bytes(range(i % 256)) * (i % 7 + 1))
        for data in cases:
            self.assertEqual(self.native.sha3_256(data),
                             hashlib.sha3_256(data).digest(),
                             f"len={len(data)}")

    def test_large_input(self):
        if not hasattr(hashlib, "sha3_256"):
            self.skipTest("hashlib has no sha3_256")
        data = b"a" * 1_000_000
        self.assertEqual(self.native.sha3_256(data), hashlib.sha3_256(data).digest())


class InterfaceTests:
    """Interface level: CPU flag, PE architecture, DLL layout."""

    def test_cpu_flag(self):
        self.assertTrue(self.native.cpu_has_aes_ni(), "cpu_has_aes_ni() returned 0")

    def test_dlls_are_x64(self):
        """Every DLL must be a 64-bit PE, matching the interpreter."""
        import struct
        self.assertEqual(struct.calcsize("P"), 8, "interpreter is not 64-bit")
        for name, path in dll_paths(self.dll_root).items():
            with open(path, "rb") as fh:
                head = fh.read(0x40)
            self.assertEqual(head[:2], b"MZ", f"{name} is not a PE file")
            with open(path, "rb") as fh:
                fh.seek(0x3C)
                pe = int.from_bytes(fh.read(4), "little")
                fh.seek(pe + 4)
                machine = int.from_bytes(fh.read(2), "little")
            self.assertEqual(machine, 0x8664, f"{name} is not x86-64 (machine=0x{machine:04X})")


class FingerprintTests:
    """Record the build fingerprint so the two toolchains can be told apart."""

    def test_print_fingerprints(self):
        print(f"\n    build root: {self.dll_root}")
        for name, path in dll_paths(self.dll_root).items():
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            size = path.stat().st_size
            print(f"    {name:5s} {size:>7d} B  sha256={digest}")


class CrossBuildMixin:
    """Feed identical inputs to two builds and require identical outputs."""

    _left_root: Path = None
    _right_root: Path = None

    @classmethod
    def setUpClass(cls):
        cls.left = native_for(cls._left_root)
        cls.right = native_for(cls._right_root)
        if not (cls.left.cpu_has_aes_ni() and cls.right.cpu_has_aes_ni()):
            raise unittest.SkipTest("CPU does not support AES-NI")

    def test_aes_block_matches(self):
        for seed in range(16):
            key = hashlib.sha256(b"key" + bytes([seed])).digest()[:16]
            block = hashlib.md5(b"blk" + bytes([seed])).digest()
            self.assertEqual(
                self.left.encrypt_block(self.left.expand_key_enc(key), block),
                self.right.encrypt_block(self.right.expand_key_enc(key), block),
                f"seed={seed}",
            )

    def test_ctr_matches(self):
        for length in (0, 1, 15, 16, 17, 64, 100):
            data = hashlib.shake_128(f"ctr{length}".encode()).digest(length)
            self.assertEqual(
                self.left.ctr(NIST_KEY, CTR_IV, data),
                self.right.ctr(NIST_KEY, CTR_IV, data),
                f"length={length}",
            )

    def test_cbc_matches(self):
        for length in (0, 1, 16, 17, 64, 100):
            data = hashlib.shake_128(f"cbc{length}".encode()).digest(length)
            self.assertEqual(
                self.left.cbc_encrypt(NIST_KEY, CBC_IV, data),
                self.right.cbc_encrypt(NIST_KEY, CBC_IV, data),
                f"length={length}",
            )

    def test_gcm_matches(self):
        for length in (0, 1, 16, 17, 60, 129):
            data = hashlib.shake_128(f"gcm{length}".encode()).digest(length)
            aad = hashlib.shake_128(f"aad{length}".encode()).digest(length % 23)
            self.assertEqual(
                self.left.gcm_encrypt(GCM3_KEY, GCM3_IV, data, aad),
                self.right.gcm_encrypt(GCM3_KEY, GCM3_IV, data, aad),
                f"length={length}",
            )

    def test_sha3_matches(self):
        for length in (0, 1, 135, 136, 137, 1024, 65536):
            data = hashlib.shake_128(f"sha3{length}".encode()).digest(length)
            self.assertEqual(self.left.sha3_256(data), self.right.sha3_256(data),
                             f"length={length}")


_MIXINS = (
    ("AesBlockTests", AesBlockTests),
    ("CtrTests", CtrTests),
    ("CbcTests", CbcTests),
    ("GcmTests", GcmTests),
    ("Sha3Tests", Sha3Tests),
    ("InterfaceTests", InterfaceTests),
    ("FingerprintTests", FingerprintTests),
)

_LABEL_ALIASES = {"msvc_dll": "Msvc", "gcc_dll": "Gcc"}

_installed_names: list[str] = []


def build_label(root: Path) -> str:
    """Turn a directory name into a valid class-name prefix."""
    if root.name in _LABEL_ALIASES:
        return _LABEL_ALIASES[root.name]
    parts = re.split(r"[^0-9A-Za-z]+", root.name)
    return "".join(p.capitalize() for p in parts if p) or "Dll"


def _clear_installed() -> None:
    for name in _installed_names:
        globals().pop(name, None)
    _installed_names.clear()


def install_test_cases(roots) -> None:
    """Create one concrete TestCase per (build root, mixin) pair."""
    _clear_installed()
    for label, root in roots:
        for mixin_name, mixin in _MIXINS:
            class_name = f"{label}{mixin_name}"
            globals()[class_name] = type(
                class_name,
                (DllTestCase, mixin),
                {
                    "dll_root": root,
                    "__module__": __name__,
                    "__doc__": f"[{label}] {mixin.__doc__ or ''}".strip(),
                },
            )
            _installed_names.append(class_name)

    for (label_a, root_a), (label_b, root_b) in zip(roots, roots[1:]):
        class_name = f"Cross{label_a}{label_b}Tests"
        globals()[class_name] = type(
            class_name,
            (CrossBuildMixin, unittest.TestCase),
            {
                "_left_root": root_a,
                "_right_root": root_b,
                "__module__": __name__,
                "__doc__": f"Cross-build comparison {label_a} vs {label_b}",
            },
        )
        _installed_names.append(class_name)


def default_roots():
    """Roots used when no --dll-root is given: every existing test/*_dll dir."""
    candidates = [MSVC_DLL_ROOT, GCC_DLL_ROOT]
    extra = sorted(
        p for p in (ROOT / "test").glob("*_dll")
        if p.is_dir() and p not in candidates
    ) if (ROOT / "test").is_dir() else []
    return [(build_label(p), p) for p in candidates + extra if has_all_dlls(p)]

install_test_cases(default_roots())


def print_vectors() -> None:
    print("Reference vectors and their sources:\n")
    print(f"  {'source':32s} {'purpose':32s} detail")
    print(f"  {'-' * 32} {'-' * 32} {'-' * 40}")
    for source, purpose, detail in VECTOR_SOURCES:
        print(f"  {source:32s} {purpose:32s} {detail}")
    print("\nDocuments:")
    for line in (
        "  FIPS 197     https://csrc.nist.gov/pubs/fips/197/final",
        "  SP 800-38A   https://csrc.nist.gov/pubs/sp/800/38/a/final",
        "  SP 800-38D   https://csrc.nist.gov/pubs/sp/800/38/d/final",
        "  GCM spec     https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf",
        "  FIPS 202     https://csrc.nist.gov/pubs/fips/202/final",
        "  RFC 5652     https://www.rfc-editor.org/rfc/rfc5652#section-6.3",
    ):
        print(line)


def _resolve_roots(raw_roots):
    roots = []
    for raw in raw_roots:
        path = Path(raw).expanduser().resolve()
        if has_all_dlls(path):
            roots.append((build_label(path), path))
        else:
            print(f"[skip] {path}: one or more DLLs are missing", file=sys.stderr)
    return roots


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    parser = argparse.ArgumentParser(
        description="Known-answer tests for the SecureImageStego native crypto DLLs",
        epilog="examples: python Test.py -v  |  "
               "python Test.py --dll-root test/msvc_dll --dll-root test/gcc_dll",
    )
    parser.add_argument(
        "--dll-root", action="append", default=None,
        help="directory containing aes/dll and sha3/dll; repeatable "
             "(default: every test/*_dll that exists)",
    )
    parser.add_argument(
        "--list-vectors", action="store_true",
        help="print the reference vectors and their sources, then exit",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose output")
    args, rest = parser.parse_known_args(argv)

    if args.list_vectors:
        print_vectors()
        return 0

    if args.dll_root:
        raw_roots = args.dll_root
    elif os.environ.get("STEGO_DLL_ROOT"):
        raw_roots = os.environ["STEGO_DLL_ROOT"].split(os.pathsep)
    else:
        raw_roots = None

    if raw_roots is None:
        roots = default_roots()
    else:
        roots = _resolve_roots(raw_roots)

    if not roots:
        print("[error] no usable DLL root found; build one with "
              "tools\\build_msvc_cl.bat or tools\\build_gcc.bat", file=sys.stderr)
        return 2

    for label, root in roots:
        print(f"[build] {label:6s} {root}")
    install_test_cases(roots)

    unittest.main(argv=[sys.argv[0]] + (["-v"] if args.verbose else []) + rest)
    return 0


if __name__ == "__main__":
    sys.exit(main())
