import ctypes
import os
from src.Proccess.FileManagement import Paths


class AES_CBC:
    KEY_LEN = 16
    IV_LEN = 16
    BLOCK_SIZE = 16

    aes_lib = None
    cbc_lib = None

    @classmethod
    def load_lib(cls):
        if cls.cbc_lib is not None:
            return cls.cbc_lib

        aes_dll = Paths.crypto_dll('aes', 'aes')
        cbc_dll = Paths.crypto_dll('aes', 'cbc')

        if aes_dll is None:
            return
        if cbc_dll is None:
            return

        aes_lib = ctypes.CDLL(str(aes_dll))
        aes_lib.cpu_has_aes_ni.restype = ctypes.c_int
        aes_lib.cpu_has_aes_ni.argtypes = []
        if not aes_lib.cpu_has_aes_ni():
            raise RuntimeError('CPU does not support AES-NI. The module is disabled.')

        cbc_lib = ctypes.CDLL(str(cbc_dll))
        cbc_lib.cbc_encrypt.restype = ctypes.c_int
        cbc_lib.cbc_encrypt.argtypes = [
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_size_t)
        ]

        cbc_lib.cbc_decrypt.restype = ctypes.c_int
        cbc_lib.cbc_decrypt.argtypes = [
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_size_t)
        ]

        cls.aes_lib = aes_lib
        cls.cbc_lib = cbc_lib
        return cls.cbc_lib

    def __init__(self, key, iv=None):
        self.lib = self.load_lib()
        self.key = bytes(key)
        self.iv = os.urandom(self.IV_LEN) if (iv is None or len(iv) != self.IV_LEN) else iv

    def encrypt(self, _plaintext):
        pt = bytes(_plaintext)
        padded_len = ((len(pt) // self.BLOCK_SIZE) + 1) * self.BLOCK_SIZE
        ct_buf = ctypes.create_string_buffer(padded_len)
        ct_len = ctypes.c_size_t(0)

        rc = self.lib.cbc_encrypt(self.key, self.iv, pt, len(pt), ct_buf, ctypes.byref(ct_len))
        if rc != 0:
            return None
        return self.iv, ct_buf.raw[:ct_len.value]

    def decrypt(self, _ciphertext, _iv=None):
        ct = bytes(_ciphertext)
        if len(ct) == 0 or len(ct) % self.BLOCK_SIZE != 0:
            return None

        use_iv = self.iv if _iv is None else bytes(_iv)
        if len(use_iv) != self.IV_LEN:
            return None

        pt_buf = ctypes.create_string_buffer(len(ct))
        pt_len = ctypes.c_size_t(0)

        rc = self.lib.cbc_decrypt(self.key, use_iv, ct, len(ct), pt_buf, ctypes.byref(pt_len))
        if rc != 0:
            return None
        return pt_buf.raw[:pt_len.value]

    @classmethod
    def pack(cls, _data: bytes, _key: bytes, **_params):
        iv = _params.get('iv')
        cipher = cls(_key, iv)
        result = cipher.encrypt(_data)
        if result is None:
            return None
        used_iv, ct = result
        return {
            'algorithm': 'AES-CBC',
            'params': used_iv,
            'tag': b'',
            'ciphertext': ct
        }

    @classmethod
    def unpack(cls, _package: dict, _key: bytes, **_params):
        iv = _package.get('params', b'')
        ct = _package.get('ciphertext')
        if ct is None:
            return None
        cipher = cls(_key, iv)
        return cipher.decrypt(ct, iv)


class AES_GCM:
    NONCE_LEN = 12
    KEY_LEN = 16
    TAG_LEN = 16

    aes_lib = None
    gcm_lib = None

    @classmethod
    def load_lib(cls):
        if cls.gcm_lib is not None:
            return cls.gcm_lib

        aes_dll = Paths.crypto_dll('aes', 'aes')
        gcm_dll = Paths.crypto_dll('aes', 'gcm')

        aes_lib = ctypes.CDLL(str(aes_dll))
        aes_lib.cpu_has_aes_ni.restype = ctypes.c_int
        aes_lib.cpu_has_aes_ni.argtypes = []
        if not aes_lib.cpu_has_aes_ni():
            raise RuntimeError('CPU does not support AES-NI. The module is disabled.')

        gcm_lib = ctypes.CDLL(str(gcm_dll))
        gcm_lib.gcm_encrypt.restype = ctypes.c_int
        gcm_lib.gcm_encrypt.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p,
            ctypes.c_char_p, ctypes.c_size_t,
            ctypes.c_char_p, ctypes.c_size_t,
            ctypes.c_char_p, ctypes.c_char_p
        ]

        gcm_lib.gcm_decrypt.restype = ctypes.c_int
        gcm_lib.gcm_decrypt.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p,
            ctypes.c_char_p, ctypes.c_size_t,
            ctypes.c_char_p, ctypes.c_size_t,
            ctypes.c_char_p, ctypes.c_char_p
        ]

        cls.aes_lib = aes_lib
        cls.gcm_lib = gcm_lib
        return cls.gcm_lib

    def __init__(self, key, nonce):
        self.lib = self.load_lib()
        self.key = bytes(key)
        self.nonce = bytes(nonce) if nonce is not None else None

    def resolve_nonce(self, _nonce):
        if _nonce is not None:
            if len(_nonce) != self.NONCE_LEN:
                return
            return bytes(_nonce)
        if self.nonce is not None:
            return self.nonce
        return os.urandom(self.NONCE_LEN)

    def encrypt(self, _plaintext, _aad=b'', _nonce=None):
        n = self.resolve_nonce(_nonce)
        if n is None:
            return
        pt = bytes(_plaintext)
        a = bytes(_aad)

        ct_buf = ctypes.create_string_buffer(max(len(pt), 1))
        tag_buf = ctypes.create_string_buffer(self.TAG_LEN)

        rc = self.lib.gcm_encrypt(self.key, n, a, len(a), pt, len(pt), ct_buf, tag_buf)
        if rc != 0:
            return
        return n, ct_buf.raw[:len(pt)], tag_buf.raw[:self.TAG_LEN]

    def decrypt(self, _ciphertext, _tag, _aad=b'', _nonce=None):
        n = self.resolve_nonce(_nonce)
        if n is None:
            return
        ct = bytes(_ciphertext)
        t = bytes(_tag)
        a = bytes(_aad)

        if len(t) != self.TAG_LEN:
            return

        pt_buf = ctypes.create_string_buffer(max(len(ct), 1))

        rc = self.lib.gcm_decrypt(self.key, n, a, len(a), ct, len(ct), t, pt_buf)
        if rc != 0:
            return
        return pt_buf.raw[:len(ct)]

    @classmethod
    def pack(cls, _data: bytes, _key: bytes, **_params):
        aad = _params.get('aad', b'')
        nonce = _params.get('nonce')
        cipher = cls(_key, nonce)
        result = cipher.encrypt(_data, aad)
        if result is None:
            return None
        used_nonce, ct, tag = result
        return {
            'algorithm': 'AES-GCM',
            'params': used_nonce,
            'tag': tag,
            'ciphertext': ct
        }

    @classmethod
    def unpack(cls, _package: dict, _key: bytes, **_params):
        aad = _params.get('aad', b'')
        nonce = _package.get('params', b'')
        tag = _package.get('tag', b'')
        ct = _package.get('ciphertext')
        if ct is None:
            return None
        cipher = cls(_key, nonce)
        return cipher.decrypt(ct, tag, aad, nonce)

