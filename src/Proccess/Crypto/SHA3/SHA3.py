import ctypes
import hmac
from src.Proccess.FileManagement import Paths


class SHA3:
    DIGEST_BYTES = 32
    MAGIC = b'SH3\x01'
    TRAILER_BITS = (len(MAGIC) + DIGEST_BYTES) * 8

    sha3_lib = None

    @classmethod
    def load_lib(cls):
        if cls.sha3_lib is not None:
            return cls.sha3_lib
        sha3_dll = Paths.crypto_dll('sha3', 'sha3')
        if sha3_dll is None:
            return
        sha3_lib = ctypes.CDLL(str(sha3_dll))
        sha3_lib.sha3_256.restype = ctypes.c_int
        sha3_lib.sha3_256.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
        cls.sha3_lib = sha3_lib
        return sha3_lib

    @staticmethod
    def bits_to_bytes(_bits: str):
        return bytes(int(_bits[i:i + 8], 2) for i in range(0, len(_bits), 8))

    @staticmethod
    def bytes_to_bits(_data: bytes):
        return str(''.join(f'{b:08b}' for b in _data))

    def hash_bytes(self, _data):
        out = ctypes.create_string_buffer(self.DIGEST_BYTES)
        data = bytes(_data)
        if self.load_lib().sha3_256(data, len(data), out) != 0:
            raise ValueError('sha3_256 failed')
        return out.raw

    def payload_digest(self, _payload):
        if isinstance(_payload, (bytes, bytearray)):
            return self.hash_bytes(bytes(_payload))
        return self.hash_bytes(self.bits_to_bytes(_payload))

    def attach(self, _payload_binary, _digest):
        trailer = self.MAGIC + bytes(_digest)
        if isinstance(_payload_binary, (bytes, bytearray)):
            return bytes(_payload_binary) + trailer
        return _payload_binary + self.bytes_to_bits(trailer)

    def detach(self, _extracted):
        if isinstance(_extracted, (bytes, bytearray)):
            data = bytes(_extracted)
            n = len(self.MAGIC) + self.DIGEST_BYTES
            if len(data) >= n and data[-n:-self.DIGEST_BYTES] == self.MAGIC:
                return data[:-n], data[-self.DIGEST_BYTES:]
            return data, None

        if len(_extracted) >= self.TRAILER_BITS:
            trailer = self.bits_to_bytes(_extracted[-self.TRAILER_BITS:])
            if trailer[:len(self.MAGIC)] == self.MAGIC:
                return _extracted[:-self.TRAILER_BITS], trailer[len(self.MAGIC):]
        return _extracted, None

    def verify(self, _payload, _stored_digest: bytes):
        return bool(hmac.compare_digest(self.payload_digest(_payload), _stored_digest))
