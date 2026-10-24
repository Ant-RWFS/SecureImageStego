import struct
from . import DataStructure
from .Crypto.AES.AESNI import AES_CTR, AES_CBC, AES_GCM
from .Crypto.SHA3.SHA3 import SHA3

CRYPTOGRAPHY = {
    'AES': {
        'CTR': {
            'enc': AES_CTR.pack,
            'dec': AES_CTR.unpack,
            'params': [],
            'key_len': AES_CTR.KEY_LEN
        },
        'CBC': {
            'enc': AES_CBC.pack,
            'dec': AES_CBC.unpack,
            'params': [],
            'key_len': AES_CBC.KEY_LEN
        },
        'GCM': {
            'enc': AES_GCM.pack,
            'dec': AES_GCM.unpack,
            'params': [
                DataStructure.Cryptography('aad', 'AAD', bytes, default='')
            ],
            'key_len': AES_GCM.KEY_LEN
        }
    }
}


class Cryptography:
    def __init__(self, algorithm: str, mode: str, key: bytes, parameters: dict):
        self.algorithm = algorithm
        self.mode = mode
        self.expected_key_len = CRYPTOGRAPHY[self.algorithm][self.mode].get('key_len', 16)
        self.key = bytes(key[:self.expected_key_len].ljust(self.expected_key_len, b'\00'))
        self.parameters = parameters

    def convert_params(self):
        params = self.parameters.copy()
        param_struct = CRYPTOGRAPHY[self.algorithm][self.mode]['params']
        for param in param_struct:
            raw = params.get(param.name, param.default)
            if param.param_type is bytes:
                params[param.name] = raw.encode('utf-8') if isinstance(raw, str) else bytes(raw)
            elif param.param_type is bool:
                params[param.name] = (raw.lower() == 'true') if isinstance(raw, str) else bool(raw)
            else:
                params[param.name] = param.param_type(raw)
        return params

    def encrypt(self, _plaintext):
        if self.algorithm != '-':
            info = CRYPTOGRAPHY[self.algorithm][self.mode]
            package = info['enc'](self.encode(_plaintext), self.key, **self.convert_params())
            if package is None:
                return None
            return self.serialize(package)
        else:
            return _plaintext

    def decrypt(self, _ciphertext):
        if self.algorithm != '-':
            info = CRYPTOGRAPHY[self.algorithm][self.mode]
            package = self.deserialize(self.normalize(_ciphertext))
            if package is None:
                return None
            return info['dec'](package, self.key, **self.convert_params())
        else:
            return _ciphertext

    @staticmethod
    def key_len(_algorithm: str, _mode: str) -> int:
        return CRYPTOGRAPHY[_algorithm][_mode].get('key_len', 16)

    @staticmethod
    def serialize(_package: dict) -> bytes:
        params = _package.get('params', b'') or b''
        tag = _package.get('tag', b'') or b''
        ct = _package.get('ciphertext', b'') or b''
        return struct.pack('>II', len(params), len(tag)) + params + tag + ct

    @staticmethod
    def deserialize(_data: bytes) -> dict:
        params_len, tag_len = struct.unpack('>II', _data[:8])
        offset = 8
        params = _data[offset:offset + params_len]
        offset += params_len
        tag = _data[offset:offset + tag_len]
        offset += tag_len
        ciphertext = _data[offset:]
        return {'params': params, 'tag': tag, 'ciphertext': ciphertext}

    @staticmethod
    def encode(_data) -> bytes:
        return str(_data).encode('latin-1')

    @staticmethod
    def normalize(_data) -> bytes:
        if isinstance(_data, (bytes, bytearray)):
            return bytes(_data)
        elif isinstance(_data, str):
            if len(_data) > 0 and len(_data) % 8 == 0 and set(_data) <= {'0', '1'}:
                return bytes(int(_data[i:i + 8], 2) for i in range(0, len(_data), 8))
        return _data.encode('latin-1')


class Integrity:
    def __init__(self):
        self.algorithm = SHA3()

    def digest(self, _payload):
        return self.algorithm.payload_digest(_payload)

    def attach(self, _payload, _digest):
        return self.algorithm.attach(_payload, _digest)

    def detach(self, _extracted):
        return self.algorithm.detach(_extracted)

    def verify(self, _payload, _digest):
        return self.algorithm.verify(_payload, _digest)
