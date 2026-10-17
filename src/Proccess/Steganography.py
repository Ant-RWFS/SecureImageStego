from stegosphere.embeddings import LSB, VD
from stegosphere import image, io, payloader
from . import DataStructure
from .Cryptography import Cryptography

STEGANOGRAPHY = {
    'LSB': {
        'embed': LSB.embed,
        'extract': LSB.extract,
        'params': [DataStructure.Steganography('bits', 'Embedded Bits', int, default=1, min=1, max=8)]
    },
    'VD': {
        'embed': VD.embed,
        'extract': VD.extract,
        'params': []
    }
}


class Steganography:
    def __init__(self, algorithm: str, encryption: dict, parameters: dict, key: bytes = None):
        self.algorithm = algorithm
        self.encryption = encryption
        self.parameters = parameters
        self.key = key
        self.crypto = None
        if key:
            self.crypto = Cryptography(
                encryption['algorithm'],
                encryption['mode'],
                key,
                encryption['params']
            )

    def embed_file(self, _input_file, _payload_file, _output_file):
        algorithm_info = STEGANOGRAPHY[self.algorithm]
        embed_func = algorithm_info['embed']
        param_struct = algorithm_info['params']
        params = self.convert_params(param_struct)

        container = image.ImageContainer(_input_file)
        carrier = container.read()
        payload_binary = io.file_to_binary(_payload_file)

        if self.crypto is not None:
            raw = self.crypto.encrypt(payload_binary)
            if raw is None:
                return
            payload_binary = raw.decode('latin-1')
        embedded_data = embed_func(carrier, payload_binary, framing=payloader.FixedHeader(), **params)
        container.save(_output_file, embedded_data)

    def extract_file(self, _input_file, _output_file):
        algorithm_info = STEGANOGRAPHY[self.algorithm]
        extract_func = algorithm_info['extract']
        param_struct = algorithm_info['params']
        params = self.convert_params(param_struct)

        container = image.ImageContainer(_input_file)
        carrier = container.read()

        extracted_data = extract_func(carrier, framing=payloader.FixedHeader(), **params)
        if self.crypto is not None:
            raw = self.crypto.decrypt(extracted_data)
            if raw is None:
                return
            extracted_data = raw.decode('latin-1')
        io.binary_to_file(extracted_data, _output_file)

    def convert_params(self, _param_struct):
        params = self.parameters.copy()
        for param in _param_struct:
            if param.name in params:
                raw = params[param.name]
                if param.param_type is bool:
                    if isinstance(raw, str):
                        params[param.name] = raw.lower() == 'true'
                    else:
                        params[param.name] = bool(raw)
                else:
                    params[param.name] = param.param_type(raw)
        return params
