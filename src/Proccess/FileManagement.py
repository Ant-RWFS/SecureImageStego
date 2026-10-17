from pathlib import Path
import hashlib


class Paths:
    root_cache = None
    src_cache = None
    build_cache = None

    dll_cache: dict[tuple[str, str], Path] = {}

    @classmethod
    def root_path(cls):
        if cls.root_cache is None:
            cls.root_cache = Path(__file__).resolve().parents[2]
        return cls.root_cache

    @classmethod
    def src_path(cls):
        if cls.src_cache is None:
            cls.src_cache = cls.root_path() / 'src'
        return cls.src_cache

    @classmethod
    def build_path(cls):
        if cls.build_cache is None:
            cls.build_cache = cls.root_path() / 'build'
        return cls.build_cache

    @classmethod
    def crypto_dll(cls, _module: str, _name: str):
        key = (_module, _name)
        cached = cls.dll_cache.get(key)
        if cached is not None and cached.exists():
            return cached

        dll = cls.build_path() / 'crypto' / f'{_module}' / 'dll' / f'{_name}.dll'
        if dll.exists():
            cls.dll_cache[key] = dll
            return dll

        cls.dll_cache.pop(key, None)
        return None

    @classmethod
    def clear_cache(cls):
        cls.root_cache = None
        cls.src_cache = None
        cls.build_cache = None
        cls.dll_cache.clear()


class Secrets:
    @classmethod
    def derive_key(cls, _password: str, _length: int = 32):
        return hashlib.sha256(_password.encode('utf-8')).digest()[:_length]
