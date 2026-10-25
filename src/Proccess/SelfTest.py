import os
import shutil
import sys
import traceback


def _base_dir() -> str:
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def run() -> int:
    from src.Proccess.Cryptography import Cryptography
    from src.Proccess.FileManagement import Paths, Secrets
    from src.Proccess.Steganography import Steganography

    base = _base_dir()
    log_path = os.path.join(base, "selftest.log")
    work = os.path.join(base, "_selftest_tmp")
    lines = []

    def log(message):
        lines.append(str(message))
        try:
            print(message, flush=True)
        except Exception:
            pass
        try:
            with open(log_path, "w", encoding="utf-8") as handle:
                handle.write("\n".join(lines) + "\n")
        except OSError:
            pass

    rc = 0
    try:
        missing = [
            f"{module}/{name}"
            for module, name in (
                ("aes", "aes"), ("aes", "ctr"), ("aes", "cbc"),
                ("aes", "gcm"), ("sha3", "sha3"),
            )
            if Paths.crypto_dll(module, name) is None
        ]
        if missing:
            raise RuntimeError(f"native dll missing: {missing}")
        log(f"dll ok: {Paths.build_path()}")

        key = Secrets.derive_key("selftest-password")
        for mode in ("CTR", "CBC", "GCM"):
            cipher = Cryptography("AES", mode, key, {})
            probe = "secure image stego"
            if cipher.decrypt(cipher.encrypt(probe)) != probe.encode("latin-1"):
                raise RuntimeError(f"AES-{mode} roundtrip failed")
            log(f"AES-{mode}: ok")

        from stegosphere import __version__ as stegosphere_version
        log(f"stegosphere: {stegosphere_version}")

        os.makedirs(work, exist_ok=True)
        from PIL import Image
        import numpy as np

        carrier = os.path.join(work, "carrier.png")
        payload = os.path.join(work, "payload.bin")
        embedded = os.path.join(work, "embedded.png")
        extracted = os.path.join(work, "extracted.bin")

        pixels = np.random.default_rng(0).integers(0, 256, (64, 64, 4), dtype=np.uint8)
        Image.fromarray(pixels).save(carrier)
        data = os.urandom(64)
        with open(payload, "wb") as handle:
            handle.write(data)

        stego = Steganography(
            "LSB",
            {"algorithm": "AES", "mode": "GCM", "params": {}},
            {"bits": "1"},
            key,
        )

        status, info = stego.embed_file(carrier, payload, embedded)
        log(f"embed: status={status} info={info}")
        if status != 2:
            raise RuntimeError("embed failed")

        status, info = stego.extract_file(embedded, extracted)
        log(f"extract: status={status} info={info}")
        if status != 3:
            raise RuntimeError("extract or integrity check failed")

        with open(extracted, "rb") as handle:
            if handle.read() != data:
                raise RuntimeError("payload mismatch")
        log("roundtrip: ok")
        log("SELFTEST OK")
    except Exception:
        log(traceback.format_exc())
        rc = 1
    finally:
        if rc == 0:
            shutil.rmtree(work, ignore_errors=True)
    return rc
