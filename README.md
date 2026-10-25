# SecureImageStego

![platform](https://img.shields.io/badge/platform-Windows%20x64-0078D6)
![python](https://img.shields.io/badge/python-3.11%2B-3776AB)
![release](https://img.shields.io/badge/release-1.0.1-blue)
![license](https://img.shields.io/badge/license-MIT-green)

**Encrypt a file, hide it inside an image, and prove it was never touched.**

SecureImageStego is a Windows desktop application that covers the full
**encrypt → embed → extract → verify** pipeline. A hand-written C cryptography
core is loaded from Python through `ctypes`; the payload is hashed with
SHA3-256, optionally encrypted with AES-128, and embedded into the pixels of a
carrier image. Extraction reverses the process and verifies the SHA3-256 digest
before anything is written to disk.

> Academic demonstration built for the **NTU SE6003 Cryptography** group
> project. The crypto core is implemented from the standards rather than
> wrapped from a library, so the primitives can be inspected and tested
> against the official vectors.

---

## Table of contents

- [Features](#features)
- [How it works](#how-it-works)
- [Download](#download)
- [Usage](#usage)
- [Building from source](#building-from-source)
- [Testing](#testing)
- [Project layout](#project-layout)
- [Compatibility](#compatibility)
- [Security notes](#security-notes)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Features

- **AES-128 with hardware acceleration** — CTR, CBC and GCM modes built on
  AES-NI intrinsics instead of table lookups, so the block cipher runs at
  memory-speed rather than being the bottleneck.
- **SHA3-256 integrity trailer** — every payload carries a digest, so a
  modified stego image is detected instead of silently producing garbage.
- **Three encryption modes to compare** — stream (CTR), block chaining with
  PKCS#7 (CBC), and authenticated encryption (GCM with optional AAD).
- **Two embedding methods** — LSB (1–8 bits per channel) and Pixel Value
  Differencing, both provided by [stegosphere](https://github.com/Maximilian-Koch/stegosphere).
- **Native C core, Python front end** — the crypto lives in five small DLLs
  loaded through `ctypes`; the UI is a Flet (Flutter) desktop app.
- **Reproducible, testable build** — the same sources build with MSVC or
  MinGW-w64, and `Test.py` runs the NIST known-answer vectors against either
  build, plus a bit-for-bit cross-check between them.

## How it works

```
   payload file
        │
        │  SHA3-256
        ├──────────────────────────────► 32-byte digest
        │
        └─ payload ‖ "SH3\x01" ‖ digest          integrity trailer
                     │
                     │  optional: AES-128-CTR / CBC / GCM
                     │  key = SHA-256(password)[0:16]
                     ▼
              payload bits
                     │
                     │  LSB or Pixel Value Differencing
                     ▼
   carrier.png ──► stego.png
```

Extraction runs the same pipeline backwards: read pixels → extract bits →
decrypt → split trailer → recompute SHA3-256 → compare → write the file only
if the digest matches.

### Cryptography

| Layer         | Algorithm                 | Parameters                                        | Source                                                             |
| ------------- | ------------------------- | ------------------------------------------------- | ------------------------------------------------------------------ |
| Block cipher  | AES-128 (AES-NI)          | 16-byte key, 10 rounds                            | [`src/Proccess/Crypto/AES/AES.c`](src/Proccess/Crypto/AES/AES.c)   |
| Mode          | CTR                       | 128-bit big-endian counter, random IV             | [`CTR/AES_CTR.c`](src/Proccess/Crypto/AES/CTR/AES_CTR.c)           |
| Mode          | CBC                       | PKCS#7 padding, random IV                         | [`CBC/AES_CBC.c`](src/Proccess/Crypto/AES/CBC/AES_CBC.c)           |
| Mode          | GCM                       | 96-bit nonce, 128-bit tag, optional AAD           | [`GCM/AES_GCM.c`](src/Proccess/Crypto/AES/GCM/AES_GCM.c)           |
| Hash          | SHA3-256 (Keccak-f[1600]) | 32-byte digest                                    | [`SHA3/SHA3.c`](src/Proccess/Crypto/SHA3/SHA3.c)                   |
| KDF           | `SHA-256(password)[0:16]` | demo-grade, see [Security notes](#security-notes) | [`src/Proccess/FileManagement.py`](src/Proccess/FileManagement.py) |
| Steganography | LSB (C backend) / PV-D    | 1–8 bits per channel                              | stegosphere 1.3                                                    |

The DLLs export a flat C API (`ctr_crypt`, `cbc_encrypt`, `gcm_encrypt`,
`sha3_256`, …) which is bound in Python with explicit `argtypes`, so a missing
symbol fails loudly instead of corrupting memory.

## Download

Grab the latest build from the [releases page](https://github.com/Ant-RWFS/SecureImageStego/releases/tag/release-v1.0.1):

| Artifact                                                                                                                                                               | Size   | Notes                                                               |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ | ------------------------------------------------------------------- |
| [SecureImageStego-setup-1.0.1-win_amd64.exe](https://github.com/Ant-RWFS/SecureImageStego/releases/download/release-v1.0.1/SecureImageStego-setup-1.0.1-win_amd64.exe) | ~52 MB | Installer, adds a Start-menu entry and an optional desktop shortcut |
| [SecureImageStego-1.0.1-win_amd64.zip](https://github.com/Ant-RWFS/SecureImageStego/releases/download/release-v1.0.1/SecureImageStego-1.0.1-win_amd64.zip)             | ~71 MB | Portable build, unpack and run `SecureImageStego.exe`               |

Both are unsigned, so Windows SmartScreen may show a warning on first launch.

## Usage

The window has two tabs.

### Embed a file

1. **INPUT** — pick the carrier image. Any format Pillow can read works
   (PNG, BMP, TIFF, …). Prefer PNG: JPEG artefacts will destroy LSB payloads.
2. **EMBED** — pick the file you want to hide.
3. **OUTPUT** — choose where to save the stego image. Always use `.png`.
4. Optional, via the two icon buttons:
   - ⚙ **Steganography config** — `LSB` with 1–8 bits per channel, or `VD`
     (Pixel Value Differencing, Wu & Tsai 2003). More bits store more data but
     are easier to detect and more fragile.
   - 🔑 **Cryptography config** — AES mode (`CTR` / `CBC` / `GCM`), an optional
     password, and AAD for GCM. Leave the password empty to embed the payload
     in the clear (the SHA3-256 trailer is still applied).
5. Click **Embed**. The status bar reports success, or a capacity warning if
   the carrier is too small for the payload.

### Extract a file

1. **INPUT** — pick the stego image.
2. **OUTPUT** — where to write the recovered file.
3. Configure the same steganography / cryptography settings used when
   embedding.
4. Click **Extract**. The status bar distinguishes:
   - extracted **and** SHA3-256 verified;
   - extracted, but no digest found;
   - integrity check failed (the file is **not** written);
   - wrong password / corrupted ciphertext.

### Capacity

LSB capacity is roughly `width × height × channels × bits / 8` bytes, minus
the framing header and the 36-byte integrity trailer (`SH3\x01` + 32-byte
digest). A 1920×1080 RGB image at 1 bit/channel holds about 760 KB.

## Building from source

### Prerequisites

- Windows 10/11 x64
- Python 3.11+ (developed on 3.15)
- **Either** Visual Studio 2022 with the C++ workload, **or** MinGW-w64
  (MSYS2 UCRT64 or a standalone WinLibs build)
- Inno Setup 6 (only for the installer)

### 1. Native crypto DLLs

Pick one toolchain; both produce the same directory layout under
`build\crypto\`.

```bat
rem MSVC - run from an "x64 Native Tools Command Prompt"
tools\build_msvc_cl.bat

rem MinGW-w64 - gcc must be on PATH, or pass its full path
set "CC=C:\msys64\ucrt64\bin\gcc.exe"
tools\build_mingw64_gcc.bat
```

Expected output:

```
build\crypto\aes\dll\{aes,ctr,cbc,gcm}.dll
build\crypto\sha3\dll\sha3.dll
```

The resulting DLLs require an x64 CPU with **AES-NI** and **PCLMULQDQ**
(Intel Westmere / AMD Bulldozer or newer, i.e. anything from ~2011 onwards).

### 2. Python application

```bat
python -m venv venv
venv\Scripts\python.exe -m pip install -r requirements.txt
venv\Scripts\python.exe -m pip install "pyinstaller==6.22.3"

rem run from source
venv\Scripts\python.exe Main.py
```

### 3. Bundle and install

```bat
tools\setup.bat
dist\SecureImageStego\SecureImageStego.exe --selftest
```

`setup.bat` runs PyInstaller with [`tools/SecureImageStego.spec`](tools/SecureImageStego.spec),
then patches the icon resources of the bundled Flet client (`flet.exe`) so the
window and taskbar icons are not the default Flet logo.

`--selftest` runs the DLL, AES and embed/extract checks headlessly, writes
`selftest.log` next to the executable and exits `0` on success.

## Testing

`Test.py` is a self-contained `unittest` suite (no pytest required) that
verifies the native DLLs against official known-answer vectors.

```bat
rem every test\*_dll build that exists
venv\Scripts\python.exe Test.py -v

venv\Scripts\python.exe Test.py --dll-root test\gcc_dll

rem list the reference vectors and their sources
venv\Scripts\python.exe Test.py --list-vectors
```

It generates one suite per build root (`Msvc*`, `Gcc*`) and, when both exist,
a `CrossMsvcGccTests` class that feeds identical random inputs to both builds
and asserts bit-identical output.

| Vector set                  | Source                                                |
| --------------------------- | ----------------------------------------------------- |
| AES-128 block, key schedule | FIPS 197, Appendix B and C.1                          |
| AES-128-CTR                 | NIST SP 800-38A, F.5.1                                |
| AES-128-CBC                 | NIST SP 800-38A, F.2.1                                |
| AES-128-GCM (incl. AAD)     | NIST SP 800-38D and McGrew–Viega GCM spec, Appendix B |
| SHA3-256                    | FIPS 202, plus cross-check against `hashlib.sha3_256` |
| PKCS#7 padding              | RFC 5652 §6.3                                         |

## Project layout

```
SecureImageStego/
├── Main.py                     application entry point (Flet)
├── Test.py                     known-answer tests for the native DLLs
├── requirements.txt
├── LICENSE
├── asset/app.ico               application and window icon
├── src/
│   ├── GUI/                    Flet window, tabs, dialogs
│   └── Proccess/
│       ├── Cryptography.py     mode dispatch + (de)serialisation of packages
│       ├── Steganography.py    embed/extract pipeline
│       ├── FileManagement.py   path resolution, password -> key derivation
│       └── Crypto/             C sources of the five DLLs
├── build/crypto/               compiled DLLs (aes/, sha3/)
├── test/
│   ├── msvc_dll/               MSVC build snapshot, used by Test.py
│   └── gcc_dll/                MinGW-w64 build snapshot, used by Test.py
└── tools/
    ├── build_msvc_cl.bat       native build, MSVC
    ├── build_mingw64_gcc.bat   native build, MinGW-w64
    ├── setup.bat               PyInstaller bundle + icon patch
    ├── SecureImageStego.spec   PyInstaller spec
    ├── set_icon.py             rewrites the flet.exe icon resources
    └── inno_setup.iss          installer script
```

## Compatibility

|             |                                                 |
| ----------- | ----------------------------------------------- |
| OS          | Windows 10 1809+ / Windows 11, x64              |
| CPU         | x64 with AES-NI + PCLMULQDQ + SSE4.1            |
| ARM64       | not supported (the DLLs are PE/x64)             |
| Interpreter | CPython 3.11+                                   |
| Images      | anything Pillow reads; save stego images as PNG |

## Security notes

This is a teaching project. Read these before using it for anything that
matters:

- **The KDF is deliberately simple.** The AES key is the first 16 bytes of a
  single SHA-256 over the password — no salt, no work factor. A real system
  should use PBKDF2, scrypt or Argon2id with a per-file salt.
- **Steganography is not encryption.** Without a password the payload is
  merely hidden; anyone who suspects LSB embedding can recover it.
- **LSB is fragile.** Re-encoding, resizing or lossy compression destroys the
  payload. Keep the stego image as PNG and ship it byte-for-byte.
- **CBC is not authenticated on its own.** Integrity comes from the SHA3-256
  trailer, which is checked after decryption; GCM is authenticated by design.
- **No anti-forensics.** LSB embedding leaves statistical traces; the project
  does not attempt to resist steganalysis.

## Troubleshooting

| Symptom                                     | Cause / fix                                                                                                                  |
| ------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `RuntimeError: CPU does not support AES-NI` | The CPU lacks AES-NI; the crypto core refuses to run rather than crash on an illegal instruction.                            |
| App exits immediately, no window            | A native DLL is missing or was built for a different architecture. Check `build\crypto\aes\dll` and `build\crypto\sha3\dll`. |
| "Integrity check failed" on extract         | Wrong password, wrong mode, or the image was re-encoded/edited. The file is intentionally not written.                       |
| "Embed FAILED" / capacity warning           | The carrier image is too small for the payload at the chosen bit depth.                                                      |
| Window icon is still the Flet logo          | Re-run `tools\set_icon.py` (or `tools\setup.bat`) after a rebuild; Explorer may also cache the old icon.                     |
| SmartScreen warning                         | The binaries are unsigned. Use "More info → Run anyway", or build from source.                                               |

## License

Released under the [MIT License](LICENSE).

Third-party components bundled with the distributed builds:

| Component                                                         | License                                    |
| ----------------------------------------------------------------- | ------------------------------------------ |
| [stegosphere](https://github.com/Maximilian-Koch/stegosphere) 1.3 | GPL-3.0-or-later                           |
| [Flet](https://flet.dev) 0.27.4                                   | Apache-2.0                                 |
| [PyInstaller](https://pyinstaller.org) 6.22.3                     | GPL-2.0-or-later with bootloader exception |
| [NumPy](https://numpy.org)                                        | BSD-3-Clause                               |
| [Pillow](https://python-pillow.org)                               | MIT-CMU                                    |

Note that stegosphere is GPL-3.0-or-later: redistributing a binary that bundles
it means the combined distribution has to satisfy the GPL as well.

## Acknowledgements

- [stegosphere](https://github.com/Maximilian-Koch/stegosphere) by Maximilian Koch — embedding methods and file containers.
- Wu, D. C. & Tsai, W. H. (2003), *A steganographic method for images by pixel-value differencing*, Pattern Recognition Letters 24(9–10).
- NIST FIPS 197, FIPS 202, SP 800-38A, SP 800-38D, and the McGrew–Viega GCM specification for the reference vectors.
- NTU SE6003 Cryptography, for the assignment that prompted this project.
