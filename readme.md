# cryptor 

A simple command-line file encryption tool with authenticated and involutive (reversible) modes.

Provides authenticated encryption and decryption using Argon2id and XChaCha20-Poly1305, along with an experimental deterministic transformation that preserves file size and uses the same operation to encrypt and decrypt (Argon2id + XChaCha20).

This project is intended to explore file formats, key derivation functions, stream encryption, authentication, and cybersecurity concepts.

Currently tested on and targeting **Ubuntu LTS**, but the code should compile on all major operating systems (Linux distros, Windows, macOS, BSD) as the dependencies are cross platform.

## dependencies

- C++17 or greater
- libsodium development headers
- CLI11 / libcli11 development headers
- GNU Make (optional)

## building
1. On Ubuntu, install the required development packages
```bash
$ sudo apt install build-essential libsodium-dev libcli11-dev
```
Note: `build-essential` is not required if a compatible C++ compiler and `make` are installed.

2. Build using the existing `Makefile`
```bash
$ make
```
Alternatively, compile directly with: `g++ -std=c++17 -Wall -Wextra -Wpedantic cryptor.cc -o cryptor -lsodium`

3. Run `cryptor`
```bash
$ ./cryptor [args] <input> <output> <password>
```

## usage

Cryptor requires exactly one operation from:

| Option | Operation |
|---|---|
| `-e`, `--encrypt` | Encrypt using authenticated safe mode |
| `-d`, `--decrypt` | Decrypt a safely encrypted file |
| `-u`, `--unsafe` | Apply the deterministic reversible transformation |
| `-h`, `--help` | Display help |

All non-help operations also require 3 positional arguments: `/path/to/input`, `/path/to/output`, `password`

Note:

- Input and output must refer to distinct files.
- Passwords containing spaces or shell characters should be quoted.

### safe mode

```bash
$ ./cryptor [-e|-d] /path/to/input /path/to/output "password"
```

Safe mode uses Argon2id and XChaCha20-Poly1305 authenticated encryption.

- Detects incorrect passwords, tampering, corruption and truncated files
- Produces different ciphertext each time, even with the same file and password
- Encryption adds a 64-byte header, and 17 authentication bytes per 64 KiB chunk
- Recommended when protecting real files

### unsafe mode
```bash
$ ./cryptor -u /path/to/input /path/to/output "password"
```

Unsafe mode applies a deterministic XChaCha20 XOR transformation. Applying it twice with the same password restores the original file.

- Preserves the exact file size
- Uses the same operation for encryption and decryption
- Produces identical output for the same file and password
- Cannot detect incorrect passwords, tampering or corruption (incorrect password produces garbage output)
- Intended for experimentation rather than sensitive files

Unsafe mode is still relatively secure, but is susceptible to certain attacks under some conditions. At a high-level, it derives a 256-bit key from the password with Argon2id, then uses XChaCha20 to generate a pseudorandom keystream equal in length to the file.

With a strong, unique password for each file, this provides strong computational confidentiality. However, reusing a password reuses the same keystream across files and may expose information about their plaintext.

For more information about the specific vulnerabilities, read [the unsafe mode security notes](docs/unsafe-mode.md).

## todo

- [ ] docs: safe v1 file-format specification
- [ ] docs: unsafe-mode security and limitations
- [ ] feat: atomic file operations
- [ ] feat: hidden interactive password input
- [ ] feat: add optional unsafe-mode parameters
- [ ] misc: guarantee key and stream-state cleanup on error
- [ ] test: automated tests and v1 compatibility fixtures
- [ ] test: cross platform compatibility

## license
MIT
