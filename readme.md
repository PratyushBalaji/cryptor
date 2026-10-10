# cryptor 

A simple command-line file encryption tool with authenticated and involutive (reversible) modes.

Provides authenticated encryption and decryption using Argon2id and XChaCha20-Poly1305, along with an experimental deterministic transformation that preserves file size and uses the same operation to encrypt and decrypt (Argon2id + XChaCha20).

This project is intended to explore file formats, key derivation functions, stream encryption, authentication, and cybersecurity concepts.

Currently tested on and targeting **Ubuntu LTS**. The current implementation should also compile on other Linux distributions, macOS, and BSD systems with the required dependencies. Windows is not currently supported due to the use of `mkstemp` for atomic file operations.

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
Alternatively, compile directly with: `g++ -std=c++17 -Wall -Wextra -Wpedantic src/cryptor.cc -o cryptor -lsodium`

3. Run `cryptor`
```bash
$ ./cryptor [args] <input> <output>
```

## usage

Cryptor requires exactly one operation from:

| Option | Operation |
|---|---|
| `-e`, `--encrypt` | Encrypt using authenticated safe mode |
| `-d`, `--decrypt` | Decrypt a safely encrypted file |
| `-u`, `--unsafe` | Apply the deterministic reversible transformation |

These operations require two positional arguments: `/path/to/input` and `/path/to/output`.

Additional options:

| Option | Description |
|---|---|
| `--password-file <path>` | Read the password from a file instead of the terminal |
| `-f`, `--force` | Skip replacement confirmation prompts |
| `-h`, `--help` | Display help |

Note:

- Passing the exact same input and output path performs an atomic in-place operation. Different paths that alias the same file through a symbolic or hard link are rejected.
- Passwords are read from the controlling terminal and are not displayed.
- Safe-mode encryption asks for the password twice to catch typing mistakes.

For non-interactive use, pass `--password-file <path>`. Cryptor reads the entire file and removes one trailing LF or CRLF. It warns when the file grants permissions to group or other users.

Cryptor asks for confirmation before replacing an existing output, performing an in-place operation or replacing the password file. Use `--force` to skip the prompt; warnings and path validation are still shown. Unsafe mode always warns that it cannot authenticate passwords or file contents.

Output is written to a temporary file and atomically moved into place only after the operation succeeds. The replacement file has `0600` permissions. Existing permissions, ACLs, extended attributes and other metadata are not preserved.

### safe mode

```bash
$ ./cryptor [-e|-d] /path/to/input /path/to/output
```

Safe mode uses Argon2id and XChaCha20-Poly1305 authenticated encryption.

- Detects incorrect passwords, tampering, corruption and truncated files
- Produces different ciphertext each time, even with the same file and password
- Encryption adds a 64-byte header, and 17 authentication bytes per 64 KiB chunk
- Recommended when protecting real files

For more information, read [the safe mode specification](docs/format-v1.md).

### unsafe mode
```bash
$ ./cryptor -u /path/to/input /path/to/output
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

- [x] docs: safe v1 file-format specification
- [x] docs: unsafe-mode security and limitations
- [x] feat: atomic file operations
- [x] feat: hidden interactive password input
- [x] feat: password file input
- [ ] feat: add optional unsafe-mode parameters
- [x] misc: guarantee key and stream-state cleanup on error
- [x] test: automated tests and v1 compatibility fixtures
- [ ] test: cross platform compatibility

## license
MIT
