# Cryptor safe file format v1

This document defines the byte-level format produced by Cryptor safe-mode encryption and required for compatible decryption.

Version 1 uses Argon2id for password-based key derivation and XChaCha20-Poly1305 secretstream for authenticated encryption. Files consist of a fixed 64-byte header followed by one or more authenticated ciphertext chunks.

This specification applies only to safe mode. Unsafe mode has no header or versioned file format and is documented separately in [unsafe-mode.md](unsafe-mode.md).

## Cryptographic parameters

The following parameters are fixed for format version 1:

| Parameter | v1 value |
|---|---|
| Format version | `0x01` |
| Password KDF | Argon2id v1.3 (`crypto_pwhash_ALG_ARGON2ID13`) |
| Argon2 operations limit | `2` |
| Argon2 memory limit | `67,108,864` bytes (64 MiB) |
| Argon2 parallelism | 1 lane |
| Derived key size | 32 bytes |
| Salt size | 16 bytes |
| Cipher | XChaCha20-Poly1305 secretstream |
| Secretstream header size | 24 bytes |
| Plaintext chunk size | 65,536 bytes |
| Authentication overhead | 17 bytes per chunk |
| Total file header size | 64 bytes |
| Integer encoding | Unsigned 64-bit, big-endian |
| Associated data | Complete 64-byte file header |

These values are part of the v1 format and must remain unchanged for compatibility. Any incompatible parameter change requires a new format version.

## Header layout

Every safe-mode file begins with a fixed 64-byte header:

| Offset | Size | Contents |
|---:|---:|---|
| `0x00–0x06` | 7 bytes | ASCII signature `CRYPTOR` |
| `0x07` | 1 byte | Format version `0x01` |
| `0x08–0x0F` | 8 bytes | Argon2 operations limit |
| `0x10–0x17` | 8 bytes | Argon2 memory limit in bytes |
| `0x18–0x27` | 16 bytes | Random Argon2 salt |
| `0x28–0x3F` | 24 bytes | XChaCha20-Poly1305 secretstream header |
| `0x40` | — | First ciphertext chunk begins |

In v1 an encrypted file always starts with this sequence of bytes: (`xxd -c 8` style schematic)

```hex
00000000: 4352 5950 544f 5201  CRYPTOR.   // file signature, version 1
00000008: 0000 0000 0000 0002  ........   // operations limit
00000010: 0000 0000 0400 0000  ........   // memory limit
00000018: XXXX XXXX XXXX XXXX  ????????   // X - salt
00000020: XXXX XXXX XXXX XXXX  ????????
00000028: YYYY YYYY YYYY YYYY  ........   // Y - secretstream header
00000030: YYYY YYYY YYYY YYYY  ........
00000038: YYYY YYYY YYYY YYYY  ........
00000040: CCCC CCCC CCCC CCCC  ????????   // ciphertext begins
00000048: CCCC CCCC CCCC CCCC  ????????
                  ...
```
The salt, secretstream header, and ciphertext vary for every encryption.

The header is public and is not encrypted. However, the complete 64-byte header is used as associated data for every ciphertext chunk, so authenticated decryption fails if it is modified.

## Key derivation

The encryption key is derived from the supplied password using Argon2id v1.3.

```c++
key = Argon2id13(
    password,
    salt = header[0x18–0x27],
    operations = 2,
    memory = 67,108,864 bytes,
    parallelism = 1,
    output length = 32 bytes
)
```

The password is treated as its exact byte sequence (no null terminator). Cryptor performs no text encoding conversion or Unicode normalisation.

During encryption, a new random 16-byte salt is generated and stored in the file header. The salt is public and does not need to be kept secret.

During decryption, the salt and Argon2 parameters are read from the header. Version 1 accepts only its fixed operations and memory limits. Files containing different values are rejected before key derivation.

The derived 32-byte key initialises the XChaCha20-Poly1305 secretstream state.

## Authenticated chunk framing

Plaintext is divided into consecutive chunks of at most 65,536 bytes.

- Every non-final plaintext chunk contains exactly 65,536 bytes and is tagged with `crypto_secretstream_xchacha20poly1305_TAG_MESSAGE` (`0x00`).
- The final plaintext chunk contains between 0 and 65,536 bytes and is tagged with `crypto_secretstream_xchacha20poly1305_TAG_FINAL` (`0x03`).
- An empty file is represented by one empty final chunk.
- Each ciphertext chunk is 17 bytes larger than its corresponding plaintext chunk due to secretstream authentication overhead.
- The complete 64-byte Cryptor header is supplied as associated data for every chunk.

Chunks are encrypted using `crypto_secretstream_xchacha20poly1305_push()`:

```text
ciphertext chunk length = plaintext chunk length + 17 bytes
```

Ciphertext chunks are concatenated directly after the 64-byte header. No separate chunk lengths or separators are stored.

Because every non-final plaintext chunk is exactly 65,536 bytes, every non-final ciphertext chunk is exactly 65,553 bytes. The remaining bytes at the end of the file form the final ciphertext chunk.

During decryption, each chunk is authenticated before its plaintext is written. Version 1 accepts only `TAG_MESSAGE` and `TAG_FINAL`.

A valid stream must satisfy all of the following:

- Every ciphertext chunk contains at least 17 bytes.
- Every non-final chunk uses `TAG_MESSAGE`.
- Exactly one chunk uses `TAG_FINAL`.
- The final authenticated chunk ends at the physical end of the file.
- A stream ending without `TAG_FINAL` is rejected.
- Data appearing after `TAG_FINAL` is rejected.
- Any authentication failure is treated as an incorrect password or corrupted file.

## File size

Let `N` be the plaintext file size in bytes.

The number of authenticated chunks is: `chunks = max(1, ceil(N / 65,536))`. Thus the total encrypted file size is: `N + 64 + (17 * chunks)` bytes.

The 64-byte addition is the Cryptor header. Each authenticated chunk adds a further 17 bytes.

## Validation requirements

A version 1 decryptor must validate the file before and during decryption.

The header must be rejected if:

- Fewer than 64 bytes are available.
- The signature is not exactly `CRYPTOR`.
- The format version is not `0x01`.
- The Argon2 operations limit is not `2`.
- The Argon2 memory limit is not `67,108,864` bytes.
- The secretstream header is invalid.

The Argon2 parameters must be validated before key derivation. This prevents an untrusted file from requesting arbitrary amounts of memory or computation.

An authentication failure cannot distinguish between an incorrect password and a corrupted or modified file. Both conditions are reported as a general decryption failure.
