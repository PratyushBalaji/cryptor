# Cryptor unsafe mode

This document describes Cryptor's unsafe-mode construction, intended behaviour, and security limitations.

Unsafe mode is Cryptor's deterministic, involutive encryption mode. It applies the same operation for encryption and decryption: running it twice with the same password restores the original file.

It exists to demonstrate reversible stream encryption while preserving the exact file size.

## Construction

Unsafe mode uses the following fixed parameters:

| Parameter | Value |
|---|---|
| Password KDF | Argon2id v1.3 (`crypto_pwhash_ALG_ARGON2ID13`) |
| Argon2 operations limit | `2` |
| Argon2 memory limit | `67,108,864` bytes (64 MiB) |
| Argon2 parallelism | 1 lane |
| Derived key size | 32 bytes |
| Salt | ASCII `cryptor-salt-1.0` (16 bytes) |
| Cipher | XChaCha20 |
| Nonce | 24 zero bytes |
| Initial block counter | `0` |
| Processing chunk size | 65,536 bytes |

The password is used as its exact byte sequence, without a null terminator, encoding conversion, or Unicode normalisation. Argon2id derives a 32-byte XChaCha20 key using the parameters above.

XChaCha20 generates a pseudorandom keystream from the key, nonce, and block counter. Cryptor XORs it with the input:

```text
output = input XOR keystream
```

Because XOR is its own inverse:

```text
(input XOR keystream) XOR keystream = input
```

The block counter advances continuously across the file, so processing another 65,536-byte chunk does not restart the keystream.

The output is raw ciphertext with exactly the same size as the input. It contains no signature, header, stored parameters, authentication tag, or version information.

## Susceptible attacks

This section discusses unsafe mode's susceptibility to common attacks against encryption:

- Ciphertext comparison and keystream reuse
- Known-plaintext attacks
- Crib dragging
- Password guessing and rainbow tables
- Ciphertext tampering and forgery

The first three attacks require at least two files known to use the same key and nonce. A unique, sufficiently unpredictable password for every file prevents that condition. Password guessing and ciphertext tampering can each target a single file.

Unsafe mode has no random per-file salt or nonce. The fixed salt makes the same password derive the same key, while the all-zero nonce makes that key generate the same keystream for every file.

A nonce must not be reused with the same stream-cipher key. It normally lets one key generate a different keystream for each message; the unsafe static nonce supplies no such per-file uniqueness. The salt and nonce have separate roles: the salt affects Argon2id key derivation, while the nonce affects the XChaCha20 keystream.

### Ciphertext comparison and keystream reuse

Encrypting identical data with the same password produces identical ciphertext. Equal ciphertext ranges at equal file offsets therefore reveal equal plaintext ranges.

For two files encrypted with the same key:

```text
C1 = P1 XOR K
C2 = P2 XOR K
```

XORing the ciphertexts cancels the shared keystream:

```text
C1 XOR C2 = P1 XOR P2
```

Thus, if it is **known to an attacker** that two files were encoded in unsafe mode and used the same key, keystream reuse can expose relationships between their plaintexts, allow guessed or known content in one file to reveal corresponding content in the other, and reveal when equal plaintext occurs at equal offsets.

### Known-plaintext attacks

Known plaintext from one file exposes the corresponding keystream bytes:

```text
K = C1 XOR P1
P2 = C2 XOR K
```

Those bytes decrypt the same offsets in another file using the same key and nonce. Useful known plaintext may be only a file signature, standard header, document template, protocol field, or predictable fragment rather than the entire file.

The recovered keystream applies only at those offsets. XChaCha20 does not use a short repeating XOR key, so it does not expose unrelated positions within the file.

### Crib dragging

An attacker can calculate `P1 XOR P2`, slide a likely word or byte sequence across it, and inspect the resulting candidate bytes for the other plaintext. Natural-language and predictable structured files provide more useful clues than compressed or already-random-looking data.

The ciphertexts remain aligned by file offset so that matching keystream bytes cancel. The guessed plaintext is what moves across the combined XOR. This attack is not available from a single unsafe ciphertext because XChaCha20's keystream does not repeat within the file.

### Password guessing and rainbow tables

Cryptor-specific rainbow tables can map likely passwords to derived keys or fixed-nonce keystream prefixes. They need cover only plausible passwords, not the complete XChaCha20 key space.

The fixed construction makes such a table reusable across unsafe files. Although no password verifier is stored, recognisable file signatures, expected text, or other predictable plaintext can confirm a candidate. Argon2id is the expensive part of each new guess; after that, generating a short XChaCha20 keystream and XORing it with a ciphertext prefix is comparatively cheap.

A random per-file salt would prevent this reuse by requiring the Argon2id work to be repeated for every target.

### Ciphertext tampering and forgery

XOR encryption is malleable. Changing a ciphertext bit changes the corresponding plaintext bit after decryption.

If the original bytes are known and chosen replacement bytes are desired:

```text
delta = original XOR replacement
modified ciphertext = ciphertext XOR delta
```

The modified ciphertext decrypts to the replacement without revealing the password or key. This attack needs only one ciphertext.

Unsafe mode also cannot detect accidental corruption, truncation, extension, or an incorrect password. It always produces an output byte sequence.

Truncating the ciphertext produces the corresponding plaintext prefix. Appending ciphertext preserves the original plaintext and adds unauthenticated bytes after it.

## Operational limitations

Cryptor cannot distinguish unsafe ciphertext from plaintext, unrelated binary data, or ciphertext produced with another password. The absence of version information also means that changing the fixed salt, Argon2 parameters, nonce, cipher, or counter behaviour would make existing files undecryptable unless the original settings were selected externally.

Unsafe mode is appropriate for studying involutive stream encryption or when exact size preservation is specifically required. For ordinary file protection, safe mode should be used.
