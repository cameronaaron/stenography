# stenography

A Discord bot that hides text inside images. `/stego encode` encrypts a
message under a generated password and embeds it in an image's DCT
coefficients; `/stego decode` and `/stego decode_manual` recover it.

## How a message is hidden

1. **Keys.** Argon2id (t=16, 512 MiB) feeds scrypt (N=2^20), whose output is
   hashed with SHA3-256 and split by HMAC into an AES key, a ChaCha20 key and
   an HMAC key.
2. **Packing.** The text is zlib-compressed, protected with 32 Reed-Solomon
   symbols and prefixed with an HMAC.
3. **Encryption.** AES-256-GCM, then ChaCha20-Poly1305 over the result.
4. **Embedding.** The ciphertext is repeated 20 times and written one bit per
   8×8 block across the Y, Cb and Cr channels, by setting eight mid-frequency
   DCT coefficients. A 20-bit sync marker leads the bits. Extraction tries
   each copy until one decrypts and verifies.

Images must be at least 1920×1080 unless low-resolution input is allowed; the
bot allows it.

## Limitations

- The bot keeps every message's password and salt in plain text in
  `storage.json`, so whoever runs it can read every hidden message.
- The bot reports each operation (user, time, and the encoded image's URL) to
  the configured webhook.
- `stegano.py` is the library the bot uses. `yess.py` is an earlier
  experimental copy with a compression-robustness test harness, and
  `decypsteno.py` decodes with it. The copies have diverged (for example,
  Argon2 memory of 2 GiB rather than 512 MiB), so `decypsteno.py` cannot
  decode images the bot made.

## Run

```sh
pip install -r requirements.txt
cp .env.example .env          # fill in the bot token, app id and webhook URL
python discordbot.py
```

`cloud-init.example.yml` provisions a server that runs the bot under
systemd; fill in your own SSH and deploy keys and keep that copy out of git.

## Test

```sh
pip install pytest -r requirements.txt
pytest
```

The tests cover encryption, packing and the DCT round trip with fixed keys;
they skip the key derivation, which needs over a gigabyte of memory.

## License

[AGPL-3.0-or-later](LICENSE).
