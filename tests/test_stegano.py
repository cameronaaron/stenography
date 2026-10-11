# SPDX-FileCopyrightText: 2026 Cameron Aaron
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Round trips through stegano.py with fixed keys; the real KDF needs >1 GiB."""

import os

import numpy as np
from PIL import Image

import stegano

KEYS = {"encryption": os.urandom(32), "chacha": os.urandom(32), "hmac": os.urandom(32)}


def test_encrypt_then_decrypt_returns_the_plaintext():
    assert stegano.decrypt_data(stegano.encrypt_data(b"hello", KEYS), KEYS) == b"hello"


def test_packed_message_verifies_and_rejects_tampering():
    packed = stegano.prepare_data_for_embedding("a secret", KEYS["hmac"])
    assert stegano.extract_and_verify_data(packed, KEYS["hmac"], None) == "a secret"
    tampered = packed[:-1] + bytes([packed[-1] ^ 1])
    assert stegano.extract_and_verify_data(tampered, KEYS["hmac"], None) is None


def test_bits_survive_embedding_in_an_image(tmp_path):
    rng = np.random.default_rng(1)
    src, out = tmp_path / "in.png", tmp_path / "out.png"
    Image.fromarray(rng.integers(60, 200, (256, 256, 3), dtype=np.uint8)).save(src)
    bits = stegano.bytes_to_binary(b"payload!")
    stegano.embed_data_dct(str(src), str(out), bits)
    assert stegano.extract_data_dct(str(out), len(bits)) == bits
