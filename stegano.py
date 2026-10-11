import os
import secrets
import zlib
import numpy as np
from pathlib import Path
from PIL import Image, ImageOps
from datetime import datetime
import json
import hashlib
import re
import platform
import shutil
import tempfile
from typing import Optional, Tuple, Dict
import warnings
import uuid
warnings.filterwarnings('ignore', category=DeprecationWarning)

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives import hmac, hashes
from reedsolo import RSCodec, ReedSolomonError
from argon2.low_level import hash_secret_raw, Type
from scipy.fftpack import dct, idct
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# =============================================================================
# Configuration
# =============================================================================

MIN_IMAGE_WIDTH = 1920
MIN_IMAGE_HEIGHT = 1080
REDUNDANCY = 20
ECC_SYMBOLS = 32
ARGON_TIME_COST = 16
ARGON_MEMORY_COST = 524288  # KiB, i.e. 512 MiB
ARGON_PARALLELISM = 8
PASSWORD_LENGTH = 32
ENCRYPTION_IV_SIZE = 12
DCT_STRENGTH = 70

DCT_POSITIONS = [
    (4,1), (3,3), (4,4), (5,2),
    (3,4), (4,3), (5,3), (4,2)
]
BLOCK_SIZE = 8
MIN_STRENGTH = 45
MAX_STRENGTH = 90
COLOR_CHANNELS = ['Y', 'Cb', 'Cr']
SYNC_MARKER = "10110011100011110000"  # 20-bit pattern

# =============================================================================
# Secure Logger
# =============================================================================

class SecureLogger:
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.log_dir = self.base_dir / "logs"
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.operation_id = str(uuid.uuid4())
        self.log_file = self.log_dir / f"stego_log_{self.operation_id}_{self.timestamp}.txt"
        self.decrypt_info = {
            "version": "final",
            "operation_id": self.operation_id,
            "timestamp": self.timestamp,
            "password": None,
            "salt": None,
            "embedded_bits": None,
            "algorithm": {
                "encryption": "AES-256-GCM + ChaCha20Poly1305",
                "kdf": f"Argon2id(t={ARGON_TIME_COST},m={ARGON_MEMORY_COST})+Scrypt(N={2**20})+SHA3_256",
                "compression": "zlib-9",
                "ecc": f"Reed-Solomon-{ECC_SYMBOLS}",
                "dct_strength": DCT_STRENGTH
            },
            "system": {
                "platform": platform.system(),
                "python": platform.python_version(),
                "processor": platform.processor(),
                "machine": platform.machine()
            },
            "files": {},
            "metadata": {
                "time_utc": datetime.utcnow().isoformat(),
                "hostname": platform.node()
            }
        }

    def log(self, msg: str, level: str = "INFO", emoji: str = "ℹ️"):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        line = f"[{timestamp}] [{level}] {emoji} {msg}"
        print(line)
        with open(self.log_file, "a", encoding='utf-8') as f:
            f.write(line + "\n")

    def add_file_hash(self, path: str, file_type: str):
        with open(path, "rb") as f:
            h = hashlib.sha256(f.read()).hexdigest()
        self.decrypt_info["files"][file_type] = {
            "path": str(path),
            "sha256": h
        }

# =============================================================================
# Validation
# =============================================================================

def validate_image(image_path: str, allow_low_res: bool = False,
                   min_width: int = MIN_IMAGE_WIDTH, min_height: int = MIN_IMAGE_HEIGHT):
    img = Image.open(image_path)
    w, h = img.size
    img.close()
    if not allow_low_res and (w < min_width or h < min_height):
        raise ValueError(f"Image must be at least {min_width}x{min_height}, got {w}x{h}.")

def validate_password(password: str) -> bool:
    if len(password) < PASSWORD_LENGTH:
        return False
    patterns = [r'[A-Z]', r'[a-z]', r'[0-9]', r'[!@#$%^&*()_+<>\?]']
    return all(bool(re.search(p, password)) for p in patterns)

# =============================================================================
# Key Derivation & Encryption
# =============================================================================

def derive_keys(password: str, salt: bytes) -> Dict[str, bytes]:
    combined = password.encode() + salt
    argon_key = hash_secret_raw(
        secret=combined,
        salt=salt,
        time_cost=ARGON_TIME_COST,
        memory_cost=ARGON_MEMORY_COST,
        parallelism=ARGON_PARALLELISM,
        hash_len=32,
        type=Type.ID
    )
    kdf = Scrypt(salt=salt, length=32, n=2**20, r=8, p=1)
    scrypt_key = kdf.derive(argon_key)

    h = hashes.Hash(hashes.SHA3_256())
    h.update(scrypt_key)
    master_key = h.finalize()

    keys = {}
    for name, ctext in {
        "encryption": b"aes256gcm",
        "chacha": b"chacha20poly1305",
        "hmac": b"hmacsha256"
    }.items():
        hh = hmac.HMAC(master_key, hashes.SHA256())
        hh.update(ctext)
        keys[name] = hh.finalize()

    return keys

def encrypt_data(data: bytes, keys: Dict[str, bytes]) -> bytes:
    aes = AESGCM(keys['encryption'])
    iv1 = os.urandom(ENCRYPTION_IV_SIZE)
    aes_ct = aes.encrypt(iv1, data, None)

    chacha = ChaCha20Poly1305(keys['chacha'])
    iv2 = os.urandom(ENCRYPTION_IV_SIZE)
    final_ct = chacha.encrypt(iv2, aes_ct, None)
    return iv1 + iv2 + final_ct

def decrypt_data(ct: bytes, keys: Dict[str, bytes]) -> bytes:
    iv1 = ct[:ENCRYPTION_IV_SIZE]
    iv2 = ct[ENCRYPTION_IV_SIZE:2*ENCRYPTION_IV_SIZE]
    aes_ct = ct[2*ENCRYPTION_IV_SIZE:]

    chacha = ChaCha20Poly1305(keys['chacha'])
    raw_aes = chacha.decrypt(iv2, aes_ct, None)

    aes = AESGCM(keys['encryption'])
    return aes.decrypt(iv1, raw_aes, None)

def compute_hmac(hmac_key: bytes, data: bytes) -> bytes:
    hh = hmac.HMAC(hmac_key, hashes.SHA256())
    hh.update(data)
    return hh.finalize()

# =============================================================================
# Reed-Solomon & Data Prep
# =============================================================================

def add_error_correction(data: bytes) -> bytes:
    rsc = RSCodec(ECC_SYMBOLS)
    return rsc.encode(data)

def remove_error_correction(data: bytes) -> bytes:
    rsc = RSCodec(ECC_SYMBOLS)
    return rsc.decode(data)[0]

def prepare_data_for_embedding(plaintext: str, hmac_key: bytes) -> bytes:
    raw = plaintext.encode('utf-8')
    comp = zlib.compress(raw, level=9)
    ecc = add_error_correction(comp)
    mac = compute_hmac(hmac_key, ecc)
    return mac + ecc

def extract_and_verify_data(data: bytes, hmac_key: bytes, logger: Optional[SecureLogger]) -> Optional[str]:
    if len(data) < 32:
        return None
    stored_mac = data[:32]
    ecc = data[32:]
    check_mac = compute_hmac(hmac_key, ecc)
    if check_mac != stored_mac:
        return None
    try:
        dec_ecc = remove_error_correction(ecc)
        dec_data = zlib.decompress(dec_ecc)
        text = dec_data.decode('utf-8')
        if logger:
            logger.log("Successfully verified data (HMAC/ECC) and decompressed!", "INFO", "🔐")
        return text
    except:
        return None

# =============================================================================
# Bit Conversion
# =============================================================================

def bytes_to_binary(data: bytes) -> str:
    return ''.join(format(b, '08b') for b in data)

def binary_to_bytes(b_str: str) -> bytes:
    return int(b_str, 2).to_bytes((len(b_str)+7)//8, byteorder='big')

# =============================================================================
# Capacity Estimation & DCT
# =============================================================================

def estimate_capacity_dct(path: str) -> int:
    img = Image.open(path)
    w, h = img.size
    img.close()
    blk = BLOCK_SIZE
    h_blocks = h // blk
    w_blocks = w // blk
    return h_blocks * w_blocks * len(COLOR_CHANNELS)

def embed_data_dct(image_path: str, output_path: str, bitstring: str, strength: int = DCT_STRENGTH):
    """
    Embed bits into YCbCr channels via 2D DCT.
    """
    bitstring = SYNC_MARKER + bitstring
    img = Image.open(image_path).convert("YCbCr")
    chans = list(img.split())
    arrs = [np.array(c, dtype=np.float32) for c in chans]

    height, width = arrs[0].shape
    h_blocks = height // BLOCK_SIZE
    w_blocks = width // BLOCK_SIZE
    total_bits = len(bitstring)
    bits_per_chan = total_bits // len(arrs)

    idx_global = 0
    for chan_idx, arr in enumerate(arrs):
        start_bit = chan_idx * bits_per_chan
        end_bit = start_bit + bits_per_chan if chan_idx < len(arrs)-1 else total_bits
        c_bits = bitstring[start_bit:end_bit]
        bit_i = 0

        for by in range(h_blocks):
            for bx in range(w_blocks):
                if bit_i >= len(c_bits):
                    break
                block = arr[by*BLOCK_SIZE:(by+1)*BLOCK_SIZE, bx*BLOCK_SIZE:(bx+1)*BLOCK_SIZE]
                block_mean = np.mean(block)
                block_std = np.std(block)
                adaptive = np.clip(strength*(1 + block_std/max(block_mean,1)), MIN_STRENGTH, MAX_STRENGTH)

                dct_blk = dct(dct(block.T, norm='ortho').T, norm='ortho')
                b_val = int(c_bits[bit_i])
                embed_val = adaptive if b_val else -adaptive

                for pos in DCT_POSITIONS:
                    coeff = dct_blk[pos]
                    mag = abs(coeff)
                    scale = 1.0 + (mag / 255.0)
                    dct_blk[pos] = scale * embed_val

                idct_blk = idct(idct(dct_blk.T, norm='ortho').T, norm='ortho')
                arr[by*BLOCK_SIZE:(by+1)*BLOCK_SIZE, bx*BLOCK_SIZE:(bx+1)*BLOCK_SIZE] = idct_blk
                bit_i += 1
                idx_global += 1

    arrs = [np.clip(a, 0, 255).astype(np.uint8) for a in arrs]
    new_chans = [Image.fromarray(a, 'L') for a in arrs]
    out = Image.merge('YCbCr', new_chans).convert("RGB")
    out.save(output_path, "PNG", optimize=False)
    img.close()
    out.close()

def extract_data_dct(image_path: str, total_bits: int) -> str:
    """
    Extract bits from DCT blocks.
    """
    needed = total_bits + len(SYNC_MARKER)
    img = Image.open(image_path).convert("YCbCr")
    chans = list(img.split())
    arrs = [np.array(c, dtype=np.float32) for c in chans]
    height, width = arrs[0].shape
    h_blocks = height // BLOCK_SIZE
    w_blocks = width // BLOCK_SIZE
    bits_per_chan = needed // len(chans)
    if needed % len(chans):
        bits_per_chan += 1

    bits_collected = []
    for chan_idx, arr in enumerate(arrs):
        required = bits_per_chan if chan_idx < len(chans)-1 else (needed - bits_per_chan*(len(chans)-1))
        bit_i = 0

        for by in range(h_blocks):
            for bx in range(w_blocks):
                if bit_i >= required:
                    break
                blk = arr[by*BLOCK_SIZE:(by+1)*BLOCK_SIZE, bx*BLOCK_SIZE:(bx+1)*BLOCK_SIZE]
                dct_blk = dct(dct(blk.T, norm='ortho').T, norm='ortho')

                votes = []
                mags = []
                for pos in DCT_POSITIONS:
                    coeff = dct_blk[pos]
                    mags.append(abs(coeff))
                    votes.append(1 if coeff > 0 else 0)

                if sum(mags) > 0:
                    w_vote = sum(v * m for v,m in zip(votes,mags)) / sum(mags)
                    bit = '1' if w_vote > 0.5 else '0'
                else:
                    bit = '1' if votes.count(1) > len(votes)/2 else '0'

                bits_collected.append(bit)
                bit_i += 1

    img.close()
    raw_bits = ''.join(bits_collected[:needed])
    idx = raw_bits.find(SYNC_MARKER)
    if idx == -1:
        return ''
    # Return only the payload portion
    return raw_bits[idx+len(SYNC_MARKER):idx+len(SYNC_MARKER)+total_bits]

# =============================================================================
# Main API
# =============================================================================

def embed_data_into_image(
    image_path: str,
    output_path: str,
    data_str: str,
    password: str,
    allow_low_res: bool = False,
    redundancy: int = REDUNDANCY,
    logger: Optional[SecureLogger] = None
) -> Tuple[bytes, int, int, bytes]:
    if logger:
        logger.log("Validating image resolution...", "STEP", "🔍")
    validate_image(image_path, allow_low_res)

    if logger:
        logger.log("Estimating capacity...", "STEP", "📏")
    cap = estimate_capacity_dct(image_path)

    if logger:
        logger.log("Deriving keys...", "STEP", "🔑")
    salt = os.urandom(32)
    keys = derive_keys(password, salt)

    if logger:
        logger.log("Preparing data (compression + ECC + HMAC)...", "STEP", "🗜️")
    data_packed = prepare_data_for_embedding(data_str, keys['hmac'])

    if logger:
        logger.log("Encrypting data...", "STEP", "🔒")
    data_enc = encrypt_data(data_packed, keys)

    # Redundancy
    total_payload = data_enc * redundancy
    bitstring = bytes_to_binary(total_payload)
    needed_bits = len(bitstring)

    if logger:
        logger.log(f"Capacity: {cap} bits, Needed: {needed_bits} bits", "INFO", "📏")
    if needed_bits > cap:
        raise ValueError("Payload (with redundancy) is too large for this image.")

    if logger:
        logger.log("Performing DCT embedding...", "STEP", "🎨")
    embed_data_dct(image_path, output_path, bitstring, DCT_STRENGTH)
    return salt, needed_bits, redundancy, keys['hmac']

def extract_data_from_image(
    image_path: str,
    password: str,
    salt: bytes,
    expected_bits: int,
    redundancy: int = REDUNDANCY,
    logger: Optional[SecureLogger] = None,
    original_size: Optional[tuple] = None
) -> Tuple[Optional[str], bool]:
    # Derive keys
    if logger:
        logger.log("Deriving keys for extraction...", "STEP", "🔑")
    keys = derive_keys(password, salt)

    # Extract bits
    if logger:
        logger.log(f"Extracting {expected_bits} bits from image...", "STEP", "📤")
    raw_bits = extract_data_dct(image_path, expected_bits)
    if not raw_bits:
        if logger:
            logger.log("No bits found or SYNC_MARKER missing.", "ERROR", "❌")
        return None, False

    raw_bytes = binary_to_bytes(raw_bits)
    piece_len = len(raw_bytes) // redundancy

    # Attempt each redundancy block
    for i in range(redundancy):
        block = raw_bytes[i*piece_len:(i+1)*piece_len]
        try:
            dec = decrypt_data(block, keys)
            result = extract_and_verify_data(dec, keys['hmac'], logger)
            if result is not None:
                return result, True
        except Exception as e:
            if logger:
                logger.log(f"Block {i+1} decryption/HMAC error: {e}", "WARNING", "⚠️")

    # If all fail
    if logger:
        logger.log("All redundancy blocks failed. Extraction unsuccessful.", "ERROR", "❌")
    return None, False
