import os
import sys
import secrets
import zlib
import numpy as np
from pathlib import Path
from PIL import Image, ImageFilter, ImageOps
from datetime import datetime
import json
import hashlib
import re
import platform
import shutil
import tempfile
from typing import Optional
import warnings
warnings.filterwarnings('ignore', category=DeprecationWarning)

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives import hmac, hashes
from reedsolo import RSCodec, ReedSolomonError
from argon2.low_level import hash_secret_raw, Type
from scipy.fftpack import dct, idct
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import tkinter as tk
from tkinter import filedialog

# ==============================
# Configuration Constants
# ==============================
MIN_IMAGE_WIDTH = 1920
MIN_IMAGE_HEIGHT = 1080
REDUNDANCY = 20
ECC_SYMBOLS = 32  # Ensure this is always less than the total message length
ARGON_TIME_COST = 16
ARGON_MEMORY_COST = 2097152  # KiB, i.e. 2 GiB
ARGON_PARALLELISM = 8
PASSWORD_LENGTH = 32
ENCRYPTION_IV_SIZE = 12
DCT_STRENGTH = 70

DCT_POSITIONS = [
    (4,1), (3,3), (4,4), (5,2),
    (3,4), (4,3), (5,3), (4,2)
]
SPATIAL_BLOCKS = 4
MIN_STRENGTH = 45
MAX_STRENGTH = 90
BLOCK_SIZE = 8
ADAPTIVE_THRESHOLD = 12
COLOR_CHANNELS = ['Y', 'Cb', 'Cr']
RS_SHORTENING = 0.85

SYNC_MARKER = "10110011100011110000"  # 20-bit fixed pattern

class SecureLogger:
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.log_dir = self.base_dir / "logs"
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file = self.log_dir / f"stego_log_{self.timestamp}.txt"
        self.decrypt_info = {
            "version": "final-simplified",
            "timestamp": self.timestamp,
            "password": None,
            "salt": None,
            "seed": None,
            "embedded_bits": None,
            "algorithm": {
                "encryption": "AES-256-GCM + ChaCha20Poly1305",
                "kdf": f"Argon2id(t={ARGON_TIME_COST},m={ARGON_MEMORY_COST})+Scrypt(N={2**20})+SHA3_256",
                "compression": "zlib-9",
                "ecc": f"Reed-Solomon-{ECC_SYMBOLS}",
                "dct_strength": DCT_STRENGTH,
                "hmac": "SHA256",
                "hmac_validation": True,
                "redundancy": REDUNDANCY
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

    def log(self, msg: str, level: str = "INFO", emoji: str = "ℹ️") -> None:
        timestamp = datetime.now().strftime("%Y-%d-%m %H:%M:%S.%f")[:-3]
        formatted = f"[{timestamp}] [{level}] {emoji} {msg}"
        print(formatted)
        with open(self.log_file, "a", encoding='utf-8') as f:
            f.write(formatted + "\n")

    def save_decrypt_info(self) -> Path:
        info_dir = self.base_dir / "output"
        info_dir.mkdir(parents=True, exist_ok=True)
        
        info_file = info_dir / f"decrypt_info_{self.timestamp}.json"
        backup_file = info_dir / f"decrypt_info_{self.timestamp}.backup.json"
        
        for file in [info_file, backup_file]:
            with open(file, "w") as f:
                json.dump(self.decrypt_info, f, indent=2)
            if platform.system() != "Windows":
                os.chmod(file, 0o600)
                
        self.log(f"Decrypt info saved to: {info_file}", "INFO", "💾")
        self.log(f"Backup saved to: {backup_file}", "INFO", "📑")
        return info_file

    def add_file_hash(self, filepath, file_type):
        with open(filepath, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        self.decrypt_info["files"][file_type] = {
            "path": str(filepath),
            "sha256": file_hash
        }

def add_error_correction(data: bytes) -> bytes:
    # ECC_SYMBOLS is fixed small and guaranteed to be < len(data).
    rsc = RSCodec(ECC_SYMBOLS)
    return rsc.encode(data)

def remove_error_correction(data: bytes) -> bytes:
    rsc = RSCodec(ECC_SYMBOLS)
    return rsc.decode(data)[0]

def validate_image(image_path, allow_low_res=False, min_width=MIN_IMAGE_WIDTH, min_height=MIN_IMAGE_HEIGHT):
    img = Image.open(image_path)
    width, height = img.size
    img.close()
    if not allow_low_res and (width < min_width or height < min_height):
        raise ValueError(f"Image {image_path} must be at least {min_width}x{min_height}. Current: {width}x{height}")

def validate_password(password: str) -> bool:
    if len(password) < PASSWORD_LENGTH: return False
    patterns = [r'[A-Z]', r'[a-z]', r'[0-9]', r'[!@#$%^&*()_+<>\?]']
    return all(bool(re.search(pattern, password)) for pattern in patterns)

def derive_keys(password: str, salt: bytes) -> dict:
    combined_input = password.encode() + salt
    argon_key = hash_secret_raw(
        secret=combined_input,
        salt=salt,
        time_cost=ARGON_TIME_COST,
        memory_cost=ARGON_MEMORY_COST,
        parallelism=ARGON_PARALLELISM,
        hash_len=32,
        type=Type.ID
    )
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**20,
        r=8,
        p=1
    )
    scrypt_key = kdf.derive(argon_key)
    
    h = hashes.Hash(hashes.SHA3_256())
    h.update(scrypt_key)
    master_key = h.finalize()
    
    keys = {}
    contexts = {
        'encryption': b'aes256gcm',
        'chacha': b'chacha20poly1305',
        'hmac': b'hmacsha256'
    }
    
    for key_name, context in contexts.items():
        hmac_key = hmac.HMAC(master_key, hashes.SHA256())
        hmac_key.update(context)
        keys[key_name] = hmac_key.finalize()
    
    assert len(keys['encryption']) == 32
    assert len(keys['chacha']) == 32
    assert len(keys['hmac']) == 32
    return keys

def encrypt_data(data: bytes, keys: dict) -> bytes:
    aesgcm = AESGCM(keys['encryption'])
    iv1 = os.urandom(ENCRYPTION_IV_SIZE)
    aes_ct = aesgcm.encrypt(iv1, data, None)
    
    chacha = ChaCha20Poly1305(keys['chacha'])
    iv2 = os.urandom(ENCRYPTION_IV_SIZE)
    final_ct = chacha.encrypt(iv2, aes_ct, None)
    
    return iv1 + iv2 + final_ct

def decrypt_data(encrypted_data: bytes, keys: dict) -> bytes:
    iv1 = encrypted_data[:ENCRYPTION_IV_SIZE]
    iv2 = encrypted_data[ENCRYPTION_IV_SIZE:2*ENCRYPTION_IV_SIZE]
    ct = encrypted_data[2*ENCRYPTION_IV_SIZE:]
    
    chacha = ChaCha20Poly1305(keys['chacha'])
    aes_ct = chacha.decrypt(iv2, ct, None)
    
    aesgcm = AESGCM(keys['encryption'])
    return aesgcm.decrypt(iv1, aes_ct, None)

def compute_hmac(hmac_key: bytes, data: bytes) -> bytes:
    h = hmac.HMAC(hmac_key, hashes.SHA256())
    h.update(data)
    return h.finalize()

def bytes_to_binary(byte_data: bytes) -> str:
    return ''.join(format(b, '08b') for b in byte_data)

def binary_to_bytes(binary_data: str) -> bytes:
    return int(binary_data, 2).to_bytes((len(binary_data) + 7) // 8, byteorder='big')

def estimate_capacity_dct(image_path: str) -> int:
    img = Image.open(image_path)
    width, height = img.size
    img.close()
    block_size = 8
    h_blocks = height // block_size
    w_blocks = width // block_size
    return h_blocks * w_blocks * len(COLOR_CHANNELS)

def embed_data_dct(image_path: str, output_path: str, bitstring: str, strength: int = DCT_STRENGTH) -> None:
    # Merge sync marker at the start of bitstring
    bitstring = SYNC_MARKER + bitstring

    img = Image.open(image_path).convert("YCbCr")
    channels = list(img.split())
    channel_arrays = [np.array(channel, dtype=np.float32) for channel in channels]
    
    height, width = channel_arrays[0].shape
    h_blocks = height // BLOCK_SIZE
    w_blocks = width // BLOCK_SIZE
    total_bits = len(bitstring)
    bits_per_channel = total_bits // len(channels)
    
    for channel_idx, channel_arr in enumerate(channel_arrays):
        start_bit = channel_idx * bits_per_channel
        end_bit = start_bit + bits_per_channel
        channel_bits = bitstring[start_bit:end_bit] if channel_idx < len(channels)-1 else bitstring[start_bit:]
        
        bit_idx = 0
        for by in range(h_blocks):
            for bx in range(w_blocks):
                if bit_idx >= len(channel_bits):
                    break
                block = channel_arr[by*BLOCK_SIZE:(by+1)*BLOCK_SIZE, bx*BLOCK_SIZE:(bx+1)*BLOCK_SIZE]

                block_mean = np.mean(block)
                block_std = np.std(block)
                adaptive_strength = np.clip(
                    strength * (1 + block_std/max(block_mean, 1)),
                    MIN_STRENGTH, MAX_STRENGTH
                )
                
                dct_block = dct(dct(block.T, norm='ortho').T, norm='ortho')
                
                bit = int(channel_bits[bit_idx])
                embed_value = adaptive_strength if bit else -adaptive_strength
                
                for pos in DCT_POSITIONS:
                    coeff = dct_block[pos]
                    magnitude = abs(coeff)
                    scale = 1.0 + (magnitude / 255.0)
                    dct_block[pos] = scale * embed_value
                
                idct_block = idct(idct(dct_block.T, norm='ortho').T, norm='ortho')
                channel_arr[by*BLOCK_SIZE:(by+1)*BLOCK_SIZE, bx*BLOCK_SIZE:(bx+1)*BLOCK_SIZE] = idct_block
                bit_idx += 1

        channel_arrays[channel_idx] = np.clip(channel_arr, 0, 255).astype(np.uint8)
    
    channels_new = [Image.fromarray(arr, 'L') for arr in channel_arrays]
    img_new = Image.merge('YCbCr', channels_new).convert("RGB")
    img_new.save(output_path, "PNG", optimize=False)
    img.close()
    img_new.close()

def extract_data_dct(image_path: str, num_bits: int) -> str:
    extended_bits = num_bits + len(SYNC_MARKER)
    
    img = Image.open(image_path).convert("YCbCr")
    channels = list(img.split())
    bits_per_channel = extended_bits // len(channels)
    remainder = extended_bits % len(channels)
    if remainder > 0:
        bits_per_channel += 1
    all_bits = []
    
    for channel_idx, channel in enumerate(channels):
        channel_arr = np.array(channel, dtype=np.float32)
        height, width = channel_arr.shape
        h_blocks = height // BLOCK_SIZE
        w_blocks = width // BLOCK_SIZE
        
        channel_bits = []
        bit_idx = 0
        needed = bits_per_channel if channel_idx < len(channels)-1 else (extended_bits - bits_per_channel*(len(channels)-1))
        
        for by in range(h_blocks):
            for bx in range(w_blocks):
                if bit_idx >= needed:
                    break
                
                block = channel_arr[by*BLOCK_SIZE:(by+1)*BLOCK_SIZE, bx*BLOCK_SIZE:(bx+1)*BLOCK_SIZE]
                dct_block = dct(dct(block.T, norm='ortho').T, norm='ortho')
                
                votes = []
                magnitudes = []
                
                for pos in DCT_POSITIONS:
                    coeff = dct_block[pos]
                    mag = abs(coeff)
                    magnitudes.append(mag)
                    votes.append(1 if coeff > 0 else 0)
                
                if sum(magnitudes) > 0:
                    weighted_vote = sum(v * m for v, m in zip(votes, magnitudes)) / sum(magnitudes)
                    bit = '1' if weighted_vote > 0.5 else '0'
                else:
                    bit = '1' if votes.count(1) > len(votes)/2 else '0'
                    
                channel_bits.append(bit)
                bit_idx += 1
                
        all_bits.extend(channel_bits)
    
    img.close()
    extracted = ''.join(all_bits[:extended_bits])
    idx = extracted.find(SYNC_MARKER)
    if idx == -1:
        return ''
    return extracted[idx+len(SYNC_MARKER):idx+len(SYNC_MARKER)+num_bits]

def simulate_compression(input_path: str, output_path: str, format: str = "JPEG", quality: Optional[int] = 85) -> None:
    img = Image.open(input_path).convert('RGB')
    if format == "JPEG":
        img.save(output_path, "JPEG", quality=quality, optimize=True)
    elif format == "PNG":
        img.save(output_path, "PNG", optimize=True)
    elif format == "WEBP":
        img.save(output_path, "WEBP", quality=quality)
    img.close()

def prepare_data_for_embedding(data_str: str, hmac_key: bytes) -> bytes:
    data_bytes = data_str.encode('utf-8')
    compressed = zlib.compress(data_bytes, level=9)
    # ECC_SYMBOLS=32 is guaranteed smaller than message length
    ecc_data = add_error_correction(compressed)
    data_hmac = compute_hmac(hmac_key, ecc_data)
    return data_hmac + ecc_data

def attempt_partial_extraction(logger: SecureLogger, ecc_data: bytes, hmac_key: bytes) -> None:
    logger.log("Attempting partial/heuristic extraction without HMAC verification...", "WARNING", "⚠️")
    try:
        cleaned = remove_error_correction(ecc_data)
        try:
            decompressed = zlib.decompress(cleaned)
            try:
                extracted_str = decompressed.decode('utf-8', errors='replace')
                logger.log("Partial extraction success (no HMAC):", "INFO", "🔍")
                logger.log(f"Extracted (possibly corrupted): {extracted_str[:500]}", "INFO", "🔎")
            except:
                logger.log("Decompression succeeded but UTF-8 decoding failed. Printing partial hex:", "INFO", "🔎")
                logger.log(cleaned.hex()[:500], "INFO", "🧩")
        except zlib.error:
            logger.log("Decompression failed. Printing partial raw hex from ECC-cleaned data:", "INFO", "🧩")
            logger.log(cleaned.hex()[:500], "INFO", "🧪")
    except ReedSolomonError:
        logger.log("ECC decoding failed. The data is highly corrupted.", "ERROR", "💔")
        logger.log("Printing raw ECC data as hex (without HMAC verification):", "INFO", "🧪")
        logger.log(ecc_data.hex()[:500], "INFO", "📜")

def extract_and_verify_data(data: bytes, hmac_key: bytes, logger: SecureLogger) -> Optional[str]:
    if len(data) < 32:
        return None
    data_hmac = data[:32]
    ecc_data = data[32:]
    computed_hmac = compute_hmac(hmac_key, ecc_data)
    if computed_hmac != data_hmac:
        return None
    try:
        cleaned = remove_error_correction(ecc_data)
        decompressed = zlib.decompress(cleaned)
        extracted_str = decompressed.decode('utf-8')
        logger.log("HMAC verified and data successfully decompressed and decoded.", "INFO", "🔐")
        logger.log("Extracted Text:", "INFO", "📝")
        logger.log(extracted_str, "INFO", "📜")
        return extracted_str
    except:
        return None

def try_fallbacks_for_extraction(image_path: str, password: str, salt: bytes, expected_bits: int, redundancy: int, hmac_key: bytes, original_size: tuple, logger: SecureLogger) -> Optional[str]:
    def attempt_extract(img: Image.Image) -> Optional[str]:
        temp_path = Path(tempfile.gettempdir()) / ("fallback_" + os.path.basename(image_path))
        img.save(temp_path, "PNG", optimize=True)
        extracted_bits = extract_data_dct(str(temp_path), expected_bits)
        if not extracted_bits:
            return None
        extracted_bytes = binary_to_bytes(extracted_bits)
        single_length = len(extracted_bytes) // redundancy
        for i in range(redundancy):
            part = extracted_bytes[i*single_length:(i+1)*single_length]
            try:
                keys = derive_keys(password, salt)
                decrypted = decrypt_data(part, keys)
                result = extract_and_verify_data(decrypted, keys['hmac'], logger)
                if result is not None:
                    return result
            except:
                continue
        return None

    img = Image.open(image_path)
    for angle in [90, 180, 270]:
        logger.log(f"Trying fallback rotation by {angle} degrees...", "INFO", "🔄")
        rotated = img.rotate(angle, expand=True)
        res = attempt_extract(rotated)
        if res:
            return res

    if img.size != original_size:
        logger.log("Attempting to resize image back to original dimensions...", "INFO", "🖌️")
        resized = img.resize(original_size, Image.Resampling.LANCZOS)
        res = attempt_extract(resized)
        if res:
            return res

    logger.log("Attempting contrast normalization...", "INFO", "🔄")
    eq_img = ImageOps.autocontrast(img)
    res = attempt_extract(eq_img)
    if res:
        return res

    return None

def embed_data_into_image(image_path: str, output_path: str, data_str: str, password: str, allow_low_res: bool = False, redundancy: int = REDUNDANCY, logger: Optional[SecureLogger] = None) -> tuple:
    if logger:
        logger.log("Validating image...", "STEP", "🔍")
    validate_image(image_path, allow_low_res=allow_low_res)

    if logger:
        logger.log("Estimating capacity...", "STEP", "🔍")
    capacity = estimate_capacity_dct(image_path)

    if logger:
        logger.log("Generating salt and deriving keys...", "STEP", "🔑")
    salt = os.urandom(32)
    keys = derive_keys(password, salt)

    if logger:
        logger.log("Preparing data for embedding (compression, ECC, HMAC)...", "STEP", "🗜️")
    prepared = prepare_data_for_embedding(data_str, keys['hmac'])

    if logger:
        logger.log("Encrypting data...", "STEP", "🔒")
    encrypted = encrypt_data(prepared, keys)
    
    total_payload = encrypted * redundancy
    binary_data = bytes_to_binary(total_payload)
    needed_bits = len(binary_data)

    if logger:
        logger.log(f"Image capacity: {capacity} bits", "INFO", "📏")
        logger.log(f"Needed bits: {needed_bits} bits", "INFO", "📏")

    if needed_bits > capacity:
        if logger:
            logger.log("Data too large for this image. Consider a larger image or shorter message.", "ERROR", "⚠️")
        raise ValueError("Data (with redundancy) too large for this image's capacity.")

    if logger:
        logger.log("Embedding data into image via DCT modifications...", "STEP", "🖌️")
    embed_data_dct(image_path, output_path, binary_data, DCT_STRENGTH)

    return salt, needed_bits, redundancy, keys['hmac']

def extract_data_from_image(image_path: str, password: str, salt: bytes, expected_bits: int, redundancy: int = REDUNDANCY, logger: Optional[SecureLogger] = None, original_size: Optional[tuple] = None) -> tuple:
    if not os.path.exists(image_path):
        if logger:
            logger.log(f"Image not found: {image_path}", "ERROR", "❌")
        return None, False

    if logger:
        logger.log("Deriving keys for extraction...", "STEP", "🔑")
    keys = derive_keys(password, salt)

    if logger:
        logger.log(f"Extracting {expected_bits} bits from image...", "STEP", "📤")
    extracted_bits = extract_data_dct(
        image_path=image_path,
        num_bits=expected_bits
    )

    if not extracted_bits:
        if logger:
            logger.log("No bits extracted initially. Trying fallback methods...", "INFO", "🔄")
        result = try_fallbacks_for_extraction(image_path, password, salt, expected_bits, redundancy, keys['hmac'], original_size if original_size else Image.open(image_path).size, logger)
        if result:
            return result, True
        if logger:
            logger.log("Fallback attempts failed.", "ERROR", "❌")
        return None, False
        
    extracted_bytes = binary_to_bytes(extracted_bits)
    single_length = len(extracted_bytes) // redundancy

    if logger:
        logger.log("Attempting to decrypt and verify data from redundant copies...", "STEP", "🔍")

    for i in range(redundancy):
        part = extracted_bytes[i*single_length:(i+1)*single_length]
        try:
            decrypted = decrypt_data(part, keys)
            result = extract_and_verify_data(decrypted, keys['hmac'], logger)
            if result is not None:
                if logger:
                    logger.log("Successfully verified and extracted data!", "SUCCESS", "✅")
                return result, True
        except Exception as e:
            if logger:
                logger.log(f"Redundancy block {i+1} failed to verify: {e}", "WARNING", "⚠️")

    if logger:
        logger.log("All redundancy blocks failed. Attempting fallback methods...", "INFO", "🔍")
    fallback_result = try_fallbacks_for_extraction(image_path, password, salt, expected_bits, redundancy, keys['hmac'], original_size if original_size else Image.open(image_path).size, logger)
    if fallback_result:
        return fallback_result, True

    if logger:
        logger.log("All redundancy blocks and fallbacks failed. Attempting partial extraction...", "INFO", "🔍")
    first_part = extracted_bytes[:single_length]
    if len(first_part) > 32:
        attempt_partial_extraction(logger, first_part[32:], keys['hmac'])
            
    return None, False

def select_image() -> Optional[str]:
    root = tk.Tk()
    root.withdraw()
    file_path = filedialog.askopenfilename(
        title="Select Image",
        filetypes=[
            ("Image files", "*.png *.jpg *.jpeg *.bmp *.tiff *.webp"),
            ("All files", "*.*")
        ]
    )
    return file_path if file_path else None

def main():
    base_dir = Path(".").resolve()
    logger = SecureLogger(base_dir)

    logger.log("Starting steganography process...", "START", "🚀")
    logger.log("="*80, "SEPARATOR", "📋")

    input_image_path = select_image()
    if not input_image_path:
        logger.log("No image selected. Exiting...", "ERROR", "❌")
        return

    if not os.path.isfile(input_image_path):
        logger.log("Selected image does not exist. Exiting...", "ERROR", "❌")
        return

    output_dir = base_dir / "output"
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    embedded_image_name = f"embedded_{timestamp}.png"
    embedded_path = output_dir / embedded_image_name

    secret_text = "This is a very secret message that should remain hidden even after compression and manipulations."
    # Generate a very strong password
    logger.log("Generating a strong password...", "STEP", "🔑")
    while True:
        password = ''.join(secrets.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+<>?') for _ in range(PASSWORD_LENGTH))
        if validate_password(password):
            break

    logger.log(f"Generated secure password: {password}", "SECURITY", "🔑")
    logger.decrypt_info["password"] = password

    original_img = Image.open(input_image_path)
    original_size = original_img.size
    original_img.close()

    logger.add_file_hash(input_image_path, "original_image")

    logger.log("Embedding data into the image...", "STEP", "📥")
    try:
        salt, embedded_bits, used_redundancy, hmac_key = embed_data_into_image(
            input_image_path, 
            embedded_path, 
            secret_text, 
            password, 
            allow_low_res=True, 
            redundancy=REDUNDANCY,
            logger=logger
        )
    except ValueError as ve:
        logger.log(str(ve), "ERROR", "❌")
        return

    logger.decrypt_info["salt"] = salt.hex()
    logger.decrypt_info["embedded_bits"] = embedded_bits
    logger.decrypt_info["algorithm"]["redundancy"] = used_redundancy

    logger.add_file_hash(embedded_path, "embedded_image")

    logger.log("Verifying extraction before any compression...", "STEP", "🔧")
    extracted_data_pre, success_pre = extract_data_from_image(
        str(embedded_path), 
        password, 
        salt, 
        embedded_bits, 
        redundancy=used_redundancy,
        logger=logger,
        original_size=original_size
    )

    if success_pre and extracted_data_pre is not None and extracted_data_pre == secret_text:
        logger.log("Perfect extraction and integrity match before compression!", "SUCCESS", "🔐")
    else:
        logger.log("Pre-compression extraction failed or mismatched.", "ERROR", "❌")

    compression_tests = [
        ("JPEG", [95, 85, 75, 50, 30]),
        ("PNG", [None]),
        ("WEBP", [95, 80, 60, 40])
    ]

    for fmt, qualities in compression_tests:
        for q in qualities:
            if q is None:
                compressed_name = f"test_{fmt}_{timestamp}.png"
                compressed_path = output_dir / compressed_name
                logger.log(f"Simulating {fmt} compression (no quality param)...", "PROCESS", "🗜️")
                simulate_compression(str(embedded_path), str(compressed_path), format=fmt)
            else:
                ext = fmt.lower() if fmt != "WEBP" else "webp"
                compressed_name = f"test_{fmt}_{q}_{timestamp}.{ext}"
                compressed_path = output_dir / compressed_name
                logger.log(f"Simulating {fmt} compression at quality={q}...", "PROCESS", "🗜️")
                simulate_compression(str(embedded_path), str(compressed_path), format=fmt, quality=q)

            logger.add_file_hash(compressed_path, f"compressed_{fmt}_{q}")
            
            logger.log(f"Attempting extraction after {fmt} compression (quality={q})...", "STEP", "📤")
            extracted_data, success = extract_data_from_image(
                str(compressed_path), 
                password, 
                salt, 
                embedded_bits, 
                redundancy=used_redundancy,
                logger=logger,
                original_size=original_size
            )

            if success and extracted_data is not None:
                if extracted_data == secret_text:
                    logger.log(f"Perfect extraction after {fmt} compression (quality={q})!", "SUCCESS", "✅")
                else:
                    logger.log(f"Extraction succeeded after {fmt} compression (quality={q}), but message differs slightly. HMAC verified though.", "WARNING", "⚠️")
            else:
                logger.log(f"Extraction failed or corrupted after {fmt} compression (quality={q}).", "ERROR", "❌")

    manipulation_stats = {
        "total_tests": 0,
        "successful": 0,
        "failed": 0,
        "partial": 0,
        "results": []
    }

    extended_compression_tests = [
        ("JPEG", [99, 98, 95, 90, 85, 80, 75, 70, 60, 50, 40, 30, 20, 10]),
        ("PNG", [None]),
        ("WEBP", [100, 95, 90, 85, 80, 75, 70, 60, 50, 40, 30, 20])
    ]

    logger.log("Starting comprehensive resilience testing...", "TEST", "🧪")

    # Test compression
    for fmt, qualities in extended_compression_tests:
        for q in qualities:
            manipulation_stats["total_tests"] += 1
            test_name = f"{fmt}_q{q}" if q else fmt
            if q is None and fmt == "PNG":
                compressed_path = output_dir / f"test_{test_name}_{timestamp}.png"
                logger.log(f"Testing {test_name}...", "TEST", "🔄")
                simulate_compression(str(embedded_path), str(compressed_path), format=fmt)
            else:
                ext = fmt.lower() if fmt != "WEBP" else "webp"
                compressed_path = output_dir / f"test_{test_name}_{timestamp}.{ext}"
                logger.log(f"Testing {test_name}...", "TEST", "🔄")
                simulate_compression(str(embedded_path), str(compressed_path), format=fmt, quality=q)

            extracted_data, success = extract_data_from_image(
                str(compressed_path), 
                password, 
                salt, 
                embedded_bits,
                redundancy=used_redundancy,
                logger=logger,
                original_size=original_size
            )

            result = {
                "test": test_name,
                "type": "compression",
                "success": success,
                "match": extracted_data == secret_text if extracted_data else False
            }
            manipulation_stats["results"].append(result)
            
            if success and result["match"]:
                manipulation_stats["successful"] += 1
            elif success:
                manipulation_stats["partial"] += 1
            else:
                manipulation_stats["failed"] += 1

    manipulation_tests = [
        ("resize_up", lambda img: img.resize((int(img.width*1.2), int(img.height*1.2)), Image.Resampling.LANCZOS)),
        ("resize_down", lambda img: img.resize((int(img.width*0.8), int(img.height*0.8)), Image.Resampling.LANCZOS)),
        ("rotate_90", lambda img: img.rotate(90, expand=True)),
        ("rotate_180", lambda img: img.rotate(180)),
        ("brightness_up", lambda img: Image.fromarray(np.clip(np.array(img) * 1.2, 0, 255).astype(np.uint8))),
        ("brightness_down", lambda img: Image.fromarray(np.clip(np.array(img) * 0.8, 0, 255).astype(np.uint8))),
        ("contrast_up", lambda img: Image.fromarray(np.clip((np.array(img) - 128) * 1.2 + 128, 0, 255).astype(np.uint8))),
        ("contrast_down", lambda img: Image.fromarray(np.clip((np.array(img) - 128) * 0.8 + 128, 0, 255).astype(np.uint8))),
        ("blur", lambda img: img.filter(ImageFilter.GaussianBlur(radius=1))),
        ("sharpen", lambda img: img.filter(ImageFilter.SHARPEN)),
    ]

    for test_name, manipulation in manipulation_tests:
        manipulation_stats["total_tests"] += 1
        manipulated_path = output_dir / f"test_manipulated_{test_name}_{timestamp}.png"
        
        logger.log(f"Testing {test_name}...", "TEST", "🔄")
        
        try:
            img = Image.open(str(embedded_path))
            manipulated = manipulation(img)
            manipulated.save(str(manipulated_path), "PNG", optimize=True)
            img.close()
            manipulated.close()

            extracted_data, success = extract_data_from_image(
                str(manipulated_path),
                password,
                salt,
                embedded_bits,
                redundancy=used_redundancy,
                logger=logger,
                original_size=original_size
            )

            result = {
                "test": test_name,
                "type": "manipulation",
                "success": success,
                "match": extracted_data == secret_text if extracted_data else False
            }
            manipulation_stats["results"].append(result)
            
            if success and result["match"]:
                manipulation_stats["successful"] += 1
            elif success:
                manipulation_stats["partial"] += 1
            else:
                manipulation_stats["failed"] += 1

        except Exception as e:
            logger.log(f"Error during {test_name}: {str(e)}", "ERROR", "❌")
            manipulation_stats["failed"] += 1

    logger.log("\n" + "="*50, "REPORT", "📊")
    logger.log("FINAL RESILIENCE REPORT", "REPORT", "📈")
    logger.log("="*50, "REPORT", "📊")
    logger.log(f"Total Tests Run: {manipulation_stats['total_tests']}", "REPORT", "📋")
    logger.log(f"Successful: {manipulation_stats['successful']} ({(manipulation_stats['successful']/manipulation_stats['total_tests']*100):.1f}%)", "REPORT", "✅")
    logger.log(f"Partial Success: {manipulation_stats['partial']} ({(manipulation_stats['partial']/manipulation_stats['total_tests']*100):.1f}%)", "REPORT", "⚠️")
    logger.log(f"Failed: {manipulation_stats['failed']} ({(manipulation_stats['failed']/manipulation_stats['total_tests']*100):.1f}%)", "REPORT", "❌")
    
    logger.log("\nDetailed Results:", "REPORT", "📝")
    for result in manipulation_stats["results"]:
        if result["success"] and result["match"]:
            status = "✅"
        elif result["success"]:
            status = "⚠️"
        else:
            status = "❌"
        logger.log(f"{status} {result['type'].title()}: {result['test']}", "REPORT", "📋")
    
    logger.log("\nRecommended Quality Settings:", "REPORT", "💡")
    successful_compressions = [r for r in manipulation_stats["results"] 
                             if r["type"] == "compression" and r["match"]]
    if successful_compressions:
        logger.log("Compression tests were successful. Recommended settings:", "REPORT", "💡")
        for result in successful_compressions:
            logger.log(f"Format: {result['test']}", "REPORT", "📋")

    info_file = logger.save_decrypt_info()
    logger.log("All processes completed.", "END", "💾")

    logger.log("Cleaning up temporary files...", "INFO", "🧹")
    temp_dir = tempfile.mkdtemp()
    try:
        shutil.rmtree(temp_dir, ignore_errors=True)
    except Exception as e:
        logger.log(f"Cleanup warning: {str(e)}", "WARNING", "⚠️")

    logger.log("Done.", "END", "🏁")

if __name__ == "__main__":
    main()
