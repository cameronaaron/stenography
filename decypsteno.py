import json
import argparse
from pathlib import Path
import sys
from typing import Optional
from datetime import datetime
import platform
import warnings
import hashlib
from PIL import Image as PILImage
warnings.filterwarnings('ignore', category=DeprecationWarning)

# Import required functions from yess.py
from yess import (
    SecureLogger,
    extract_data_from_image,
    Image
)

def parse_args():
    parser = argparse.ArgumentParser(description='Steganography Decryption Tool')
    parser.add_argument('--config', type=str, required=True, help='Path to decrypt info JSON file')
    parser.add_argument('--log', action='store_true', help='Enable detailed logging')
    parser.add_argument('--force', action='store_true', help='Force decryption even if hash mismatches')
    return parser.parse_args()

def load_config(config_path: str) -> dict:
    with open(config_path, 'r') as f:
        return json.load(f)

def get_file_hash(filepath: str) -> str:
    """Calculate SHA256 hash of file"""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def decrypt_from_config(config: dict, config_path: str, force: bool = False, logger: Optional[SecureLogger] = None) -> Optional[str]:
    try:
        if 'files' not in config or 'embedded_image' not in config['files']:
            if logger:
                logger.log("No embedded image information found in config", "ERROR", "❌")
            return None

        # Get config file directory and image path
        config_dir = Path(config_path).parent
        image_path = config['files']['embedded_image']['path']
        
        # First try relative to config directory
        final_path = config_dir / image_path
        
        if logger:
            logger.log(f"Config directory: {config_dir}", "DEBUG", "🔍")
            logger.log(f"Looking for image at: {final_path}", "DEBUG", "🔍")

        if not final_path.exists():
            if logger:
                logger.log(f"Image not found at: {final_path}", "ERROR", "❌")
            return None

        if logger:
            logger.log(f"Found image at: {final_path}", "INFO", "✅")

        # Log hash mismatch but continue
        if logger:
            image_hash = get_file_hash(str(final_path))
            expected_hash = config['files']['embedded_image']['sha256']
            logger.log(f"Image hash: {image_hash}", "DEBUG", "🔍")
            logger.log(f"Expected hash: {expected_hash}", "DEBUG", "🔍")
            
            if image_hash != expected_hash:
                logger.log("Image hash differs - continuing extraction attempt", "WARN", "⚠️")

        # Load and validate image
        try:
            img = PILImage.open(str(final_path))
            if logger:
                logger.log(f"Image size: {img.size}", "DEBUG", "🔍")
                logger.log(f"Image mode: {img.mode}", "DEBUG", "🔍")
                logger.log("Starting extraction process...", "INFO", "🔄")
        except Exception as e:
            if logger:
                logger.log(f"Failed to load image: {str(e)}", "ERROR", "❌")
            return None

        # Extract with minimal required parameters
        try:
            if logger:
                logger.log("Starting extraction with config parameters:", "INFO", "🔄")
                logger.log(f"- Bits: {config['embedded_bits']}", "DEBUG", "🔍")
                logger.log(f"- Redundancy: {config['algorithm']['redundancy']}", "DEBUG", "🔍")
                logger.log(f"- Encryption: {config['algorithm']['encryption']}", "DEBUG", "🔍")

            # Only use supported parameters
            extracted_text, success = extract_data_from_image(
                str(final_path),
                password=config['password'],
                salt=bytes.fromhex(config['salt']),
                expected_bits=config['embedded_bits'],
                redundancy=config['algorithm']['redundancy'],
                logger=logger,
                original_size=None
            )
            
            if success:
                if logger:
                    logger.log("Extraction successful!", "SUCCESS", "✅")
                return extracted_text
            else:
                if logger:
                    logger.log("Extraction failed - no valid data found", "ERROR", "❌")
                return None

        except TypeError as e:
            if logger:
                logger.log(f"Invalid parameter error: {str(e)}", "ERROR", "❌")
            return None
        except Exception as e:
            if logger:
                logger.log(f"Extraction error: {str(e)}", "ERROR", "❌")
            return None

    except Exception as e:
        if logger:
            logger.log(f"Critical error: {str(e)}", "ERROR", "❌")
        raise

def main():
    args = parse_args()
    
    # Setup logging if enabled
    logger = None
    if args.log:
        base_dir = Path(".").resolve()
        logger = SecureLogger(base_dir)
        logger.log("Starting decryption process...", "START", "🚀")

    try:
        # Load config
        if logger:
            logger.log(f"Loading config from: {args.config}", "INFO", "📄")
        config = load_config(args.config)

        # Attempt decryption with config path and force flag
        result = decrypt_from_config(config, args.config, force=args.force, logger=logger)

        if result:
            if logger:
                logger.log("Decryption successful!", "SUCCESS", "✅")
                logger.log("Decrypted message:", "RESULT", "📝")
            print("\nDecrypted message:")
            print("="*50)
            print(result)
            print("="*50)
            sys.exit(0)
        else:
            if logger:
                logger.log("Decryption failed", "ERROR", "❌")
            print("Decryption failed - no valid message could be extracted")
            sys.exit(1)

    except Exception as e:
        if logger:
            logger.log(f"Error during decryption: {str(e)}", "ERROR", "❌")
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()