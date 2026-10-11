import discord
from discord.ext import commands, tasks
from discord import app_commands
import aiohttp
import tempfile
import os
from pathlib import Path
import asyncio
from typing import Optional, Tuple
from datetime import datetime
import json
import logging
import secrets
import uuid
import socket
import warnings
import sys
import time
import dns.resolver
from dotenv import load_dotenv

load_dotenv()

# 1) Global, persistent process pool
from concurrent.futures import ProcessPoolExecutor

# Create a single pool at the module level
PROCESS_POOL = ProcessPoolExecutor(max_workers=4)

# Import the steganography functions from stegano.py
from stegano import (
    embed_data_into_image,
    extract_data_from_image,
    validate_image,
    SecureLogger,
    PASSWORD_LENGTH,
    validate_password,
)

##############################################################################
# Helpers
##############################################################################

async def run_in_process_pool(func, *args):
    """
    Run CPU-intensive function in a persistent process pool so we do NOT block
    the main event loop or spawn new processes every time.
    """
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(PROCESS_POOL, func, *args)

async def check_dns_connectivity() -> Tuple[bool, str]:
    """Test DNS resolution for discord.com"""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        answers = resolver.resolve('discord.com', 'A')
        return True, f"DNS resolution successful, found {len(answers)} record(s)"
    except Exception as e:
        return False, f"DNS resolution failed: {str(e)}"

async def test_connection(host='discord.com', port=443) -> Tuple[bool, str]:
    """Test TCP connection to Discord"""
    try:
        reader, writer = await asyncio.open_connection(host, port)
        writer.close()
        await writer.wait_closed()
        return True, "Connection successful"
    except Exception as e:
        return False, f"Connection failed: {str(e)}"

async def check_network_status():
    """Check basic network connectivity (to 8.8.8.8)"""
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=3)
        return True, "Network is reachable"
    except OSError:
        return False, "Network is unreachable"

async def startup_diagnostics():
    """Run startup connectivity checks."""
    net_status, net_msg = await check_network_status()
    logger.info(f"Network: {net_msg}")

    dns_status, dns_msg = await check_dns_connectivity()
    logger.info(f"DNS: {dns_msg}")

    conn_status, conn_msg = await test_connection()
    logger.info(f"Discord Connection: {conn_msg}")

    return all([net_status, dns_status, conn_status])

async def get_ip_type():
    """Check available IP protocols."""
    try:
        sock_v4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock_v6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock_v4.close()
        sock_v6.close()
        return "both"
    except:
        try:
            sock_v6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            sock_v6.close()
            return "ipv6"
        except:
            try:
                sock_v4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock_v4.close()
                return "ipv4"
            except:
                return "none"

##############################################################################
# Configuration / Secrets
##############################################################################

# Secrets come from the environment (see .env.example); python-dotenv loads a
# local .env if present.
DISCORD_BOT_TOKEN = os.environ.get("DISCORD_BOT_TOKEN", "")
DISCORD_APP_ID = int(os.environ.get("DISCORD_APP_ID") or 0)
WEBHOOK_URL = os.environ.get("WEBHOOK_URL", "")


if not all([DISCORD_BOT_TOKEN, DISCORD_APP_ID, WEBHOOK_URL]):
    raise EnvironmentError("Please set DISCORD_BOT_TOKEN, DISCORD_APP_ID, and WEBHOOK_URL.")

##############################################################################
# Logging
##############################################################################

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

##############################################################################
# Persistent Storage
##############################################################################

STORAGE_PATH = Path("storage.json")
if STORAGE_PATH.exists():
    try:
        with open(STORAGE_PATH, "r") as f:
            storage = json.load(f)
        logger.info("Storage loaded successfully.")
    except json.JSONDecodeError:
        logger.error("Storage file is corrupted. Starting with empty storage.")
        storage = {}
else:
    storage = {}
    with open(STORAGE_PATH, "w") as f:
        json.dump(storage, f)
    logger.info("Created new storage file.")

def save_storage():
    """Persist storage data to disk."""
    try:
        with open(STORAGE_PATH, "w") as f:
            json.dump(storage, f, indent=2)
        logger.debug("Storage saved successfully.")
    except Exception as e:
        logger.error(f"Failed to save storage: {e}")

##############################################################################
# Bot Definition
##############################################################################

class StegoBot(commands.Bot):
    def __init__(self):
        intents = discord.Intents.default()
        intents.message_content = True
        super().__init__(command_prefix="!", intents=intents, application_id=DISCORD_APP_ID)

        self.latency_history = []
        self.connection_start = None
        self.disconnection_count = 0

        # Register command group
        self.stego_group = self.create_stego_group()
        self.tree.add_command(self.stego_group)

    async def setup_hook(self):
        try:
            await self.tree.sync()
            logger.info("Commands synced.")
            self.connection_start = time.time()

            self.monitor_connection.start()
            self.log_metrics.start()
            logger.info("Monitoring tasks started.")
        except Exception as e:
            logger.error(f"setup_hook error: {e}")
            raise

    @tasks.loop(seconds=30)
    async def monitor_connection(self):
        """Keep an eye on latency and log warnings if high."""
        try:
            curr_lat = self.latency
            self.latency_history.append(curr_lat)
            if len(self.latency_history) > 10:
                self.latency_history.pop(0)

            if curr_lat > 1.0:
                logger.warning(f"High latency: {curr_lat:.2f}s")
        except Exception as e:
            logger.error(f"monitor_connection error: {e}")

    @monitor_connection.before_loop
    async def before_monitor(self):
        await self.wait_until_ready()

    @tasks.loop(minutes=5)
    async def log_metrics(self):
        """Log some connection metrics every 5 minutes."""
        try:
            if not self.latency_history:
                return
            avg_lat = sum(self.latency_history) / len(self.latency_history)
            uptime = time.time() - self.connection_start if self.connection_start else 0

            logger.info(
                f"Connection Metrics:\n"
                f"  Average Latency: {avg_lat:.3f}s\n"
                f"  Current Latency: {self.latency:.3f}s\n"
                f"  Uptime: {uptime:.2f}s\n"
                f"  Disconnection Count: {self.disconnection_count}"
            )
        except Exception as e:
            logger.error(f"log_metrics error: {e}")

    @log_metrics.before_loop
    async def before_metrics(self):
        await self.wait_until_ready()

    async def on_ready(self):
        logger.info(f"Logged in as {self.user} (ID: {self.user.id})")
        self.connection_start = time.time()
        logger.info("------")

    async def on_resumed(self):
        logger.info("Connection resumed")

    async def on_disconnect(self):
        logger.warning("Bot disconnected")
        self.disconnection_count += 1

    async def on_connect(self):
        logger.info("Bot connected")

    async def close(self):
        """Shutdown tasks and the bot itself."""
        self.monitor_connection.cancel()
        self.log_metrics.cancel()
        PROCESS_POOL.shutdown(wait=False)  # Optionally shut down the global pool
        await super().close()

    def create_stego_group(self):
        """Create the slash-command group /stego with subcommands."""
        group = app_commands.Group(name="stego", description="Steganography commands")

        @group.command(name="encode", description="Encode a message into an image")
        async def encode(
            interaction: discord.Interaction,
            image: discord.Attachment,
            message: str,
            password: Optional[str] = None,
        ):
            logger.debug(f"Encode command from {interaction.user} | msg length: {len(message)}")

            # Validate
            if not message.strip():
                await interaction.response.send_message("❌ Message cannot be empty.", ephemeral=True)
                return
            if not image:
                await interaction.response.send_message("❌ An image is required.", ephemeral=True)
                return

            # Password
            final_pass = password
            if final_pass:
                if not validate_password(final_pass):
                    await interaction.response.send_message(
                        "❌ Invalid password (must have uppercase, lowercase, digit, special char).",
                        ephemeral=True,
                    )
                    return
            else:
                # Generate strong password
                while True:
                    cand = "".join(secrets.choice(
                        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+<>?"
                    ) for _ in range(PASSWORD_LENGTH))
                    if validate_password(cand):
                        final_pass = cand
                        break

            # Defer
            await interaction.response.defer(ephemeral=True)

            try:
                with tempfile.TemporaryDirectory() as tmpdir:
                    temp_dir = Path(tmpdir)
                    os.chmod(temp_dir, 0o700)  # nosemgrep: insecure-file-permissions  # owner-only

                    input_path = temp_dir / f"input_{image.filename}"
                    output_path = temp_dir / f"output_{image.filename}"

                    # Download
                    if not await download_image(image.url, str(input_path)):
                        await interaction.followup.send("❌ Failed to download image.", ephemeral=True)
                        return

                    secure_logger = SecureLogger(temp_dir)

                    redundancies_to_try = [20, 15, 10, 5, 3, 1]
                    salt = None
                    bits = None
                    used_red = None
                    hmac_key = None
                    discord_file_limit = 8 * 1024 * 1024
                    encoded_under_limit = False

                    for r in redundancies_to_try:
                        try:
                            salt, bits, used_red, hmac_key = await run_in_process_pool(
                                embed_data_into_image,
                                str(input_path),
                                str(output_path),
                                message,
                                final_pass,
                                True,  # allow_low_res
                                r,     # redundancy
                                secure_logger
                            )
                            file_size = os.path.getsize(output_path)
                            if file_size <= discord_file_limit:
                                encoded_under_limit = True
                                break
                        except ValueError as ve:
                            # If it's just too large for the image, try next redundancy
                            if "Payload (with redundancy) is too large" in str(ve):
                                continue
                            else:
                                raise ve

                    if not encoded_under_limit:
                        await interaction.followup.send(
                            "❌ Even with reduced redundancy, the final image is still too large for Discord.",
                            ephemeral=True
                        )
                        return

                    # Embed CPU-bound
                    try:
                        operation_uuid = str(uuid.uuid4())
                        storage[operation_uuid] = {
                            "password": final_pass,
                            "salt": salt.hex(),
                            "embedded_bits": bits,
                            "timestamp": datetime.now().isoformat(),
                            "user_id": str(interaction.user.id),
                            "image_filename": image.filename,
                        }
                        save_storage()

                        # Check output size. If too large for Discord, skip file send
                        file_size = os.path.getsize(output_path)
                        discord_file_limit = 8 * 1024 * 1024  # 8 MB for typical accounts
                        if file_size > discord_file_limit:
                            # 1) Send text info only
                            await interaction.user.send(
                                f"**UUID:** {operation_uuid}\n"
                                f"**Password:** {final_pass}\n"
                                f"**Salt(hex):** {salt.hex()}\n"
                                f"**Embedded Bits:** {bits}\n"
                                f"**Redundancy:** {used_red}\n\n"
                                f"**Note:** The encoded image is **{file_size / (1024*1024):.2f}MB**, "
                                f"which exceeds the typical Discord 8MB limit. You’ll need to retrieve "
                                f"it from your server’s filesystem or an external host."
                            )
                            await interaction.followup.send(
                                "✅ Done, but the final image is too big (>8MB). Check your DM for details.",
                                ephemeral=True
                            )
                        else:
                            # 2) Send file in DM
                            dm_msg = await interaction.user.send(
                                file=discord.File(output_path),
                                content=f"**UUID:** {operation_uuid}\n"
                                        f"**Password:** {final_pass}\n"
                                        f"**Salt(hex):** {salt.hex()}\n"
                                        f"**Bits:** {bits} | Redundancy: {used_red}\n"
                                        f"Keep your UUID/password safe!"
                            )
                            # Webhook embed
                            if dm_msg.attachments:
                                encoded_url = dm_msg.attachments[0].url
                                webhook_embed = {
                                    "title": "🔒 Steganography Operation",
                                    "color": 0x3498db,
                                    "fields": [
                                        {"name": "Operation", "value": "Encode", "inline": True},
                                        {"name": "User", "value": str(interaction.user), "inline": True},
                                        {"name": "Timestamp", "value": datetime.now().isoformat(), "inline": True},
                                    ],
                                    "image": {"url": encoded_url},
                                }
                                await send_webhook(webhook_embed)
                            
                            await interaction.followup.send("✅ Encoding complete! Check your DM.", ephemeral=True)

                    except Exception as e:
                        logger.error(f"Encoding error: {e}")
                        await interaction.followup.send(
                            f"❌ Error during encode: {str(e)}",
                            ephemeral=True
                        )
            except Exception as e:
                logger.error(f"Unexpected encode error: {e}")
                await interaction.followup.send(
                    f"❌ Unexpected error: {str(e)}",
                    ephemeral=True
                )

        @group.command(name="decode", description="Decode a message from an image")
        async def decode(
            interaction: discord.Interaction,
            image: discord.Attachment,
            uuid_str: str
        ):
            logger.debug(f"Decode command from {interaction.user} | UUID: {uuid_str}")

            await interaction.response.defer(ephemeral=True)

            # Validate UUID
            try:
                op_uuid = str(uuid.UUID(uuid_str))
            except ValueError:
                await interaction.followup.send("❌ Invalid UUID format.", ephemeral=True)
                return

            info = storage.get(op_uuid)
            if not info:
                await interaction.followup.send("❌ No data found for that UUID.", ephemeral=True)
                return

            password = info["password"]
            salt_bytes = bytes.fromhex(info["salt"])
            bits = info["embedded_bits"]

            # Download / decode
            try:
                with tempfile.TemporaryDirectory() as tmpdir:
                    temp_dir = Path(tmpdir)
                    os.chmod(temp_dir, 0o700)  # nosemgrep: insecure-file-permissions  # owner-only
                    input_path = temp_dir / f"input_{image.filename}"

                    if not await download_image(image.url, str(input_path)):
                        await interaction.followup.send("❌ Failed to download image.", ephemeral=True)
                        return

                    secure_logger = SecureLogger(temp_dir)

                    # CPU-bound extract
                    try:
                        extracted, success = await run_in_process_pool(
                            extract_data_from_image,
                            str(input_path),
                            password,
                            salt_bytes,
                            bits,
                            20,  # redundancy
                            secure_logger,
                            None
                        )
                        if success and extracted:
                            # Respond
                            embed = discord.Embed(
                                title="🔓 Decoded",
                                description="Message extracted successfully.",
                                color=discord.Color.green()
                            )
                            embed.add_field(name="Message", value=extracted, inline=False)
                            await interaction.followup.send(embed=embed, ephemeral=True)

                            # Webhook
                            webhook_embed = {
                                "title": "🔓 Steganography Operation",
                                "color": 0x3498db,
                                "fields": [
                                    {"name": "Operation", "value": "Decode", "inline": True},
                                    {"name": "User", "value": str(interaction.user), "inline": True},
                                    {"name": "Timestamp", "value": datetime.now().isoformat(), "inline": True},
                                    {"name": "Success", "value": "✅", "inline": True},
                                ],
                            }
                            await send_webhook(webhook_embed)
                        else:
                            await interaction.followup.send(
                                "❌ Failed to extract message. Check your image/UUID combo.",
                                ephemeral=True
                            )
                    except Exception as e:
                        logger.error(f"Decode error: {e}")
                        await interaction.followup.send(
                            f"❌ Decode error: {str(e)}",
                            ephemeral=True
                        )

            except Exception as e:
                logger.error(f"Unexpected decode error: {e}")
                await interaction.followup.send(
                    f"❌ Unexpected decode error: {str(e)}",
                    ephemeral=True
                )

        @group.command(name="decode_manual", description="Decode using manual parameters")
        async def decode_manual(
            interaction: discord.Interaction,
            image: discord.Attachment,
            password: str,
            salt_hex: str,
            embedded_bits: int
        ):
            logger.debug(f"Manual decode from {interaction.user}")
            await interaction.response.defer(ephemeral=True)

            if not validate_password(password):
                await interaction.followup.send("❌ Invalid password format.", ephemeral=True)
                return
            try:
                salt_bytes = bytes.fromhex(salt_hex)
            except ValueError:
                await interaction.followup.send("❌ Salt must be valid hex.", ephemeral=True)
                return

            if embedded_bits <= 0:
                await interaction.followup.send("❌ Embedded bits must be > 0.", ephemeral=True)
                return

            try:
                with tempfile.TemporaryDirectory() as tmpdir:
                    temp_dir = Path(tmpdir)
                    os.chmod(temp_dir, 0o700)  # nosemgrep: insecure-file-permissions  # owner-only
                    input_path = temp_dir / f"manual_{image.filename}"

                    if not await download_image(image.url, str(input_path)):
                        await interaction.followup.send("❌ Failed to download image.", ephemeral=True)
                        return

                    secure_logger = SecureLogger(temp_dir)

                    try:
                        extracted, success = await run_in_process_pool(
                            extract_data_from_image,
                            str(input_path),
                            password,
                            salt_bytes,
                            embedded_bits,
                            20,
                            secure_logger,
                            None
                        )
                        if success and extracted:
                            em = discord.Embed(
                                title="🔓 Manual Decode",
                                description="Decoded successfully.",
                                color=discord.Color.green()
                            )
                            em.add_field(name="Message", value=extracted, inline=False)
                            await interaction.followup.send(embed=em, ephemeral=True)

                            # Webhook
                            webhook_embed = {
                                "title": "🔓 Manual Steganography Operation",
                                "color": 0x3498db,
                                "fields": [
                                    {"name": "Operation", "value": "Manual Decode", "inline": True},
                                    {"name": "User", "value": str(interaction.user), "inline": True},
                                    {"name": "Timestamp", "value": datetime.now().isoformat(), "inline": True},
                                    {"name": "Success", "value": "✅", "inline": True},
                                ],
                            }
                            await send_webhook(webhook_embed)
                        else:
                            await interaction.followup.send(
                                "❌ Failed to decode message. Verify parameters.",
                                ephemeral=True
                            )
                    except Exception as e:
                        logger.error(f"Manual decode error: {e}")
                        await interaction.followup.send(f"❌ {e}", ephemeral=True)

            except Exception as e:
                logger.error(f"Unexpected manual decode error: {e}")
                await interaction.followup.send(
                    f"❌ Unexpected error: {str(e)}",
                    ephemeral=True
                )

        @group.command(name="manual_help", description="Show help for manual decode usage")
        async def manual_help(interaction: discord.Interaction):
            em = discord.Embed(
                title="🔍 Manual Decode Help",
                color=discord.Color.blue(),
                description="Use `/stego decode_manual <image> <password> <salt_hex> <embedded_bits>`"
            )
            em.add_field(
                name="Required Values",
                value=(
                    "• **Password**: The one used to encode\n"
                    "• **Salt (hex)**: Provided in DM after encode\n"
                    "• **Embedded Bits**: The bit count from DM after encode"
                ),
                inline=False
            )
            await interaction.response.send_message(embed=em, ephemeral=True)

        return group

bot = StegoBot()

##############################################################################
# Networking
##############################################################################

async def download_image(url: str, filename: str) -> Optional[str]:
    """Download the image from a URL using aiohttp."""
    logger.debug(f"Downloading image from {url} -> {filename}")
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as resp:
                if (resp.status == 200):
                    data = await resp.read()
                    Path(filename).parent.mkdir(parents=True, exist_ok=True)
                    with open(filename, "wb") as f:
                        f.write(data)
                    return filename
                else:
                    logger.error(f"Download failed. HTTP status: {resp.status}")
                    return None
    except Exception as e:
        logger.error(f"download_image error: {e}")
        return None

async def send_webhook(embed_data: dict):
    """Send an embed to the configured webhook."""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(WEBHOOK_URL, json={"embeds": [embed_data]}) as resp:
                if resp.status not in (200, 204):
                    text = await resp.text()
                    logger.error(f"Webhook error {resp.status}: {text}")
                else:
                    logger.debug("Webhook sent successfully.")
    except Exception as e:
        logger.error(f"send_webhook error: {e}")

##############################################################################
# Main Entry
##############################################################################

if __name__ == "__main__":
    async def main():
        max_retries = 3
        retry_delay = 5

        for attempt in range(max_retries):
            try:
                # Preliminary network checks
                if not await startup_diagnostics():
                    logger.error("Startup diagnostics failed.")
                    if attempt < max_retries - 1:
                        logger.info(f"Retrying in {retry_delay} sec...")
                        time.sleep(retry_delay)
                        continue
                    else:
                        sys.exit(1)

                # Start the bot with built-in auto-reconnect
                async with bot:
                    await bot.start(DISCORD_BOT_TOKEN, reconnect=True)
                break

            except Exception as e:
                logger.error(f"Attempt {attempt+1}/{max_retries} failed: {e}")
                if attempt < max_retries - 1:
                    logger.info(f"Retry in {retry_delay} sec...")
                    time.sleep(retry_delay)
                else:
                    logger.error("All attempts failed.")
                    sys.exit(1)

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", RuntimeWarning)
            asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Bot shutdown via KeyboardInterrupt.")
    except Exception as e:
        logger.error(f"Unexpected top-level error: {e}")
        sys.exit(1)
