import argparse
import asyncio
import hashlib
import logging
import sys
import os
from typing import Optional, List

from electrum_aionostr.key import PrivateKey as NostrPrivateKey
from electrum_aionostr.key import PublicKey as NostrPublicKey
from aiohttp_socks import ProxyConnector

from .core import NostrFileAuthenticityTool
from .config import load_user_config, get_default_relays, get_default_trusted_npubs, save_user_config

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

def get_relays(args) -> set[str]:
    config = load_user_config()
    relays = set(config.get("relays", get_default_relays()))
    if args.relays:
        relays = set(args.relays)
    return relays

def get_trusted_pubkeys(args) -> set[str]:
    config = load_user_config()
    trusted_npubs_dict = config.get("trusted_npubs", get_default_trusted_npubs())
    trusted_npubs = set(trusted_npubs_dict.keys())
    if args.trusted_pubkeys:
        trusted_npubs = set(args.trusted_pubkeys)
    
    trusted_pubkeys_hex = set()
    for npub in trusted_npubs:
        try:
            trusted_pubkeys_hex.add(NostrPublicKey.from_npub(npub).hex())
        except Exception:
            # Try as hex if npub fails
            if len(npub) == 64:
                 trusted_pubkeys_hex.add(npub)
            else:
                logger.warning(f"Invalid trusted pubkey ignored: {npub}")
    return trusted_pubkeys_hex

def get_proxy(args) -> Optional[ProxyConnector]:
    config = load_user_config()
    proxy_url = config.get("proxy_url", "")
    if args.proxy:
        proxy_url = args.proxy
    
    if proxy_url:
        try:
            return ProxyConnector.from_url(proxy_url)
        except Exception as e:
            logger.error(f"Invalid proxy URL: {e}")
            sys.exit(1)
    return None

def calculate_file_hash(filepath: str) -> bytes:
    try:
        with open(filepath, 'rb') as f:
            file_content = f.read()
        return hashlib.sha256(file_content).digest()
    except FileNotFoundError:
        logger.error(f"File not found: {filepath}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error reading file: {e}")
        sys.exit(1)

async def sign_command(args):
    file_hash = calculate_file_hash(args.file)
    
    nsec = args.key
    if not nsec:
        nsec = os.environ.get("NOSTR_NSEC")
    
    if not nsec:
        logger.error("Private key (nsec) is required. Provide it via --key or NOSTR_NSEC environment variable.")
        sys.exit(1)

    try:
        if nsec.startswith("nsec"):
            nostr_privkey = NostrPrivateKey.from_nsec(nsec)
        else:
            nostr_privkey = NostrPrivateKey(bytes.fromhex(nsec))
    except Exception:
        logger.error("Invalid private key format.")
        sys.exit(1)

    relays = get_relays(args)
    if not relays:
        logger.error("No relays configured.")
        sys.exit(1)

    proxy = get_proxy(args)

    logger.info(f"Signing file: {args.file}")
    logger.info(f"File Hash: {file_hash.hex()}")
    logger.info("Publishing signature...")

    try:
        await NostrFileAuthenticityTool.publish_signature(
            file_hash_sha256=file_hash,
            private_key=nostr_privkey.raw_secret,
            nostr_relays=relays,
            proxy=proxy,
        )
        logger.info("Signature published successfully.")
        await asyncio.sleep(0.1)
    except Exception as e:
        logger.error(f"Error publishing signature: {e}")
        sys.exit(1)

async def verify_command(args):
    file_hash = calculate_file_hash(args.file)
    trusted_pubkeys = get_trusted_pubkeys(args)
    relays = get_relays(args)
    proxy = get_proxy(args)

    if not trusted_pubkeys:
        logger.error("No trusted public keys configured.")
        sys.exit(1)
    
    if not relays:
        logger.error("No relays configured.")
        sys.exit(1)

    logger.info(f"Verifying file: {args.file}")
    logger.info(f"File Hash: {file_hash.hex()}")
    logger.info(f"Querying {len(relays)} relays for signatures from {len(trusted_pubkeys)} trusted keys...")

    found_signers = set()
    try:
        async for signer_pubkey in NostrFileAuthenticityTool.verify_hash(
            file_hash_sha256=file_hash,
            trusted_signing_pubkeys_hex=trusted_pubkeys,
            timeout_sec=args.timeout,
            nostr_relays=relays,
            proxy=proxy,
        ):
            if signer_pubkey not in found_signers:
                found_signers.add(signer_pubkey)
                logger.info(f"Found valid signature from: {signer_pubkey}")
                if len(found_signers) >= args.min_sigs:
                    break
    except Exception as e:
        logger.error(f"Error during verification: {e}")
        sys.exit(1)

    # Wait a bit to allow pending tasks to complete/cancel gracefully
    await asyncio.sleep(0.1)

    if len(found_signers) >= args.min_sigs:
        logger.info(f"SUCCESS: File is authentic. Found {len(found_signers)} valid signatures.")
        sys.exit(0)
    else:
        logger.error(f"FAILURE: Verification failed. Found {len(found_signers)} valid signatures (required: {args.min_sigs}).")
        sys.exit(1)

def config_command(args):
    config = load_user_config()
    
    if args.list:
        print("Current Configuration:")
        print(f"* Trusted Npubs: {config.get('trusted_npubs', get_default_trusted_npubs())}")
        print(f"* Relays: {config.get('relays', list(get_default_relays()))}")
        print(f"* Proxy: {config.get('proxy_url', '')}")
        return

    changed = False
    if args.add_relay:
        current_relays = set(config.get("relays", get_default_relays()))
        current_relays.add(args.add_relay)
        config["relays"] = list(current_relays)
        changed = True
        print(f"Added relay: {args.add_relay}")

    if args.remove_relay:
        current_relays = set(config.get("relays", get_default_relays()))
        if args.remove_relay in current_relays:
            current_relays.remove(args.remove_relay)
            config["relays"] = list(current_relays)
            changed = True
            print(f"Removed relay: {args.remove_relay}")
        else:
            print(f"Relay not found: {args.remove_relay}")

    if args.add_trusted:
        current_trusted = config.get("trusted_npubs", get_default_trusted_npubs())
        if args.add_trusted not in current_trusted:
            current_trusted[args.add_trusted] = "cli_no_name"
            config["trusted_npubs"] = current_trusted
            changed = True
            print(f"Added trusted key: {args.add_trusted}")
        else:
            print(f"Trusted key already exists: {args.add_trusted}")

    if args.remove_trusted:
        current_trusted = config.get("trusted_npubs", get_default_trusted_npubs())
        if args.remove_trusted in current_trusted:
            del current_trusted[args.remove_trusted]
            config["trusted_npubs"] = current_trusted
            changed = True
            print(f"Removed trusted key: {args.remove_trusted}")
        else:
            print(f"Trusted key not found: {args.remove_trusted}")

    if args.set_proxy:
        config["proxy_url"] = args.set_proxy
        changed = True
        print(f"Set proxy: {args.set_proxy}")
    
    if args.unset_proxy:
        config["proxy_url"] = ""
        changed = True
        print("Unset proxy")

    if changed:
        save_user_config(config)
        print("Configuration saved.")
    else:
        if not args.list:
            print("No changes made. Use --help to see available options.")

def main():
    parser = argparse.ArgumentParser(description="Plume - Nostr File Authenticity Tool CLI")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Sign Command
    sign_parser = subparsers.add_parser("sign", help="Sign a file and publish signature to Nostr")
    sign_parser.add_argument("file", help="Path to the file to sign")
    sign_parser.add_argument("--key", help="Nostr private key (nsec or hex). Can also be set via NOSTR_NSEC env var.")
    sign_parser.add_argument("--relays", nargs="+", help="List of relays to publish to (overrides config)")
    sign_parser.add_argument("--proxy", help="Proxy URL (overrides config)")

    # Verify Command
    verify_parser = subparsers.add_parser("verify", help="Verify a file against trusted signatures on Nostr")
    verify_parser.add_argument("file", help="Path to the file to verify")
    verify_parser.add_argument("--trusted-pubkeys", nargs="+", help="List of trusted public keys (npub or hex) (overrides config)")
    verify_parser.add_argument("--relays", nargs="+", help="List of relays to query (overrides config)")
    verify_parser.add_argument("--proxy", help="Proxy URL (overrides config)")
    verify_parser.add_argument("--min-sigs", type=int, default=1, help="Minimum number of valid signatures required (default: 1)")
    verify_parser.add_argument("--timeout", type=int, default=20, help="Timeout in seconds for verification (default: 20)")

    # Config Command
    config_parser = subparsers.add_parser("config", help="Manage configuration")
    config_parser.add_argument("--list", action="store_true", help="List current configuration")
    config_parser.add_argument("--add-relay", help="Add a relay")
    config_parser.add_argument("--remove-relay", help="Remove a relay")
    config_parser.add_argument("--add-trusted", help="Add a trusted public key (npub)")
    config_parser.add_argument("--remove-trusted", help="Remove a trusted public key")
    config_parser.add_argument("--set-proxy", help="Set proxy URL")
    config_parser.add_argument("--unset-proxy", action="store_true", help="Unset proxy URL")

    args = parser.parse_args()

    if args.command == "sign":
        try:
            asyncio.run(sign_command(args))
        except RuntimeError:  # Ignore event loop closed errors on exit
            pass
    elif args.command == "verify":
        try:
            asyncio.run(verify_command(args))
        except RuntimeError:
            pass
    elif args.command == "config":
        config_command(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
