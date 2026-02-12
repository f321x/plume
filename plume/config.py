import os
import json
import logging
import platformdirs
from typing import Dict, Any, Set, List
from electrum_aionostr.util import normalize_url

logger = logging.getLogger(__name__)

CONFIG_DIR = platformdirs.user_config_dir("plume")
CONFIG_FILE = os.path.join(CONFIG_DIR, "preferences.json")

def load_defaults() -> Dict[str, Any]:
    try:
        with open(os.path.join(os.path.dirname(__file__), 'defaults.json'), 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to load defaults.json: {e}")
        return {"trusted_npubs": [], "relays": []}

def get_default_relays() -> Set[str]:
    defaults = load_defaults()
    return set(normalize_url(url) for url in defaults.get("relays", []))

def get_default_trusted_npubs() -> Set[str]:
    defaults = load_defaults()
    return set(defaults.get("trusted_npubs", []))

def load_user_config() -> Dict[str, Any]:
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
    return {}

def save_user_config(data: Dict[str, Any]):
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        with open(CONFIG_FILE, 'w') as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        logger.error(f"Failed to save config: {e}")
        raise
