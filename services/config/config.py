import os
from typing import Dict
import yaml

def load_config(config_file) -> Dict:
    try:
        with open(config_file, 'r') as f:
            config = yaml.safe_load(f)
            return config
    except FileNotFoundError:
        print(f"[!] Config file '{config_file}' not found. Using default settings.")
        return {}
    except yaml.YAMLError as exc:
        print(f"[!] Error parsing config file: {exc}")
        return {}
    
def update_config(config: Dict, update):
    config.update(update)

def configure_on_first_run(config):
    if not os.path.exists(config.get("cache_dir")):
        update_config(config, {"reload": True})
