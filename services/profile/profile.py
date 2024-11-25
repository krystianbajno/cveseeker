from typing import Dict
import yaml

from terminal.cli import print_greyed_out

def load_profiles(profiles_file) -> Dict:
    try:
        with open(profiles_file, 'r') as f:
            config = yaml.safe_load(f)
            return config
    except FileNotFoundError:
        print(f"[!] Profiles file '{profiles_file}' not found. Using default settings.")
        return {}
    except yaml.YAMLError as exc:
        print(f"[!] Error parsing config file: {exc}")
        return {}
    
def update_config(config: Dict, update):
    config.update(update)