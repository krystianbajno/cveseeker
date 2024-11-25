import os
import time

from terminal.cli import print_greyed_out

def is_cache_valid(config, filepath, cache_duration):
    if config.get("reload"):
        return False
    
    if config.get("autoupdate"):
        if os.path.exists(filepath):
            cache_mtime = os.path.getmtime(filepath)
            current_time = time.time()
            return (current_time - cache_mtime) < cache_duration
        return False

    return True

def ensure_cache_directory(cache_dir, provider):
    if not os.path.exists(cache_dir):
        try:
            os.makedirs(cache_dir)
            print_greyed_out(f"[+] {provider}: Created cache directory at '{cache_dir}'.")
        except Exception as e:
            print_greyed_out(f"[!] {provider}: Failed to create cache directory '{cache_dir}': {e}")
