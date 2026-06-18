#!/usr/bin/env python3

"""
 ██████╗████████╗██████╗ ██╗     ██████╗
██╔════╝╚══██╔══╝██╔══██╗██║     ██╔══██╗
██║        ██║   ██████╔╝██║     ██║  ██║
██║        ██║   ██╔══██╗██║     ██║  ██║
╚██████╗   ██║   ██║  ██║███████╗██████╔╝
 ╚═════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═════╝

███████╗██╗   ██╗███╗   ██╗ ██████╗
██╔════╝╚██╗ ██╔╝████╗  ██║██╔════╝
███████╗ ╚████╔╝ ██╔██╗ ██║██║
╚════██║  ╚██╔╝  ██║╚██╗██║██║
███████║   ██║   ██║ ╚████║╚██████╗
╚══════╝   ╚═╝   ╚═╝  ╚═══╝ ╚═════╝


----------------------
A tiny helper that keeps your Control D folders in sync with a set of remote block-lists.
Forked from https://github.com/keksiqc/ctrld-sync
It does three things:
1. Reads the folder names and rules from remote JSON files.
2. Deletes any existing folders with those names (so we start fresh).
3. Re-creates the folders and pushes all rules in batches.
"""

#!/usr/bin/env python3
"""
Control D Sync
----------------------
A tiny helper that keeps your Control D folders in sync with a set of remote block-lists.
It does three things:
1. Reads the folder names and rules from remote JSON files.
2. Deletes any existing folders with those names (so we start fresh).
3. Re-creates the folders and pushes all rules in batches.

For GitHub Actions, create repo secrets
CONTROL_D_TOKEN
CONTROL_D_PROFILES
"""

import os
import logging
import time
from typing import Dict, List, Optional, Any
import httpx
from dotenv import load_dotenv

# --------------------------------------------------------------------------- #
# Load secrets and configure logging
# --------------------------------------------------------------------------- #
load_dotenv()
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%H:%M:%S",
)
logging.getLogger("httpx").setLevel(logging.WARNING)
log = logging.getLogger("control-d-sync")

# --------------------------------------------------------------------------- #
# Constants & Configuration
# --------------------------------------------------------------------------- #
API_BASE = "https://controld.com"
TOKEN = os.getenv("TOKEN")
PROFILE_IDS = [p.strip() for p in os.getenv("PROFILE", "").split(",") if p.strip()]
DRY_RUN = os.getenv("DRY_RUN", "false").lower() in ("true", "1", "yes")

FOLDER_URLS = [
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/controld/badware-hoster-folder.json",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/controld/native-tracker-amazon-folder.json",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/controld/native-tracker-microsoft-folder.json",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/controld/native-tracker-tiktok-aggressive-folder.json",
]

# When DRY_RUN is active, dummy secrets are acceptable for initialization testing
if DRY_RUN:
    log.info("--- DRY RUN MODE ENABLED ---")
    TOKEN = TOKEN or "dummy_token_for_testing"
    PROFILE_IDS = PROFILE_IDS or ["dummy_profile_id_for_testing"]

if not TOKEN:
    log.critical("Missing TOKEN environment variable.")
    exit(1)

if not PROFILE_IDS:
    log.critical("No PROFILE IDs discovered in environment variables.")
    exit(1)

# --------------------------------------------------------------------------- #
# Sync Logic
# --------------------------------------------------------------------------- #
def get_headers() -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {TOKEN}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

def fetch_remote_folder(client: httpx.Client, url: str) -> Optional[Dict[str, Any]]:
    """Fetches and validates the remote Hagezi Control D JSON export format."""
    try:
        log.info(f"Fetching remote blocklist: {url.split('/')[-1]}")
        response = client.get(url)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        log.error(f"Failed to fetch {url}: {e}")
        return None

def get_existing_folders(client: httpx.Client, profile_id: str) -> Dict[str, str]:
    """Retrieves all folders currently assigned to a profile. Maps Name -> ID."""
    if DRY_RUN:
        log.info(f"[Dry Run] Skipping API call to fetch existing folders for profile {profile_id}")
        return {}
        
    url = f"{API_BASE}/profiles/{profile_id}/groups"
    try:
        response = client.get(url, headers=get_headers())
        response.raise_for_status()
        data = response.json()
        groups = data.get("body", {}).get("groups", [])
        return {g["name"]: g["group_id"] for g in groups if "name" in g and "group_id" in g}
    except Exception as e:
        log.error(f"Failed to fetch existing folders for profile {profile_id}: {e}")
        return {}

def delete_folder(client: httpx.Client, profile_id: str, folder_id: str, name: str):
    """Deletes an existing custom rule folder by ID."""
    if DRY_RUN:
        log.info(f"[Dry Run] Skipping API call to delete folder '{name}' (ID: {folder_id})")
        return
        
    url = f"{API_BASE}/profiles/{profile_id}/groups/{folder_id}"
    try:
        log.warning(f"Deleting existing folder '{name}' (ID: {folder_id}) to start fresh...")
        response = client.delete(url, headers=get_headers())
        response.raise_for_status()
        time.sleep(0.5)
    except Exception as e:
        log.error(f"Failed to delete folder {name}: {e}")

def create_folder(client: httpx.Client, profile_id: str, name: str, action: str, status: int) -> Optional[str]:
    """Creates a new rule folder and returns its group_id."""
    if DRY_RUN:
        log.info(f"[Dry Run] Skipping API call to create folder '{name}' (Action: {action})")
        return "dry_run_folder_id"
        
    url = f"{API_BASE}/profiles/{profile_id}/groups"
    payload = {
        "name": name,
        "action": action,
        "status": status,
    }
    try:
        log.info(f"Creating folder '{name}' with inherited action: {action}")
        response = client.post(url, headers=get_headers(), json=payload)
        response.raise_for_status()
        return response.json().get("body", {}).get("group_id")
    except Exception as e:
        log.error(f"Failed to create folder {name}: {e}")
        return None

def add_rules_to_folder(client: httpx.Client, profile_id: str, folder_id: str, rules: List[Dict[str, Any]]):
    """Pushes domains into the created folder."""
    if DRY_RUN:
        log.info(f"[Dry Run] Skipping API execution for adding {len(rules)} rules to folder {folder_id}")
        for rule in rules[:5]:
            hostname = rule.get("hostname") or rule.get("PK")
            if not hostname:
                log.error("Rule validation failed: Missing hostname string in source data.")
        return

    url = f"{API_BASE}/profiles/{profile_id}/rules"
    log.info(f"Pushing {len(rules)} custom rules into folder ID: {folder_id}...")
    
    for index, rule in enumerate(rules):
        hostname = rule.get("hostname") or rule.get("PK")
        if not hostname:
            continue
            
        payload = {
            "do": rule.get("do", 0),
            "status": rule.get("status", 1),
            "group_id": folder_id,
            "text": hostname
        }
        
        try:
            res = client.post(url, headers=get_headers(), json=payload)
            if res.status_code == 429:
                log.warning("Rate limit hit. Sleeping for 5 seconds...")
                time.sleep(5)
                res = client.post(url, headers=get_headers(), json=payload)
            res.raise_for_status()
        except Exception as e:
            log.error(f"Failed inserting rule {hostname}: {e}")
            
        if index % 20 == 0 and index > 0:
            log.info(f"Progress: Pushed {index}/{len(rules)} rules...")
            time.sleep(1)

def main():
    log.info("Starting Control D Blocklist Sync Engine")
    
    with httpx.Client(timeout=30.0) as client:
        parsed_folders = []
        for url in FOLDER_URLS:
            data = fetch_remote_folder(client, url)
            if data and ("body" in data or "group" in data):
                parsed_folders.append(data)
        
        if not parsed_folders:
            log.error("No valid remote configurations fetched. Exiting.")
            exit(1)

        for profile_id in PROFILE_IDS:
            log.info(f"=== Processing Profile ID: {profile_id} ===")
            
            existing_map = get_existing_folders(client, profile_id)
            
            for remote_data in parsed_folders:
                folder_meta = remote_data.get("body", {}).get("group", remote_data.get("group", {}))
                rules = remote_data.get("body", {}).get("rules", remote_data.get("rules", []))
                
                folder_name = folder_meta.get("name")
                folder_action = folder_meta.get("action", "BLOCK")
                folder_status = folder_meta.get("status", 1)
                
                if not folder_name:
                    log.error("Could not extract folder name from source payload.")
                    continue
                
                if folder_name in existing_map:
                    delete_folder(client, profile_id, existing_map[folder_name], folder_name)
                
                new_folder_id = create_folder(client, profile_id, folder_name, folder_action, folder_status)
                
                if new_folder_id and rules:
                    add_rules_to_folder(client, profile_id, new_folder_id, rules)
                    
    log.info("Sync sequence finished successfully!")

if __name__ == "__main__":
    main()