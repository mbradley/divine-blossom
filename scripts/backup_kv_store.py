#!/usr/bin/env python3
"""
Backup Fastly KV store to Google Cloud Storage.

This script exports all key-value pairs from the Fastly KV store to a JSON file
and uploads it to GCS for durability. The backup includes:
- blob:{hash} entries (blob metadata)
- list:{pubkey} entries (user blob lists)

Environment variables:
    FASTLY_API_TOKEN: Fastly API token with kv_store.read permission
    KV_STORE_ID: Fastly KV store ID
    GCS_BUCKET: GCS bucket for backups
    GOOGLE_APPLICATION_CREDENTIALS: Path to GCS service account key (optional)

Usage:
    python backup_kv_store.py

The script will create a backup file at:
    gs://{GCS_BUCKET}/backups/kv-{YYYYMMDD-HHMMSS}.json
"""

import json
import os
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional

import requests

# Try to import google-cloud-storage, provide helpful error if not available
try:
    from google.cloud import storage as gcs
except ImportError:
    print("Error: google-cloud-storage not installed")
    print("Install with: pip install google-cloud-storage")
    sys.exit(1)


def get_env_or_exit(name: str) -> str:
    """Get environment variable or exit with error."""
    value = os.environ.get(name)
    if not value:
        print(f"Error: {name} environment variable is required")
        sys.exit(1)
    return value


def list_all_keys(store_id: str, api_token: str) -> List[str]:
    """List all keys in the KV store using pagination."""
    keys: List[str] = []
    cursor: Optional[str] = None

    headers = {
        "Fastly-Key": api_token,
        "Accept": "application/json",
    }

    while True:
        params: Dict[str, Any] = {"limit": 1000}
        if cursor:
            params["cursor"] = cursor

        url = f"https://api.fastly.com/resources/stores/kv/{store_id}/keys"
        resp = requests.get(url, headers=headers, params=params)

        if resp.status_code != 200:
            print(f"Error listing keys: {resp.status_code} - {resp.text}")
            sys.exit(1)

        data = resp.json()

        # Extract key names from the response
        for item in data.get("data", []):
            if isinstance(item, str):
                keys.append(item)
            elif isinstance(item, dict):
                keys.append(item.get("name", item.get("key", str(item))))

        # Check for next page
        cursor = data.get("meta", {}).get("next_cursor")
        if not cursor:
            break

    return keys


def get_value(store_id: str, api_token: str, key: str) -> Optional[str]:
    """Get a single value from the KV store."""
    headers = {
        "Fastly-Key": api_token,
    }

    # URL-encode the key for the path
    encoded_key = requests.utils.quote(key, safe="")
    url = f"https://api.fastly.com/resources/stores/kv/{store_id}/keys/{encoded_key}"

    resp = requests.get(url, headers=headers)

    if resp.status_code == 200:
        return resp.text
    elif resp.status_code == 404:
        return None
    else:
        print(f"Warning: Failed to get key '{key}': {resp.status_code}")
        return None


def upload_to_gcs(bucket_name: str, filename: str, content: str) -> str:
    """Upload content to GCS and return the gs:// URL.

    Falls back to saving locally if GCS upload fails.
    """
    local_path = f"/tmp/{filename.replace('/', '-')}"

    try:
        client = gcs.Client()
        bucket = client.bucket(bucket_name)
        blob = bucket.blob(filename)
        blob.upload_from_string(content, content_type="application/json")
        return f"gs://{bucket_name}/{filename}"
    except Exception as e:
        print(f"Warning: GCS upload failed ({e}), saving locally instead")
        with open(local_path, "w") as f:
            f.write(content)
        print(f"Saved to {local_path}")
        print(f"To upload manually: gsutil cp {local_path} gs://{bucket_name}/{filename}")
        return local_path


def main():
    print("=" * 60)
    print("Fastly KV Store Backup")
    print("=" * 60)

    # Get configuration
    api_token = get_env_or_exit("FASTLY_API_TOKEN")
    store_id = get_env_or_exit("KV_STORE_ID")
    gcs_bucket = get_env_or_exit("GCS_BUCKET")

    print(f"KV Store ID: {store_id}")
    print(f"GCS Bucket: {gcs_bucket}")
    print()

    # List all keys
    print("Listing all keys...")
    keys = list_all_keys(store_id, api_token)
    print(f"Found {len(keys)} keys")

    if not keys:
        print("No keys found in KV store. Nothing to backup.")
        return

    # Fetch all values
    print("Fetching values...")
    backup_data: Dict[str, Any] = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "store_id": store_id,
        "count": len(keys),
        "data": {},
    }

    success_count = 0
    error_count = 0

    for i, key in enumerate(keys):
        if (i + 1) % 100 == 0:
            print(f"  Progress: {i + 1}/{len(keys)}")

        value = get_value(store_id, api_token, key)
        if value is not None:
            # Try to parse as JSON, store raw if that fails
            try:
                backup_data["data"][key] = json.loads(value)
            except json.JSONDecodeError:
                backup_data["data"][key] = value
            success_count += 1
        else:
            error_count += 1

    print(f"Fetched {success_count} values ({error_count} errors)")

    # Generate backup filename
    timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    filename = f"backups/kv-{timestamp}.json"

    # Upload to GCS
    print(f"Uploading to GCS...")
    backup_json = json.dumps(backup_data, indent=2, ensure_ascii=False)
    gcs_url = upload_to_gcs(gcs_bucket, filename, backup_json)

    print()
    print("=" * 60)
    print("Backup complete!")
    print(f"  Keys backed up: {success_count}")
    print(f"  Backup location: {gcs_url}")
    print(f"  Backup size: {len(backup_json):,} bytes")
    print("=" * 60)


if __name__ == "__main__":
    main()
