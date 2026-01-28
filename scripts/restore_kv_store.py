#!/usr/bin/env python3
"""
Restore Fastly KV store from a GCS backup.

This script reads a backup JSON file from GCS and restores the key-value pairs
to the Fastly KV store. It can be used for disaster recovery or migration.

Environment variables:
    FASTLY_API_TOKEN: Fastly API token with kv_store.write permission
    KV_STORE_ID: Fastly KV store ID
    GOOGLE_APPLICATION_CREDENTIALS: Path to GCS service account key (optional)

Usage:
    # Restore from a specific backup file
    python restore_kv_store.py gs://bucket/backups/kv-20240101-120000.json

    # Dry run (show what would be restored without making changes)
    python restore_kv_store.py --dry-run gs://bucket/backups/kv-20240101-120000.json

    # Restore only blob metadata (blob:* keys)
    python restore_kv_store.py --filter "blob:*" gs://bucket/backups/kv-20240101-120000.json

    # Restore only user lists (list:* keys)
    python restore_kv_store.py --filter "list:*" gs://bucket/backups/kv-20240101-120000.json

    # Skip existing keys (only restore missing keys)
    python restore_kv_store.py --skip-existing gs://bucket/backups/kv-20240101-120000.json
"""

import argparse
import fnmatch
import json
import os
import sys
from typing import Any, Dict, Optional

import requests

# Try to import google-cloud-storage
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


def parse_gcs_url(url: str) -> tuple[str, str]:
    """Parse a gs:// URL into (bucket, path)."""
    if not url.startswith("gs://"):
        raise ValueError(f"Invalid GCS URL: {url}")

    parts = url[5:].split("/", 1)
    if len(parts) != 2:
        raise ValueError(f"Invalid GCS URL (no path): {url}")

    return parts[0], parts[1]


def download_from_gcs(bucket_name: str, blob_path: str) -> str:
    """Download content from GCS."""
    client = gcs.Client()
    bucket = client.bucket(bucket_name)
    blob = bucket.blob(blob_path)

    if not blob.exists():
        raise FileNotFoundError(f"Backup not found: gs://{bucket_name}/{blob_path}")

    return blob.download_as_text()


def key_exists(store_id: str, api_token: str, key: str) -> bool:
    """Check if a key exists in the KV store."""
    headers = {
        "Fastly-Key": api_token,
    }

    encoded_key = requests.utils.quote(key, safe="")
    url = f"https://api.fastly.com/resources/stores/kv/{store_id}/keys/{encoded_key}"

    resp = requests.head(url, headers=headers)
    return resp.status_code == 200


def put_value(store_id: str, api_token: str, key: str, value: str) -> bool:
    """Put a value into the KV store."""
    headers = {
        "Fastly-Key": api_token,
        "Content-Type": "application/json",
    }

    encoded_key = requests.utils.quote(key, safe="")
    url = f"https://api.fastly.com/resources/stores/kv/{store_id}/keys/{encoded_key}"

    resp = requests.put(url, headers=headers, data=value)

    if resp.status_code in (200, 201):
        return True
    else:
        print(f"Warning: Failed to put key '{key}': {resp.status_code} - {resp.text}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Restore Fastly KV store from GCS backup"
    )
    parser.add_argument(
        "backup_url",
        help="GCS URL of the backup file (gs://bucket/path/to/backup.json)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be restored without making changes",
    )
    parser.add_argument(
        "--filter",
        help="Only restore keys matching this pattern (e.g., 'blob:*' or 'list:*')",
    )
    parser.add_argument(
        "--skip-existing",
        action="store_true",
        help="Skip keys that already exist in the KV store",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Skip confirmation prompt",
    )

    args = parser.parse_args()

    print("=" * 60)
    print("Fastly KV Store Restore")
    print("=" * 60)

    # Get configuration
    api_token = get_env_or_exit("FASTLY_API_TOKEN")
    store_id = get_env_or_exit("KV_STORE_ID")

    print(f"KV Store ID: {store_id}")
    print(f"Backup URL: {args.backup_url}")
    print(f"Dry run: {args.dry_run}")
    print(f"Filter: {args.filter or '(none)'}")
    print(f"Skip existing: {args.skip_existing}")
    print()

    # Download backup from GCS
    print("Downloading backup from GCS...")
    try:
        bucket, path = parse_gcs_url(args.backup_url)
        backup_content = download_from_gcs(bucket, path)
    except Exception as e:
        print(f"Error downloading backup: {e}")
        sys.exit(1)

    # Parse backup
    try:
        backup_data = json.loads(backup_content)
    except json.JSONDecodeError as e:
        print(f"Error parsing backup JSON: {e}")
        sys.exit(1)

    print(f"Backup timestamp: {backup_data.get('timestamp', 'unknown')}")
    print(f"Total keys in backup: {backup_data.get('count', len(backup_data.get('data', {})))}")

    data: Dict[str, Any] = backup_data.get("data", {})

    # Apply filter if specified
    if args.filter:
        filtered_data = {
            k: v for k, v in data.items() if fnmatch.fnmatch(k, args.filter)
        }
        print(f"Keys matching filter '{args.filter}': {len(filtered_data)}")
        data = filtered_data

    if not data:
        print("No keys to restore.")
        return

    # Confirmation
    if not args.dry_run and not args.force:
        print()
        response = input(f"Restore {len(data)} keys to KV store? [y/N] ")
        if response.lower() != "y":
            print("Aborted.")
            return

    # Restore keys
    print()
    print("Restoring keys...")

    restored_count = 0
    skipped_count = 0
    error_count = 0

    for i, (key, value) in enumerate(data.items()):
        if (i + 1) % 100 == 0:
            print(f"  Progress: {i + 1}/{len(data)}")

        # Check if key exists
        if args.skip_existing and not args.dry_run:
            if key_exists(store_id, api_token, key):
                skipped_count += 1
                continue

        # Convert value to JSON string if it's not already a string
        if isinstance(value, (dict, list)):
            value_str = json.dumps(value, ensure_ascii=False)
        else:
            value_str = str(value)

        if args.dry_run:
            print(f"  Would restore: {key} ({len(value_str)} bytes)")
            restored_count += 1
        else:
            if put_value(store_id, api_token, key, value_str):
                restored_count += 1
            else:
                error_count += 1

    print()
    print("=" * 60)
    if args.dry_run:
        print("Dry run complete!")
        print(f"  Keys that would be restored: {restored_count}")
    else:
        print("Restore complete!")
        print(f"  Keys restored: {restored_count}")
        print(f"  Keys skipped (existing): {skipped_count}")
        print(f"  Errors: {error_count}")
    print("=" * 60)


if __name__ == "__main__":
    main()
