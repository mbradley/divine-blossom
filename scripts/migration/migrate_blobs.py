# ABOUTME: Migration script to copy blobs from blossom.divine.video to GCS
# ABOUTME: Fetches metadata from nostr relay, downloads blobs, uploads to new storage

import asyncio
import json
import hashlib
import hmac
import base64
import os
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import aiohttp
import requests
import websockets
from nostr_sdk import Keys, EventBuilder, Kind, Tag

# Configuration
OLD_SOURCES = [
    "https://cdn.divine.video",
    "https://stream.divine.video",
    "https://blossom.divine.video",
]
NEW_BLOSSOM_URL = "https://blossom.dvines.org"
GCS_BUCKET = os.environ.get("GCS_BUCKET", "blossom-media")
GCS_ACCESS_KEY = os.environ.get("GCS_ACCESS_KEY")
GCS_SECRET_KEY = os.environ.get("GCS_SECRET_KEY")
RELAY_URL = "wss://relay.divine.video"
NOSTR_NSEC = os.environ.get("NOSTR_NSEC")  # For blossom auth

# Initialize nostr keys - generate if not provided
_nostr_keys = None
try:
    if NOSTR_NSEC:
        _nostr_keys = Keys.parse(NOSTR_NSEC)
    else:
        _nostr_keys = Keys.generate()
    # print(f"Nostr auth: {_nostr_keys.public_key().to_bech32()[:20]}...")
except Exception as e:
    print(f"Warning: Nostr init failed: {e}")
PROGRESS_FILE = Path("migration_progress.json")
CONCURRENT_DOWNLOADS = 10
RETRY_ATTEMPTS = 3


def create_blossom_auth_header(sha256: str, server_url: str = "https://cdn.divine.video") -> Optional[str]:
    """Create a Blossom auth header (kind 24242) for downloading a blob."""
    if not _nostr_keys:
        return None

    try:
        expiration = int(time.time()) + 300  # 5 minutes

        # Build kind 24242 event with required tags
        builder = EventBuilder(
            Kind(24242),
            "",  # Empty content
        ).tags([
            Tag.parse(["t", "get"]),
            Tag.parse(["x", sha256]),
            Tag.parse(["expiration", str(expiration)]),
        ])

        # Sign with our keys
        event = builder.sign_with_keys(_nostr_keys)

        # Return base64-encoded event JSON
        event_json = event.as_json()
        return "Nostr " + base64.b64encode(event_json.encode()).decode()
    except Exception as e:
        print(f"  Auth error: {e}")
        return None


@dataclass
class BlobMetadata:
    """Metadata for a blob to migrate."""
    sha256: str
    pubkey: str
    mime_type: str
    size: int
    source_url: Optional[str] = None  # Original URL from event
    thumbnail_hash: Optional[str] = None
    created_at: int = 0


def parse_imeta_array(imeta_tag: list) -> dict:
    """Parse imeta tag array into a dict.

    Handles TWO formats:
    1. Space-separated: ["imeta", "url https://...", "m video/mp4"]
    2. Alternating pairs: ["imeta", "url", "https://...", "m", "video/mp4"]

    Note: Some keys like "url" can appear multiple times - we collect them as lists.
    """
    result = {}
    urls = []  # Collect all URLs since there can be multiple
    entries = imeta_tag[1:]  # Skip "imeta"

    # Detect format: if first entry has a space, it's space-separated
    if entries and " " in entries[0]:
        # Format 1: Space-separated
        for entry in entries:
            if isinstance(entry, str) and " " in entry:
                key, value = entry.split(" ", 1)
                if key == "url":
                    urls.append(value)
                else:
                    result[key] = value
    else:
        # Format 2: Alternating key-value pairs
        i = 0
        while i < len(entries) - 1:
            key = entries[i]
            value = entries[i + 1]
            if key == "url":
                urls.append(value)
            else:
                result[key] = value
            i += 2

    result["urls"] = urls  # All URLs as a list
    if urls:
        result["url"] = urls[0]  # Keep first URL for backwards compat
    return result


def extract_hash_from_url(url: str) -> Optional[str]:
    """Extract sha256 hash from a blossom URL."""
    if not url:
        return None
    # Get the filename from the path
    path = url.split("/")[-1]
    # Remove extension
    filename = path.split(".")[0]
    # Validate it's a sha256 hash
    if len(filename) == 64 and all(c in '0123456789abcdef' for c in filename.lower()):
        return filename.lower()
    return None


def extract_blob_metadata(event: dict) -> list[BlobMetadata]:
    """Extract blob metadata from all imeta tags in a nostr event."""
    results = []

    # Find ALL imeta tags
    for tag in event.get("tags", []):
        if tag[0] != "imeta":
            continue

        imeta = parse_imeta_array(tag)

        # Try to extract hash from all URLs
        source_url = None
        sha256 = None
        for url in imeta.get("urls", []):
            extracted = extract_hash_from_url(url)
            if extracted:
                sha256 = extracted
                source_url = url
                break

        # If no URL has hash, try the "x" field (explicit hash)
        if not sha256:
            x_hash = imeta.get("x")
            if x_hash and len(x_hash) == 64 and all(c in '0123456789abcdef' for c in x_hash.lower()):
                sha256 = x_hash.lower()
                # Use first URL as source
                source_url = imeta.get("url")

        if not sha256:
            continue  # Skip this imeta if we can't find a valid hash

        # Extract fields
        mime_type = imeta.get("m", "application/octet-stream")
        size_str = imeta.get("size", "0")
        try:
            size = int(size_str) if size_str and size_str != "NaN" else 0
        except ValueError:
            size = 0

        # Extract thumbnail hash from image URL if present
        thumbnail = extract_hash_from_url(imeta.get("image"))

        results.append(BlobMetadata(
            sha256=sha256,
            pubkey=event["pubkey"],
            mime_type=mime_type,
            size=size,
            source_url=source_url,
            thumbnail_hash=thumbnail,
            created_at=event.get("created_at", 0),
        ))

    return results


async def fetch_all_events(relay_url: str, kinds: list[int]) -> list[dict]:
    """Fetch all events of given kinds from a relay using pagination."""
    all_events = []
    seen_ids = set()
    batch_limit = 5000
    until = None  # Start from now, go backwards

    print(f"Connecting to {relay_url}...")
    async with websockets.connect(relay_url) as ws:
        page = 0
        while True:
            page += 1
            # Build filter with pagination
            filter_obj = {"kinds": kinds, "limit": batch_limit}
            if until is not None:
                filter_obj["until"] = until

            sub_id = f"migration_{page}"
            req = json.dumps(["REQ", sub_id, filter_obj])
            await ws.send(req)
            print(f"Page {page}: Fetching events until={until or 'now'}...")

            batch_events = []
            oldest_timestamp = None

            # Receive events for this page
            while True:
                try:
                    msg = await asyncio.wait_for(ws.recv(), timeout=30)
                    data = json.loads(msg)

                    if data[0] == "EVENT":
                        event = data[2]
                        event_id = event.get("id")
                        if event_id and event_id not in seen_ids:
                            seen_ids.add(event_id)
                            batch_events.append(event)
                            # Track oldest timestamp for pagination
                            created_at = event.get("created_at", 0)
                            if oldest_timestamp is None or created_at < oldest_timestamp:
                                oldest_timestamp = created_at
                    elif data[0] == "EOSE":
                        print(f"  Page {page}: received {len(batch_events)} new events")
                        break
                    elif data[0] == "NOTICE":
                        print(f"Relay notice: {data[1]}")
                except asyncio.TimeoutError:
                    print("Timeout waiting for events")
                    break

            # Close this subscription
            await ws.send(json.dumps(["CLOSE", sub_id]))

            # Add batch to all events
            all_events.extend(batch_events)

            # Check if we got fewer events than limit (no more pages)
            if len(batch_events) < batch_limit or oldest_timestamp is None:
                print(f"Pagination complete. Total events: {len(all_events)}")
                break

            # Set until to oldest timestamp - 1 for next page
            until = oldest_timestamp - 1

            if len(all_events) % 10000 == 0:
                print(f"  Progress: {len(all_events)} events so far...")

    return all_events


async def download_blob(session: aiohttp.ClientSession, meta: BlobMetadata) -> Optional[bytes]:
    """Download a blob, trying source URL first then fallback sources."""
    sha256 = meta.sha256

    # Build list of URLs to try
    urls_to_try = []
    if meta.source_url:
        urls_to_try.append(meta.source_url)
    for source in OLD_SOURCES:
        urls_to_try.append(f"{source}/{sha256}")
        urls_to_try.append(f"{source}/{sha256}.mp4")
        urls_to_try.append(f"{source}/{sha256}.jpg")

    # Create auth header for blossom servers
    auth_header = create_blossom_auth_header(sha256)
    headers = {"Authorization": auth_header} if auth_header else {}

    for url in urls_to_try:
        for attempt in range(RETRY_ATTEMPTS):
            try:
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=120)) as resp:
                    if resp.status == 200:
                        data = await resp.read()
                        # Verify hash
                        actual_hash = hashlib.sha256(data).hexdigest()
                        if actual_hash == sha256:
                            return data
                        else:
                            # Hash mismatch, try next URL
                            break
                    elif resp.status == 404:
                        break  # Try next URL
                    elif resp.status == 401 and not auth_header:
                        break  # No auth available, try next URL
                    else:
                        if attempt < RETRY_ATTEMPTS - 1:
                            await asyncio.sleep(2 ** attempt)
            except asyncio.TimeoutError:
                if attempt < RETRY_ATTEMPTS - 1:
                    await asyncio.sleep(2 ** attempt)
            except Exception as e:
                if attempt < RETRY_ATTEMPTS - 1:
                    await asyncio.sleep(2 ** attempt)
                else:
                    pass  # Try next URL

    return None


def gcs_sign_request(method: str, bucket: str, key: str, content_type: str = "",
                     content_md5: str = "") -> tuple[str, dict]:
    """Sign a GCS XML API request using HMAC."""
    host = "storage.googleapis.com"
    date = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")

    # Build string to sign (GCS uses AWS v2 style)
    string_to_sign = f"{method}\n{content_md5}\n{content_type}\n{date}\n/{bucket}/{key}"
    signature = base64.b64encode(
        hmac.new(GCS_SECRET_KEY.encode(), string_to_sign.encode(), hashlib.sha1).digest()
    ).decode()

    headers = {
        "Host": host,
        "Date": date,
        "Authorization": f"GOOG1 {GCS_ACCESS_KEY}:{signature}",
    }
    if content_type:
        headers["Content-Type"] = content_type
    if content_md5:
        headers["Content-MD5"] = content_md5

    url = f"https://{host}/{bucket}/{key}"
    return url, headers


async def blob_exists_in_gcs_async(session: aiohttp.ClientSession, sha256: str) -> bool:
    """Check if a blob already exists in GCS."""
    if not GCS_ACCESS_KEY or not GCS_SECRET_KEY:
        return False

    url, headers = gcs_sign_request("HEAD", GCS_BUCKET, sha256)
    try:
        async with session.head(url, headers=headers) as resp:
            return resp.status == 200
    except Exception:
        return False


def blob_exists_in_gcs(sha256: str) -> bool:
    """Sync wrapper for checking blob existence."""
    import requests
    if not GCS_ACCESS_KEY or not GCS_SECRET_KEY:
        return False

    url, headers = gcs_sign_request("HEAD", GCS_BUCKET, sha256)
    try:
        resp = requests.head(url, headers=headers)
        return resp.status_code == 200
    except Exception:
        return False


async def upload_to_gcs(session: aiohttp.ClientSession, sha256: str, data: bytes,
                        mime_type: str) -> bool:
    """Upload a blob to GCS via XML API."""
    if not GCS_ACCESS_KEY or not GCS_SECRET_KEY:
        print("GCS credentials not configured, skipping upload")
        return False

    try:
        content_md5 = base64.b64encode(hashlib.md5(data).digest()).decode()
        url, headers = gcs_sign_request("PUT", GCS_BUCKET, sha256, mime_type, content_md5)

        async with session.put(url, data=data, headers=headers) as resp:
            if resp.status in (200, 201):
                return True
            else:
                text = await resp.text()
                print(f"  Upload error: HTTP {resp.status} - {text[:200]}")
                return False
    except Exception as e:
        print(f"  Upload error: {e}")
        return False


def load_progress() -> set[str]:
    """Load set of already-migrated hashes."""
    if PROGRESS_FILE.exists():
        with open(PROGRESS_FILE) as f:
            return set(json.load(f))
    return set()


def save_progress(migrated: set[str]):
    """Save progress to file."""
    with open(PROGRESS_FILE, "w") as f:
        json.dump(list(migrated), f)


async def migrate_blob(session: aiohttp.ClientSession, meta: BlobMetadata,
                       migrated: set[str], stats: dict, verbose: bool = False) -> bool:
    """Migrate a single blob."""
    if meta.sha256 in migrated:
        stats["skipped"] += 1
        return True

    # Check if already in GCS
    loop = asyncio.get_event_loop()
    exists = await loop.run_in_executor(None, blob_exists_in_gcs, meta.sha256)
    if exists:
        if verbose:
            print(f"  Already in GCS: {meta.sha256[:16]}...")
        migrated.add(meta.sha256)
        stats["already_in_gcs"] += 1
        return True

    # Download
    if verbose:
        print(f"  Downloading: {meta.sha256[:16]}...")
    data = await download_blob(session, meta)
    if data is None:
        if verbose:
            print(f"  Not found: {meta.sha256[:16]}...")
        stats["not_found"] += 1
        return False

    # Upload
    if verbose:
        print(f"  Uploading: {meta.sha256[:16]}... ({len(data):,} bytes)")
    success = await upload_to_gcs(session, meta.sha256, data, meta.mime_type)
    if success:
        migrated.add(meta.sha256)
        stats["migrated"] += 1
        return True
    else:
        stats["failed"] += 1
        return False


async def main():
    import argparse
    parser = argparse.ArgumentParser(description="Migrate blobs to GCS")
    parser.add_argument("--test", type=int, help="Test mode: migrate only N blobs")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    args = parser.parse_args()

    print("=== Divine Blossom Migration ===\n")

    # Fetch events from relay
    print("Step 1: Fetching video metadata from relay...")
    events = await fetch_all_events(RELAY_URL, [34235, 34236])

    # Extract blob metadata
    print("\nStep 2: Extracting blob metadata...")
    blobs: dict[str, BlobMetadata] = {}
    for event in events:
        metas = extract_blob_metadata(event)  # Now returns a list
        for meta in metas:
            if meta.sha256 not in blobs:
                blobs[meta.sha256] = meta

            # Also track thumbnail if present
            if meta.thumbnail_hash and meta.thumbnail_hash not in blobs:
                blobs[meta.thumbnail_hash] = BlobMetadata(
                    sha256=meta.thumbnail_hash,
                    pubkey=meta.pubkey,
                    mime_type="image/jpeg",
                    size=0,  # Unknown
                    created_at=meta.created_at,
                )

    print(f"Found {len(blobs)} unique blobs to migrate")

    # Load progress
    migrated = load_progress()
    print(f"Already migrated: {len(migrated)}")

    # Stats
    stats = {"migrated": 0, "skipped": 0, "not_found": 0, "failed": 0, "already_in_gcs": 0}

    # Migrate blobs
    blob_list = list(blobs.values())

    # In test mode, only process N blobs
    if args.test:
        blob_list = blob_list[:args.test]
        print(f"\nTest mode: migrating only {len(blob_list)} blobs")

    print("\nStep 3: Migrating blobs...")
    connector = aiohttp.TCPConnector(limit=CONCURRENT_DOWNLOADS)
    async with aiohttp.ClientSession(connector=connector) as session:
        batch_size = 10 if args.test else 100

        for i in range(0, len(blob_list), batch_size):
            batch = blob_list[i:i + batch_size]
            tasks = [migrate_blob(session, meta, migrated, stats, verbose=args.verbose) for meta in batch]
            await asyncio.gather(*tasks)

            # Save progress periodically
            if (i + batch_size) % 100 == 0 or args.test:
                save_progress(migrated)
                print(f"\nProgress: {min(i + batch_size, len(blob_list))}/{len(blob_list)}")
                print(f"  Migrated: {stats['migrated']}, Already in GCS: {stats['already_in_gcs']}, "
                      f"Skipped: {stats['skipped']}, Not found: {stats['not_found']}, Failed: {stats['failed']}")

    # Final save
    save_progress(migrated)

    print("\n=== Migration Complete ===")
    print(f"Migrated: {stats['migrated']}")
    print(f"Already in GCS: {stats['already_in_gcs']}")
    print(f"Skipped (in progress file): {stats['skipped']}")
    print(f"Not found on old server: {stats['not_found']}")
    print(f"Failed: {stats['failed']}")


if __name__ == "__main__":
    asyncio.run(main())
