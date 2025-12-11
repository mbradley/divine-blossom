# ABOUTME: Copy blobs from staging to production GCS bucket
# ABOUTME: Uses HMAC auth (S3-compatible) to list and copy objects

import os
import hmac
import hashlib
import base64
import requests
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from urllib.parse import quote

# Load credentials from environment
GCS_ACCESS_KEY = os.environ.get("GCS_ACCESS_KEY")
GCS_SECRET_KEY = os.environ.get("GCS_SECRET_KEY")
SOURCE_BUCKET = "divine-blossom-media-staging"
DEST_BUCKET = "divine-blossom-media"
GCS_HOST = "storage.googleapis.com"

def sign_request(method, bucket, key="", content_type="", content_md5="", headers=None):
    """Sign a GCS request using AWS v2 HMAC signing (works with GCS)."""
    date = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")

    # Build canonical headers
    amz_headers = ""
    if headers:
        for k, v in sorted(headers.items()):
            if k.lower().startswith("x-amz-"):
                amz_headers += f"{k.lower()}:{v}\n"

    # Build string to sign
    resource = f"/{bucket}"
    if key:
        resource += f"/{key}"

    string_to_sign = f"{method}\n{content_md5}\n{content_type}\n{date}\n{amz_headers}{resource}"

    # Create signature
    signature = base64.b64encode(
        hmac.new(GCS_SECRET_KEY.encode(), string_to_sign.encode(), hashlib.sha1).digest()
    ).decode()

    return date, f"GOOG1 {GCS_ACCESS_KEY}:{signature}"


def list_objects(bucket, marker=None):
    """List objects in a bucket."""
    url = f"https://{GCS_HOST}/{bucket}"
    if marker:
        url += f"?marker={quote(marker)}"

    date, auth = sign_request("GET", bucket)
    headers = {
        "Host": GCS_HOST,
        "Date": date,
        "Authorization": auth,
    }

    resp = requests.get(url, headers=headers)
    if resp.status_code != 200:
        print(f"Error listing bucket: {resp.status_code} - {resp.text}")
        return [], None

    # Parse XML response
    root = ET.fromstring(resp.content)
    ns = {"s3": "http://s3.amazonaws.com/doc/2006-03-01/"}

    objects = []
    for contents in root.findall("s3:Contents", ns):
        key = contents.find("s3:Key", ns)
        size = contents.find("s3:Size", ns)
        if key is not None:
            objects.append({
                "key": key.text,
                "size": int(size.text) if size is not None else 0
            })

    # Check for truncation
    is_truncated = root.find("s3:IsTruncated", ns)
    next_marker = None
    if is_truncated is not None and is_truncated.text == "true":
        # Get last key as marker
        if objects:
            next_marker = objects[-1]["key"]

    return objects, next_marker


def copy_object(source_bucket, dest_bucket, key):
    """Copy an object from source to destination bucket using server-side copy."""
    url = f"https://{GCS_HOST}/{dest_bucket}/{key}"

    # Use x-amz-copy-source header for server-side copy
    copy_source = f"/{source_bucket}/{key}"
    extra_headers = {"x-amz-copy-source": copy_source}

    date, auth = sign_request("PUT", dest_bucket, key, headers=extra_headers)
    headers = {
        "Host": GCS_HOST,
        "Date": date,
        "Authorization": auth,
        "x-amz-copy-source": copy_source,
        "Content-Length": "0",
    }

    resp = requests.put(url, headers=headers)
    return resp.status_code == 200


def main():
    print(f"Copying from {SOURCE_BUCKET} to {DEST_BUCKET}...")

    total = 0
    copied = 0
    skipped = 0
    failed = 0
    marker = None

    while True:
        objects, next_marker = list_objects(SOURCE_BUCKET, marker)

        if not objects:
            break

        for obj in objects:
            key = obj["key"]
            total += 1

            # Skip _temp directory
            if key.startswith("_temp/"):
                skipped += 1
                continue

            # Try to copy
            if copy_object(SOURCE_BUCKET, DEST_BUCKET, key):
                copied += 1
                print(f"[{copied}/{total}] Copied: {key}")
            else:
                failed += 1
                print(f"[{total}] FAILED: {key}")

        if next_marker is None:
            break
        marker = next_marker

        print(f"Progress: {copied} copied, {skipped} skipped, {failed} failed / {total} total")

    print(f"\n=== Complete ===")
    print(f"Total objects: {total}")
    print(f"Copied: {copied}")
    print(f"Skipped: {skipped}")
    print(f"Failed: {failed}")


if __name__ == "__main__":
    if not GCS_ACCESS_KEY or not GCS_SECRET_KEY:
        print("Error: Set GCS_ACCESS_KEY and GCS_SECRET_KEY environment variables")
        exit(1)
    main()
