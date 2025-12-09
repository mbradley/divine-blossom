# ABOUTME: Cloud Run service for Blossom blob uploads
# ABOUTME: Handles Nostr auth validation, streaming upload to GCS, and SHA-256 hashing

import os
import json
import hashlib
import base64
import time
import uuid
from flask import Flask, Request, jsonify, request
from google.cloud import storage
from coincurve import PublicKeyXOnly

# Configuration
GCS_BUCKET = os.environ.get('GCS_BUCKET', 'divine-blossom-media')
CDN_BASE_URL = os.environ.get('CDN_BASE_URL', 'https://cdn.divine.video')
BLOSSOM_AUTH_KIND = 24242

# Flask app for Cloud Run
app = Flask(__name__)


@app.route('/upload', methods=['PUT', 'OPTIONS'])
@app.route('/', methods=['PUT', 'OPTIONS'])
def upload_blob_route():
    return upload_blob(request)


def upload_blob(request: Request):
    """
    HTTP Cloud Function for Blossom blob uploads.

    Handles PUT /upload with Nostr auth header.
    Streams body to GCS while computing SHA-256 hash.
    """
    # Handle CORS preflight
    if request.method == 'OPTIONS':
        return handle_cors_preflight()

    # Only allow PUT
    if request.method != 'PUT':
        return error_response('Method not allowed', 405)

    try:
        # Validate Nostr auth
        auth_event = validate_auth(request, 'upload')

        # Get content type
        content_type = request.headers.get('Content-Type', 'application/octet-stream')

        # Stream body while hashing
        sha256_hash, size = stream_to_gcs_with_hash(request, content_type)

        # Build response
        response_data = {
            'sha256': sha256_hash,
            'size': size,
            'type': content_type,
            'uploaded': int(time.time()),
            'url': f'{CDN_BASE_URL}/{sha256_hash}.{get_extension(content_type)}'
        }

        response = jsonify(response_data)
        response.status_code = 200
        add_cors_headers(response)
        return response

    except AuthError as e:
        return error_response(str(e), 401)
    except Exception as e:
        print(f'Upload error: {e}')
        return error_response('Upload failed', 500)


def stream_to_gcs_with_hash(request: Request, content_type: str) -> tuple:
    """
    Stream request body to GCS while computing SHA-256 hash.
    Returns (hash, size) tuple.
    """
    storage_client = storage.Client()
    bucket = storage_client.bucket(GCS_BUCKET)

    # Create hasher
    hasher = hashlib.sha256()

    # Use UUID for unique temp name to prevent race conditions
    temp_name = f'_temp/{uuid.uuid4().hex}'
    temp_blob = bucket.blob(temp_name)

    total_size = 0

    try:
        # Stream chunks: read from request, hash, upload to temp
        with temp_blob.open('wb') as f:
            # Read in chunks to avoid memory issues
            chunk_size = 256 * 1024  # 256KB chunks
            while True:
                chunk = request.stream.read(chunk_size)
                if not chunk:
                    break
                hasher.update(chunk)
                f.write(chunk)
                total_size += len(chunk)

        # Get final hash
        sha256_hash = hasher.hexdigest()

        # Check if blob already exists at final location
        final_blob = bucket.blob(sha256_hash)
        if final_blob.exists():
            # Delete temp and return existing
            temp_blob.delete()
            return sha256_hash, total_size

        # Copy temp to final location
        bucket.copy_blob(temp_blob, bucket, sha256_hash)

        # Reload final_blob to get updated metadata after copy
        final_blob.reload()

        # Set content type on final blob
        final_blob.content_type = content_type
        final_blob.patch()

        # Delete temp
        temp_blob.delete()

        return sha256_hash, total_size

    except Exception:
        # Clean up temp blob on any error
        try:
            temp_blob.delete()
        except Exception:
            pass
        raise


class AuthError(Exception):
    """Authentication error."""
    pass


def validate_auth(request: Request, required_action: str) -> dict:
    """
    Validate Nostr auth header.
    Returns the auth event if valid.
    """
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        raise AuthError('Authorization header required')

    if not auth_header.startswith('Nostr '):
        raise AuthError("Authorization must start with 'Nostr '")

    # Decode base64 event
    try:
        event_json = base64.b64decode(auth_header[6:])
        event = json.loads(event_json)
    except Exception as e:
        raise AuthError(f'Invalid authorization format: {e}')

    # Validate event
    validate_event(event, required_action)

    return event


def validate_event(event: dict, required_action: str):
    """Validate a Blossom auth event."""
    # Check kind
    if event.get('kind') != BLOSSOM_AUTH_KIND:
        raise AuthError(f"Invalid event kind: expected {BLOSSOM_AUTH_KIND}")

    # Check action tag
    action = get_tag_value(event, 't')
    if action != required_action:
        raise AuthError(f"Action mismatch: expected {required_action}, got {action}")

    # Check expiration
    expiration = get_tag_value(event, 'expiration')
    if expiration:
        if int(time.time()) > int(expiration):
            raise AuthError('Authorization expired')

    # Verify event ID
    computed_id = compute_event_id(event)
    if computed_id != event.get('id'):
        raise AuthError('Invalid event ID')

    # Verify signature
    verify_signature(event)


def get_tag_value(event: dict, tag_name: str) -> str:
    """Get value from event tags."""
    for tag in event.get('tags', []):
        if len(tag) >= 2 and tag[0] == tag_name:
            return tag[1]
    return None


def compute_event_id(event: dict) -> str:
    """Compute NIP-01 event ID."""
    # Validate required fields exist
    required_fields = ['pubkey', 'created_at', 'kind', 'tags', 'content']
    for field in required_fields:
        if field not in event:
            raise AuthError(f'Missing required field: {field}')

    serialized = json.dumps([
        0,
        event['pubkey'],
        event['created_at'],
        event['kind'],
        event['tags'],
        event['content']
    ], separators=(',', ':'), ensure_ascii=False)

    return hashlib.sha256(serialized.encode()).hexdigest()


def verify_signature(event: dict):
    """Verify BIP-340 Schnorr signature."""
    try:
        pubkey_bytes = bytes.fromhex(event['pubkey'])
        sig_bytes = bytes.fromhex(event['sig'])
        msg_bytes = bytes.fromhex(event['id'])

        # Create x-only public key and verify Schnorr signature
        pk = PublicKeyXOnly(pubkey_bytes)
        if not pk.verify(sig_bytes, msg_bytes):
            raise AuthError('Invalid signature')
    except AuthError:
        raise
    except Exception as e:
        raise AuthError(f'Signature verification failed: {e}')


def get_extension(content_type: str) -> str:
    """Get file extension from content type."""
    extensions = {
        'image/png': 'png',
        'image/jpeg': 'jpg',
        'image/gif': 'gif',
        'image/webp': 'webp',
        'video/mp4': 'mp4',
        'video/webm': 'webm',
        'video/quicktime': 'mov',
        'audio/mpeg': 'mp3',
        'audio/ogg': 'ogg',
        'application/pdf': 'pdf',
    }
    return extensions.get(content_type, 'bin')


def error_response(message: str, status: int):
    """Create error response with CORS headers."""
    response = jsonify({'error': message})
    response.status_code = status
    add_cors_headers(response)
    return response


def handle_cors_preflight():
    """Handle CORS preflight request."""
    response = jsonify({})
    response.status_code = 204
    add_cors_headers(response)
    response.headers['Access-Control-Max-Age'] = '86400'
    return response


def add_cors_headers(response):
    """Add CORS headers to response."""
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'PUT, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Authorization, Content-Type'
