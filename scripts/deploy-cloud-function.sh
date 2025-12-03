#!/bin/bash
# ABOUTME: Deploy the content moderation Cloud Function
# ABOUTME: Requires gcloud CLI authenticated and configured

set -e

PROJECT_ID="${GCP_PROJECT_ID:-}"
BUCKET_NAME="${GCS_BUCKET_NAME:-blossom-media}"
REGION="${GCS_REGION:-us-central1}"
FUNCTION_NAME="process-blob"

if [ -z "$PROJECT_ID" ]; then
    echo "Error: GCP_PROJECT_ID environment variable required"
    exit 1
fi

echo "Deploying Cloud Function..."
echo "Project: $PROJECT_ID"
echo "Bucket: $BUCKET_NAME"
echo "Region: $REGION"

cd "$(dirname "$0")/../cloud-functions/process-blob"

gcloud functions deploy "$FUNCTION_NAME" \
    --project="$PROJECT_ID" \
    --region="$REGION" \
    --runtime=python311 \
    --trigger-resource="$BUCKET_NAME" \
    --trigger-event=google.storage.object.finalize \
    --entry-point=process_blob \
    --memory=512MB \
    --timeout=120s \
    --set-env-vars="METADATA_WEBHOOK_URL=${METADATA_WEBHOOK_URL:-},METADATA_WEBHOOK_SECRET=${METADATA_WEBHOOK_SECRET:-}"

echo ""
echo "Cloud Function deployed!"
echo "View logs: gcloud functions logs read $FUNCTION_NAME --region=$REGION"
