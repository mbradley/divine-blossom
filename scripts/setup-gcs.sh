#!/bin/bash
# ABOUTME: Helper script to set up Google Cloud Storage for Blossom
# ABOUTME: Creates GCS bucket and HMAC keys for S3-compatible API access

set -e

# Color output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Blossom GCS Setup Script ===${NC}\n"

# Check if gcloud is installed
if ! command -v gcloud &> /dev/null; then
    echo -e "${RED}Error: gcloud CLI is not installed${NC}"
    echo "Please install it from: https://cloud.google.com/sdk/docs/install"
    exit 1
fi

# Check if gsutil is installed
if ! command -v gsutil &> /dev/null; then
    echo -e "${RED}Error: gsutil is not installed${NC}"
    echo "Please install it from: https://cloud.google.com/storage/docs/gsutil_install"
    exit 1
fi

# Get environment variables or prompt for them
if [ -z "$GCP_PROJECT_ID" ]; then
    echo -e "${YELLOW}Enter your GCP Project ID:${NC}"
    read -r GCP_PROJECT_ID
fi

if [ -z "$GCS_BUCKET_NAME" ]; then
    echo -e "${YELLOW}Enter your desired GCS bucket name:${NC}"
    read -r GCS_BUCKET_NAME
fi

if [ -z "$GCS_LOCATION" ]; then
    GCS_LOCATION="US"
    echo -e "${YELLOW}Using default location: ${GCS_LOCATION}${NC}"
    echo -e "${YELLOW}Set GCS_LOCATION env var to change (e.g., US, EU, ASIA)${NC}"
fi

if [ -z "$GCS_STORAGE_CLASS" ]; then
    GCS_STORAGE_CLASS="STANDARD"
    echo -e "${YELLOW}Using default storage class: ${GCS_STORAGE_CLASS}${NC}"
    echo -e "${YELLOW}Set GCS_STORAGE_CLASS env var to change (e.g., NEARLINE, COLDLINE)${NC}"
fi

echo -e "\n${GREEN}Configuration:${NC}"
echo "  Project ID: ${GCP_PROJECT_ID}"
echo "  Bucket Name: ${GCS_BUCKET_NAME}"
echo "  Location: ${GCS_LOCATION}"
echo "  Storage Class: ${GCS_STORAGE_CLASS}"

echo -e "\n${YELLOW}Setting GCP project...${NC}"
gcloud config set project "${GCP_PROJECT_ID}"

# Check if bucket already exists
if gsutil ls -b "gs://${GCS_BUCKET_NAME}" &> /dev/null; then
    echo -e "${YELLOW}Warning: Bucket ${GCS_BUCKET_NAME} already exists. Skipping creation.${NC}"
else
    echo -e "\n${GREEN}Creating GCS bucket...${NC}"
    gsutil mb -p "${GCP_PROJECT_ID}" -c "${GCS_STORAGE_CLASS}" -l "${GCS_LOCATION}" "gs://${GCS_BUCKET_NAME}"
    echo -e "${GREEN}✓ Bucket created successfully${NC}"
fi

# Enable uniform bucket-level access (recommended for S3 compatibility)
echo -e "\n${GREEN}Enabling uniform bucket-level access...${NC}"
gsutil uniformbucketlevelaccess set on "gs://${GCS_BUCKET_NAME}"
echo -e "${GREEN}✓ Uniform bucket-level access enabled${NC}"

# Set CORS configuration for web access
echo -e "\n${GREEN}Setting CORS configuration...${NC}"
cat > /tmp/cors-config.json <<EOF
[
  {
    "origin": ["*"],
    "method": ["GET", "HEAD", "PUT", "POST", "DELETE"],
    "responseHeader": ["Content-Type", "x-goog-resumable"],
    "maxAgeSeconds": 3600
  }
]
EOF
gsutil cors set /tmp/cors-config.json "gs://${GCS_BUCKET_NAME}"
rm /tmp/cors-config.json
echo -e "${GREEN}✓ CORS configuration set${NC}"

# Create service account for HMAC keys
SERVICE_ACCOUNT_NAME="blossom-storage-sa"
SERVICE_ACCOUNT_EMAIL="${SERVICE_ACCOUNT_NAME}@${GCP_PROJECT_ID}.iam.gserviceaccount.com"

echo -e "\n${GREEN}Checking for service account...${NC}"
if gcloud iam service-accounts describe "${SERVICE_ACCOUNT_EMAIL}" --project="${GCP_PROJECT_ID}" &> /dev/null; then
    echo -e "${YELLOW}Service account ${SERVICE_ACCOUNT_EMAIL} already exists. Skipping creation.${NC}"
else
    echo -e "${GREEN}Creating service account for HMAC keys...${NC}"
    gcloud iam service-accounts create "${SERVICE_ACCOUNT_NAME}" \
        --project="${GCP_PROJECT_ID}" \
        --display-name="Blossom Storage Service Account" \
        --description="Service account for Blossom media storage HMAC keys"
    echo -e "${GREEN}✓ Service account created${NC}"
fi

# Grant storage admin permissions to the service account
echo -e "\n${GREEN}Granting storage permissions to service account...${NC}"
gsutil iam ch "serviceAccount:${SERVICE_ACCOUNT_EMAIL}:objectAdmin" "gs://${GCS_BUCKET_NAME}"
echo -e "${GREEN}✓ Permissions granted${NC}"

# Create HMAC keys
echo -e "\n${GREEN}Creating HMAC keys...${NC}"
echo -e "${YELLOW}Note: HMAC keys will be displayed only once. Save them securely!${NC}\n"

HMAC_OUTPUT=$(gsutil hmac create "${SERVICE_ACCOUNT_EMAIL}")
echo "$HMAC_OUTPUT"

# Parse the HMAC output
ACCESS_KEY_ID=$(echo "$HMAC_OUTPUT" | grep "Access ID:" | awk '{print $3}')
SECRET_ACCESS_KEY=$(echo "$HMAC_OUTPUT" | grep "Secret:" | awk '{print $2}')

echo -e "\n${GREEN}=== Setup Complete! ===${NC}\n"
echo -e "${YELLOW}Next steps:${NC}"
echo "1. Copy fastly.toml.example to fastly.toml:"
echo "   cp fastly.toml.example fastly.toml"
echo ""
echo "2. Update fastly.toml with your GCS credentials:"
echo "   - gcs_bucket: ${GCS_BUCKET_NAME}"
echo "   - gcs_project_id: ${GCP_PROJECT_ID}"
echo "   - gcs_access_key_id: ${ACCESS_KEY_ID}"
echo "   - gcs_secret_access_key: ${SECRET_ACCESS_KEY}"
echo ""
echo "3. Test your configuration:"
echo "   fastly compute serve"
echo ""
echo -e "${YELLOW}Important: Keep your HMAC secret key secure!${NC}"
echo "If you lose it, you'll need to create new HMAC keys."
echo ""
echo "To create additional HMAC keys in the future:"
echo "  gsutil hmac create ${SERVICE_ACCOUNT_EMAIL}"
echo ""
echo "To list HMAC keys:"
echo "  gsutil hmac list"
