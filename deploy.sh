#!/usr/bin/env bash

set -e

# TODO(jason): Make this Terraform.

PROJECT=$(gcloud config get-value project)
REGION=us-east4
SA_NAME=webpush
SA_EMAIL="$SA_NAME@$PROJECT.iam.gserviceaccount.com"

# Create service account
gcloud iam service-accounts create $SA_NAME \
  --display-name="Web Push Service Account" 2>/dev/null || echo "Service account already exists"

gcloud kms keyrings create webpush-vapid-key \
  --location=global 2>/dev/null || echo "Keyring already exists"

gcloud kms keys create vapid-key \
  --location=global \
  --keyring=webpush-vapid-key \
  --purpose=asymmetric-signing \
  --default-algorithm=ec-sign-p256-sha256 2>/dev/null || echo "KMS key already exists"

echo "Granting KMS permissions to $SA_EMAIL"

# Grant permissions
gcloud kms keys add-iam-policy-binding vapid-key \
  --location=global \
  --keyring=webpush-vapid-key \
  --member="serviceAccount:$SA_EMAIL" \
  --role="roles/cloudkms.signer"

gcloud kms keys add-iam-policy-binding vapid-key \
  --location=global \
  --keyring=webpush-vapid-key \
  --member="serviceAccount:$SA_EMAIL" \
  --role="roles/cloudkms.publicKeyViewer"

# Deploy with the service account
gcloud run deploy webpush \
  --image $(KO_DOCKER_REPO=gcr.io/$PROJECT/webpush ko build ./example --sbom=none) \
  --service-account=$SA_EMAIL \
  --set-env-vars KMS_KEY_NAME=projects/$PROJECT/locations/global/keyRings/webpush-vapid-key/cryptoKeys/vapid-key/cryptoKeyVersions/1 \
  --region $REGION --allow-unauthenticated \
  --memory 4Gi --cpu 2

echo "Deployment complete!"
