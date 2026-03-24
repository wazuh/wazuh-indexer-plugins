#!/bin/bash
# Script to open a PR to Security Analytics Plugin if finding-enrichment mapping changed
# Environment variables expected:
#   GITHUB_TOKEN: GitHub token for authentication
#   COMMITER_EMAIL: Git committer email
#   COMMITTER_USERNAME: Git committer username
#   SSH_PRIVATE_KEY: SSH private key for signing commits
#   SSH_PUBLIC_KEY: SSH public key for signing commits
#   PR_TITLE: Title of the PR
#   SOURCE_PR_URL: URL of the source PR
#   GITHUB_WORKSPACE: GitHub workspace path

set -e

SAP_REPO="wazuh/wazuh-indexer-security-analytics"
SAP_MAPPING_PATH="src/main/resources/mappings/wazuh-finding-enrichment-mapping.json"
MAPPING_FILE="${GITHUB_WORKSPACE}/plugins/setup/src/main/resources/wazuh-finding-enrichment-mapping.json"

if [[ ! -f "$MAPPING_FILE" ]]; then
  echo "Finding-enrichment mapping was not generated. Skipping."
  exit 0
fi

# Clone the SAP repository
SAP_DIR=$(mktemp -d)
git clone "https://x-access-token:${GITHUB_TOKEN}@github.com/${SAP_REPO}.git" "$SAP_DIR"

# Compare with existing mapping in SAP
if diff -q "$MAPPING_FILE" "$SAP_DIR/$SAP_MAPPING_PATH" > /dev/null 2>&1; then
  echo "Finding-enrichment mapping is unchanged. No PR needed."
  rm -rf "$SAP_DIR"
  exit 0
fi

echo "Finding-enrichment mapping has changed. Opening PR to ${SAP_REPO}..."

# Configure git identity
cd "$SAP_DIR"
git config user.email "${COMMITER_EMAIL}"
git config user.name "${COMMITTER_USERNAME}"

# Set up commit signing
mkdir -p ~/.ssh/
echo "${SSH_PRIVATE_KEY}" > ~/.ssh/id_ed25519_bot
echo "${SSH_PUBLIC_KEY}" > ~/.ssh/id_ed25519_bot.pub
chmod 600 ~/.ssh/id_ed25519_bot
chmod 644 ~/.ssh/id_ed25519_bot.pub
eval "$(ssh-agent -s)"
ssh-add ~/.ssh/id_ed25519_bot
git config gpg.format ssh
git config commit.gpgsign true
git config user.signingkey ~/.ssh/id_ed25519_bot.pub

# Create branch and commit
BRANCH_NAME="automated/update-finding-enrichment-mapping"
git checkout -B "$BRANCH_NAME"
cp "$MAPPING_FILE" "$SAP_MAPPING_PATH"
git add "$SAP_MAPPING_PATH"

git commit -m "Update wazuh-finding-enrichment-mapping.json" \
  -m "Automated update from wazuh-indexer-plugins." \
  -m "Source PR: ${SOURCE_PR_URL}"
git push --force origin "$BRANCH_NAME"

# Create or update PR using GitHub CLI
EXISTING_PR=$(gh pr list --repo "$SAP_REPO" --head "$BRANCH_NAME" --json number --jq '.[].number')

if [[ -z "$EXISTING_PR" ]]; then
  SAP_PR_LINK=$(gh pr create \
    --repo "$SAP_REPO" \
    --title "$PR_TITLE" \
    --body "Automated update of the finding-enrichment mapping from [wazuh-indexer-plugins](${SOURCE_PR_URL})." \
    --head "$BRANCH_NAME" \
    --base main)
  echo "::notice::SAP PR created: ${SAP_PR_LINK}"
else
  SAP_PR_LINK=$(gh pr view "$EXISTING_PR" --repo "$SAP_REPO" --json url --jq '.url')
  echo "::notice::SAP PR already exists: ${SAP_PR_LINK}"
fi

rm -rf "$SAP_DIR"
