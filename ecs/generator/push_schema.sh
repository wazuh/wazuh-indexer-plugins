#!/usr/bin/env bash

# Pushes generated WCS modules (index templates and CSV documentation)
# to the repository and creates or updates a Pull Request.
# Requirements:
#  - Git must be installed and configured.
#  - SSH must be installed.
#  - GitHub CLI (gh) must be installed.
#  - The script must be run in a Git repository.
#  - The script must be run in a branch (not in detached HEAD state).
#  - The script must have access to the following environment variables:
#    - COMMITER_EMAIL: Email of the committer (default: git config user.email).
#    - COMMITTER_USERNAME: Username of the committer (default: git config user.name).
#    - SSH_PRIVATE_KEY: Private SSH key for commit signing.
#    - SSH_PUBLIC_KEY: Public SSH key for commit signing.
#    - GITHUB_TOKEN: GitHub token to authenticate with GitHub API.
#    - GITHUB_RUN_ID: (Optional) GitHub Actions run ID, to detect if the script is run in a GitHub Actions workflow.
#  - The GitHub token must have permissions to create branches and pull requests.

# Constants
ECS_VERSION=${ECS_VERSION:-v9.1.0}
BASE_BRANCH=${BASE_BRANCH:-main}

# Committer's identity
COMMITER_EMAIL=${COMMITER_EMAIL:-$(git config user.email)}
COMMITTER_USERNAME=${COMMITTER_USERNAME:-$(git config user.name)}

set -euo pipefail

# ====
# Configure Git
#  - Set the committer's identity (email and username).
#  - Store the SSH key pair so Git can read it.
#  - Setup commit signing using the SSH key pair.
# ====
function configure_git() {
  echo
  echo "---> Configuring Git..."
  # Setup the committers identity.
  git config --global user.email "${COMMITER_EMAIL}"
  git config --global user.name "${COMMITTER_USERNAME}"

  # Store the SSH key pair so Git can read it.
  mkdir -p ~/.ssh/
  echo "${SSH_PRIVATE_KEY}" >~/.ssh/id_ed25519_bot
  echo "${SSH_PUBLIC_KEY}" >~/.ssh/id_ed25519_bot.pub
  chmod 600 ~/.ssh/id_ed25519_bot
  chmod 644 ~/.ssh/id_ed25519_bot.pub

  # Setup commit signing
  eval "$(ssh-agent -s)"
  ssh-add ~/.ssh/id_ed25519_bot
  git config --global gpg.format ssh
  git config --global commit.gpgsign true
  git config --global user.signingkey ~/.ssh/id_ed25519_bot.pub
}

# ====
# Commit and push the WCS changes.
# ====
function push_changes() {
  echo
  echo "---> Pushing changes to the repository..."
  if ! git diff-index --quiet HEAD --; then
    git add plugins/setup/src/main/resources/*.json
    git add ecs/**/docs/fields.csv
    git add ecs/module_list.txt
    git status --short
    git commit -m "Update the Wazuh Common Schema"
    git push
  else
    echo "  Nothing to commit, working tree clean."
    exit 0
  fi
}

# ====
# Create a pull request.
# ====
function create_pr() {
  echo
  echo "---> Creating pull request..."

  # Store the PAT in a file that can be accessed by the GitHub CLI.
  echo "${GITHUB_TOKEN}" >token.txt
  # Authorize GitHub CLI for the current repository.
  gh auth login --with-token <token.txt || true # Ignore authentication warning

  # Create pull request.
  local branch=$1
  local title="Update Wazuh Common Schema"
  local body="This PR updates the Wazuh Common Schema."
  local pull_request_exists
  local pull_request_link
  pull_request_exists=$(gh pr list --head "${branch}" --json number --jq '.[].number')
  if [ -z "${pull_request_exists}" ]; then
    pull_request_link=$(gh pr create --title "${title}" --body "${body}" --head "${branch}" --base "${BASE_BRANCH}")
    echo "Pull request created: ${pull_request_link}"
  else
    pull_request_link=$(gh pr view "${pull_request_exists}" --json url --jq '.url')
    echo "Pull request already exists: ${pull_request_link}"
  fi
  # Save pull request link to file so it can be read from the GH Workflow
  # to create an annotation with the link.
  echo "${pull_request_link}" > /tmp/pull_request_link.txt
}

# ====
# Main function.
# ====
function main() {
  # Abort if the script is not running in a GitHub runner.
  if [ -z "${GITHUB_RUN_ID}" ]; then
    echo "Error: This script must be run in a GitHub Actions workflow." >&2
    exit 1
  fi

  # Abort if current folder is not a Git repository.
  if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "Error: You are not in a Git repository." >&2
    exit 1
  fi

  # Abort if GH CLI is not installed.
  if ! command -v gh &>/dev/null; then
    echo "Error: GitHub CLI (gh) is not installed. Please install it and try again." >&2
    exit 1
  fi

  # Abort if GITHUB_TOKEN is not set.
  if [ -z "${GITHUB_TOKEN:-}" ]; then
    echo "Error: GITHUB_TOKEN environment variable is not set." >&2
    exit 1
  fi

  # Set branch name to current branch if not provided.
  local branch
  branch=$(git rev-parse --abbrev-ref HEAD)

  configure_git
  push_changes
  create_pr "${branch}"
}

main "$@"
