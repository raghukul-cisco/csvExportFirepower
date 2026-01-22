#!/bin/bash
#
# Quick setup script for pushing FMC Policy Export Tool to GitHub
# Usage: ./github_push.sh YOUR_GITHUB_USERNAME
#

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "================================"
echo "FMC Policy Export Tool"
echo "GitHub Push Setup Script"
echo "================================"
echo

# Check if username provided
if [ -z "$1" ]; then
    echo -e "${YELLOW}Usage: ./github_push.sh YOUR_GITHUB_USERNAME${NC}"
    echo
    read -p "Enter your GitHub username: " GITHUB_USERNAME
else
    GITHUB_USERNAME=$1
fi

REPO_NAME="fmc-policy-export-tool"
REPO_URL="https://github.com/${GITHUB_USERNAME}/${REPO_NAME}.git"

echo -e "${GREEN}Repository URL: ${REPO_URL}${NC}"
echo

# Check if git is installed
if ! command -v git &> /dev/null; then
    echo -e "${RED}Error: git is not installed${NC}"
    echo "Install git first:"
    echo "  brew install git"
    exit 1
fi

# Check if already a git repository
if [ -d ".git" ]; then
    echo -e "${YELLOW}Warning: This is already a git repository${NC}"
    read -p "Do you want to continue? This will add a new remote. (y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
else
    echo "Initializing git repository..."
    git init
fi

# Configure git if not configured
if ! git config user.name &> /dev/null; then
    echo -e "${YELLOW}Git user not configured${NC}"
    read -p "Enter your name: " GIT_NAME
    git config --global user.name "$GIT_NAME"
fi

if ! git config user.email &> /dev/null; then
    echo -e "${YELLOW}Git email not configured${NC}"
    read -p "Enter your email: " GIT_EMAIL
    git config --global user.email "$GIT_EMAIL"
fi

# Add files
echo "Adding files..."
git add .

# Show what will be committed
echo
echo "Files to be committed:"
git status --short

echo
read -p "Continue with commit? (y/n): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 1
fi

# Commit
echo "Creating commit..."
git commit -m "Initial commit: FMC Policy Export Tool v1.0.0

- Add main export script with multi-policy support
- Add object value resolution feature
- Add API validation tool
- Add comprehensive documentation
- Support for Access Control, NAT, Prefilter, SSL, DNS policies
- Multi-domain support
- Smart caching and rate limiting"

# Check if remote exists
if git remote | grep -q "^origin$"; then
    echo -e "${YELLOW}Remote 'origin' already exists${NC}"
    CURRENT_URL=$(git remote get-url origin)
    echo "Current URL: $CURRENT_URL"
    echo "New URL: $REPO_URL"
    read -p "Update remote URL? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        git remote set-url origin "$REPO_URL"
        echo -e "${GREEN}Remote updated${NC}"
    fi
else
    echo "Adding remote..."
    git remote add origin "$REPO_URL"
fi

# Rename branch to main
echo "Setting branch to main..."
git branch -M main

# Push
echo
echo -e "${GREEN}Ready to push to GitHub!${NC}"
echo
echo "IMPORTANT: If authentication fails, you need a Personal Access Token"
echo "1. Go to: https://github.com/settings/tokens"
echo "2. Generate new token (classic)"
echo "3. Select 'repo' scope"
echo "4. Use token as password when prompted"
echo
read -p "Push to GitHub now? (y/n): " -n 1 -r
echo

if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Pushing to GitHub..."
    if git push -u origin main; then
        echo
        echo -e "${GREEN}================================${NC}"
        echo -e "${GREEN}Success! Repository pushed to GitHub${NC}"
        echo -e "${GREEN}================================${NC}"
        echo
        echo "View your repository at:"
        echo "  https://github.com/${GITHUB_USERNAME}/${REPO_NAME}"
        echo
        echo "Clone command:"
        echo "  git clone ${REPO_URL}"
        echo
    else
        echo
        echo -e "${RED}Push failed!${NC}"
        echo
        echo "Common issues:"
        echo "1. Repository doesn't exist - Create it at: https://github.com/new"
        echo "2. Authentication failed - Use Personal Access Token instead of password"
        echo "3. Permission denied - Check repository access rights"
        echo
        echo "Manual push command:"
        echo "  git push -u origin main"
    fi
else
    echo
    echo "Skipped push. To push manually later:"
    echo "  git push -u origin main"
fi

echo
echo -e "${GREEN}Setup complete!${NC}"
