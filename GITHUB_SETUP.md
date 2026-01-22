# GitHub Setup Instructions

Complete guide to push your FMC Policy Export Tool to GitHub.

## Prerequisites

- Git installed on your system
- GitHub account created at https://github.com
- Project files ready to push

## Step 1: Install Git (if not already installed)

### macOS
```bash
# Check if git is installed
git --version

# If not installed, install via Homebrew
brew install git

# Or install Xcode Command Line Tools
xcode-select --install
```

### Configure Git (First Time Only)
```bash
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"
```

## Step 2: Create GitHub Repository

### Option A: Via GitHub Website (Recommended)

1. Go to https://github.com
2. Click the **+** icon in the top right corner
3. Select **"New repository"**
4. Fill in repository details:
   - **Repository name**: `fmc-policy-export-tool` (or your preferred name)
   - **Description**: "Export Cisco FMC policies to CSV with object value resolution"
   - **Visibility**: Choose Public or Private
   - **Important**: Do NOT initialize with README, .gitignore, or license (we already have these)
5. Click **"Create repository"**
6. Copy the repository URL (looks like: `https://github.com/YOUR_USERNAME/fmc-policy-export-tool.git`)

### Option B: Via GitHub CLI (Alternative)
```bash
# Install GitHub CLI (if not installed)
brew install gh

# Login to GitHub
gh auth login

# Create repository
gh repo create fmc-policy-export-tool --public --description "Export Cisco FMC policies to CSV"
```

## Step 3: Initialize Local Git Repository

```bash
# Navigate to your project directory
cd /Users/raghukul/Downloads/Policy-CSV-Generation

# Initialize git repository
git init

# Add all files to staging
git add .

# Check what will be committed
git status

# Create first commit
git commit -m "Initial commit: FMC Policy Export Tool v1.0.0

- Add main export script with multi-policy support
- Add object value resolution feature
- Add API validation tool
- Add comprehensive documentation
- Support for Access Control, NAT, Prefilter, SSL, DNS policies
- Multi-domain support
- Smart caching and rate limiting"
```

## Step 4: Connect to GitHub Repository

```bash
# Add GitHub repository as remote
# Replace YOUR_USERNAME with your actual GitHub username
git remote add origin https://github.com/YOUR_USERNAME/fmc-policy-export-tool.git

# Verify remote is added
git remote -v
```

## Step 5: Push to GitHub

```bash
# Rename default branch to main (if needed)
git branch -M main

# Push code to GitHub
git push -u origin main
```

### If You Get Authentication Errors

GitHub no longer accepts password authentication. Use one of these methods:

#### Method 1: Personal Access Token (Recommended)
1. Go to https://github.com/settings/tokens
2. Click **"Generate new token"** → **"Generate new token (classic)"**
3. Give it a name: "FMC Tool Push"
4. Select scopes: Check **"repo"** (full control of private repositories)
5. Click **"Generate token"**
6. **Copy the token immediately** (you won't see it again)
7. When pushing, use token as password:
   ```bash
   Username: YOUR_USERNAME
   Password: ghp_YOUR_TOKEN_HERE
   ```

#### Method 2: SSH Key (Advanced)
```bash
# Generate SSH key (if you don't have one)
ssh-keygen -t ed25519 -C "your.email@example.com"

# Copy public key
cat ~/.ssh/id_ed25519.pub

# Add to GitHub:
# 1. Go to https://github.com/settings/keys
# 2. Click "New SSH key"
# 3. Paste your public key
# 4. Click "Add SSH key"

# Change remote URL to SSH
git remote set-url origin git@github.com:YOUR_USERNAME/fmc-policy-export-tool.git

# Push using SSH
git push -u origin main
```

## Step 6: Verify Upload

1. Go to `https://github.com/YOUR_USERNAME/fmc-policy-export-tool`
2. You should see all your files
3. Check that README.md displays properly

## Step 7: Add Repository Details (Optional)

### Add Topics
1. Go to your repository page
2. Click the gear icon next to "About"
3. Add topics: `cisco`, `firepower`, `fmc`, `api`, `python`, `network-automation`, `security`, `csv-export`

### Add Description
Add the description if you didn't during creation:
"Export Cisco FMC policies to CSV with automatic object value resolution. Supports Access Control, NAT, Prefilter, SSL, and DNS policies."

## Complete Command Sequence (Copy-Paste Ready)

```bash
# Navigate to project
cd /Users/raghukul/Downloads/Policy-CSV-Generation

# Initialize git
git init

# Add all files
git add .

# Commit
git commit -m "Initial commit: FMC Policy Export Tool v1.0.0"

# Add remote (REPLACE YOUR_USERNAME!)
git remote add origin https://github.com/YOUR_USERNAME/fmc-policy-export-tool.git

# Push
git branch -M main
git push -u origin main
```

## Future Updates

After the initial push, use these commands for updates:

```bash
# Check status
git status

# Add modified files
git add .

# Or add specific files
git add fmc_get_config.py

# Commit changes
git commit -m "Description of changes"

# Push to GitHub
git push
```

## Common Issues and Solutions

### Issue 1: "fatal: remote origin already exists"
```bash
# Remove existing remote
git remote remove origin

# Add correct remote
git remote add origin https://github.com/YOUR_USERNAME/fmc-policy-export-tool.git
```

### Issue 2: "Updates were rejected"
```bash
# Pull changes first
git pull origin main --rebase

# Then push
git push origin main
```

### Issue 3: "Support for password authentication was removed"
**Solution**: Use Personal Access Token (see Step 5 above)

### Issue 4: Large file errors
```bash
# If CSV files are accidentally committed
git rm --cached *.csv
git commit -m "Remove CSV files from tracking"
git push
```

## What Gets Pushed

✅ **Included** (tracked by git):
- Python scripts (.py files)
- Documentation (.md files)
- Configuration (requirements.txt, .gitignore)

❌ **Excluded** (in .gitignore):
- CSV output files (*.csv)
- Python cache files (__pycache__)
- Virtual environments (venv/)
- IDE files (.vscode/, .idea/)
- Credentials and logs
- API validation reports (api_validation_report.json)

## Repository Structure on GitHub

```
fmc-policy-export-tool/
├── .gitignore
├── README.md
├── GITHUB_SETUP.md (this file)
├── API_VALIDATION.md
├── VALIDATION_SUMMARY.md
├── OBJECT_VALUE_RESOLUTION.md
├── fmc_get_config.py
├── validate_api_endpoints.py
├── requirements.txt
└── example_usage.py (if exists)
```

## Next Steps

1. ✅ Push code to GitHub
2. ✅ Verify files are visible
3. ⭐ Star your own repository
4. 📝 Create releases for versions
5. 🐛 Set up Issues for bug tracking
6. 📊 Enable GitHub Actions for CI/CD (optional)
7. 🔒 Add LICENSE file (MIT recommended)
8. 📢 Share with community

## Creating Your First Release

After pushing code:

1. Go to your repository on GitHub
2. Click **"Releases"** (right sidebar)
3. Click **"Create a new release"**
4. Click **"Choose a tag"** → Type: `v1.0.0` → **"Create new tag"**
5. Release title: `v1.0.0 - Initial Release`
6. Description:
   ```
   ## FMC Policy Export Tool v1.0.0
   
   Initial release with full functionality.
   
   ### Features
   - Export 5 policy types (Access Control, NAT, Prefilter, SSL, DNS)
   - Automatic object value resolution
   - Multi-domain support
   - Smart caching and rate limiting
   - API validation tool
   - Comprehensive documentation
   
   ### Requirements
   - Python 3.7+
   - Cisco FMC 6.x+
   - FMC API access
   ```
7. Click **"Publish release"**

## Congratulations! 🎉

Your FMC Policy Export Tool is now on GitHub!

Share your repository:
- URL: `https://github.com/YOUR_USERNAME/fmc-policy-export-tool`
- Clone command: `git clone https://github.com/YOUR_USERNAME/fmc-policy-export-tool.git`
