# GitHub Push Quick Reference

## 🚀 Fastest Way (Automated Script)

```bash
cd /Users/raghukul/Downloads/Policy-CSV-Generation
./github_push.sh YOUR_GITHUB_USERNAME
```

The script will:
- Initialize git
- Add all files
- Create commit
- Add remote
- Push to GitHub

---

## 📝 Manual Method (Step by Step)

### 1. Create Repository on GitHub
1. Go to https://github.com/new
2. Name: `fmc-policy-export-tool`
3. **DO NOT** initialize with README
4. Click "Create repository"
5. Copy the URL

### 2. Initialize and Push
```bash
cd /Users/raghukul/Downloads/Policy-CSV-Generation

# Initialize
git init
git add .
git commit -m "Initial commit: FMC Policy Export Tool v1.0.0"

# Connect to GitHub (replace YOUR_USERNAME)
git remote add origin https://github.com/YOUR_USERNAME/fmc-policy-export-tool.git

# Push
git branch -M main
git push -u origin main
```

### 3. Authenticate
When prompted for password, use Personal Access Token:
1. Go to https://github.com/settings/tokens
2. Generate new token (classic)
3. Check "repo" scope
4. Copy token
5. Use as password

---

## 🔄 Future Updates

After initial push, use:

```bash
# Check what changed
git status

# Add and commit
git add .
git commit -m "Description of changes"

# Push
git push
```

---

## 📦 What Gets Uploaded

✅ **Yes:**
- Python scripts
- Documentation
- Requirements
- .gitignore

❌ **No:**
- CSV files
- Cache files
- Virtual environments
- IDE settings

---

## 🆘 Troubleshooting

### "remote origin already exists"
```bash
git remote remove origin
git remote add origin https://github.com/USERNAME/fmc-policy-export-tool.git
```

### "authentication failed"
Use Personal Access Token instead of password.

### "repository not found"
Create the repository on GitHub first: https://github.com/new

---

## ✅ Verification

After push, visit:
```
https://github.com/YOUR_USERNAME/fmc-policy-export-tool
```

You should see all files including README.md

---

## 📞 Quick Links

- Create repo: https://github.com/new
- Tokens: https://github.com/settings/tokens
- Your repos: https://github.com/YOUR_USERNAME?tab=repositories
- Git docs: https://git-scm.com/doc

---

## 🎯 Complete Copy-Paste Command

Replace `YOUR_USERNAME` and run:

```bash
cd /Users/raghukul/Downloads/Policy-CSV-Generation && \
git init && \
git add . && \
git commit -m "Initial commit: FMC Policy Export Tool v1.0.0" && \
git remote add origin https://github.com/YOUR_USERNAME/fmc-policy-export-tool.git && \
git branch -M main && \
git push -u origin main
```

---

**Need help?** See [GITHUB_SETUP.md](GITHUB_SETUP.md) for detailed instructions.
