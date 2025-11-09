# 🚀 Docker Build & Push - Quick Reference

## One-Click Build & Push

Press **`Ctrl+Shift+B`** → Builds and pushes to GHCR with **two tags**:
- `ghcr.io/xmutantson/aircraft_ops_tool:latest`
- `ghcr.io/xmutantson/aircraft_ops_tool:v<TODAY>` (auto-generated from current date)

**Platforms:** `linux/amd64`, `linux/386`, `linux/arm/v7`, `linux/arm64`

**Example tags created today:** `latest` and `v2025.01.07`

---

## All Available Tasks

### Docker Tasks

| Emoji | Task Name | What It Does |
|-------|-----------|--------------|
| 🚀 | **Build & Push** | Build multi-platform + push with latest & date tags (DEFAULT) |
| 🏠 | Build Local (Fast Test) | Quick local build, no push (for testing) |
| 🔧 | Setup Buildx (First Time) | Configure Docker buildx for cross-platform builds |
| 🔐 | Login to GHCR | Authenticate to GitHub Container Registry |
| 📊 | Docker System Info | Show Docker version, buildx status, images |
| 🧹 | Clean Up Old Images | Remove dangling images to free disk space |
| 🔍 | View GHCR Images | List your pushed images |

### Git Tasks

| Emoji | Task Name | What It Does |
|-------|-----------|--------------|
| 🧹 | **Git: Remove Co-Authored-By Attributions** | Removes Co-Authored-By and Claude Code attributions from commit history |

### How to Run Tasks

1. Press `Ctrl+Shift+P`
2. Type `task`
3. Select "Tasks: Run Task"
4. Pick the task you want

---

## First-Time Setup (Do This Once!)

### Step 1: Install Docker Desktop
Download from https://www.docker.com/products/docker-desktop

### Step 2: Setup Buildx (REQUIRED for cross-platform builds!)
**Run the task:** `🔧 Setup Buildx (First Time)`

Or manually in terminal:
```bash
docker buildx create --use --name multiplatform --driver docker-container --bootstrap
```

This enables cross-compilation so you can build for ARM, x86, etc. from your machine.

### Step 3: Login to GHCR
**Run the task:** `🔐 Login to GHCR`

You'll need:
- **Username:** `xmutantson`
- **Password:** Your GitHub Personal Access Token
  - Create at: https://github.com/settings/tokens
  - Required permission: `write:packages`

### Step 4: Verify Setup
**Run the task:** `📊 Docker System Info`

You should see:
- ✅ Docker version
- ✅ Buildx version
- ✅ A builder named `multiplatform` in the list

---

## Common Workflows

### 🎯 Normal Workflow (Most Common)
```
1. Make your code changes
2. Press Ctrl+Shift+B
3. Wait for build to complete
4. On your other machine: docker pull ghcr.io/xmutantson/aircraft_ops_tool:latest
5. Done! ✅
```

### 🧪 Test Before Pushing
```
1. Make changes
2. Run: 🏠 Build Local (Fast Test)
3. Test locally if needed
4. Press Ctrl+Shift+B to push for real
```

### 🔍 Check What You've Pushed
```
Run: 🔍 View GHCR Images
```

### 🧹 Free Up Disk Space
```
Run: 🧹 Clean Up Old Images
(Docker builds can use a lot of disk space over time)
```

---

## Understanding the Build Process

### What Happens When You Press Ctrl+Shift+B

1. **Generates date tag:** Uses `date +%Y.%m.%d` to create `v2025.01.07` (or current date)
2. **Builds for 4 platforms:**
   - `linux/amd64` (x86-64, most servers)
   - `linux/386` (x86-32, older systems)
   - `linux/arm/v7` (Raspberry Pi, older ARM)
   - `linux/arm64` (Modern ARM, Apple Silicon, newer Pi)
3. **Uses build cache** from registry (faster subsequent builds)
4. **Pushes two tags:**
   - `:latest` (always overwrites)
   - `:v2025.01.07` (permanent version based on today's date)
5. **Stores build cache** for next time

### Why Buildx?

**Without buildx:** You can only build for your current platform (e.g., Windows → amd64 only)

**With buildx:** You can cross-compile for ARM, x86, etc. from any machine!

This is done using QEMU emulation and Docker's buildkit backend.

---

## When Things Go Wrong

### ❌ "buildx: command not found" or "unknown flag: --platform"
**Solution:** Run `🔧 Setup Buildx (First Time)`

Docker Desktop includes buildx, but you need to create a builder instance first.

### ❌ "permission denied" or "unauthorized"
**Solutions:**
1. Run `🔐 Login to GHCR`
2. Make sure your token has `write:packages` permission
3. Check token hasn't expired

### ❌ Build is very slow (20+ minutes)
**This is normal for the first build!**
- Downloading base images takes time
- Building for 4 platforms takes time
- Subsequent builds use cache (much faster)

**To speed up testing:**
- Use `🏠 Build Local (Fast Test)` (builds only for your platform)
- First build: ~20-30 minutes
- Later builds: ~5-10 minutes (with cache)

### ❌ Build failed with "no space left on device"
**Solution:** Run `🧹 Clean Up Old Images`

Or manually: `docker system prune -a`

### ❌ Can't find the builder "multiplatform"
**Solution:** Run `🔧 Setup Buildx (First Time)` again

Check current builders: `docker buildx ls`

---

## Understanding Tags

### `:latest` Tag
- Always points to the most recent push
- Your other machine can do: `docker pull ...:latest`
- Gets overwritten on every build

### Date Tags (`:vYYYY.MM.DD`)
- Auto-generated from current date when you build
- Format: `v2025.01.07`, `v2025.01.15`, etc.
- Permanent version you can rollback to
- Never gets overwritten
- Useful for tracking what changed when
- Can specify exact version on other machine

**Example:**
```bash
# On your other machine:
docker pull ghcr.io/xmutantson/aircraft_ops_tool:latest

# Or specific version (if you built on Jan 6th):
docker pull ghcr.io/xmutantson/aircraft_ops_tool:v2025.01.06
```

**Note:** If you build multiple times in one day, the date tag gets overwritten. For unique builds, manually add a suffix like `v2025.01.07-fix2` by editing the task.

---

## Git History Cleanup

### ✨ Automatic Attribution Filtering (NEW!)

**Good news:** All new commits automatically have attributions removed!

A git `commit-msg` hook has been installed that automatically filters out:
- `Co-Authored-By: Claude <noreply@anthropic.com>`
- `🤖 Generated with [Claude Code]`

This happens automatically every time you commit - no action needed!

**Location:** `.git/hooks/commit-msg`

---

### 🧹 Remove Co-Authored-By Attributions (For Old Commits)

This task removes attributions from **existing commit history**.

**How to run:**
1. Press `Ctrl+Shift+P`
2. Type `task`
3. Select "Tasks: Run Task"
4. Choose "🧹 Git: Remove Co-Authored-By Attributions"

**What it does:**
1. ✅ Creates a backup branch (`backup-before-removing-attributions`)
2. ✅ Removes Co-Authored-By and Claude Code attributions from all commit messages
3. ✅ Cleans up internal git references
4. ✅ Optionally deletes backup and garbage collects
5. ✅ Optionally force-pushes to remote repository

**Interactive prompts:**
- The script will ask for confirmation at each major step
- You can abort at any time
- Backup branch is created first for safety

**⚠️ Warning:**
- This rewrites git history
- If you've already pushed commits, you'll need to force-push
- Coordinate with team members if working on a shared repository
- The `--force-with-lease` flag prevents overwriting others' work

**After cleanup:**
Your commit history will be clean without automation attributions, while preserving all actual code changes.

---

## Tips & Tricks

💡 **Pin this file** - Right-click tab → "Pin Tab"

💡 **First build?** Grab coffee! Multi-platform builds take 20-30 minutes initially

💡 **Regular builds?** With cache, ~5-10 minutes

💡 **Testing changes?** Use `🏠 Build Local` (much faster, 2-3 minutes)

💡 **Low on disk?** Run `🧹 Clean Up Old Images` monthly

💡 **Check status** - Run `📊 Docker System Info` anytime

💡 **Track versions** - Date tags let you see what you pushed when

💡 **Multiple builds same day?** The date tag will be the same - check the terminal output to confirm

---

## Quick Reference Commands

### Docker Commands
```bash
# View local images
docker images | grep aircraft_ops_tool

# View buildx builders
docker buildx ls

# Manual login
docker login ghcr.io -u xmutantson

# Check disk usage
docker system df

# Clean everything (careful!)
docker system prune -a

# See what tag would be generated today
date +%Y.%m.%d
```

### Git Commands
```bash
# View commit history to check for attributions
git log --oneline

# View full commit message
git log -1

# Check if backup branch exists
git branch | grep backup-before-removing-attributions

# Manually restore from backup (if needed)
git reset --hard backup-before-removing-attributions
```

---

Need more details? See [README.md](README.md)