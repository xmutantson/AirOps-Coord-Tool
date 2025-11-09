# VSCode Tasks for Aircraft Ops Tool

This directory contains VSCode configuration files to help you build and deploy the Docker image.

## Available Tasks

To run any task:
1. Press `Ctrl+Shift+P` (Windows/Linux) or `Cmd+Shift+P` (Mac)
2. Type "Tasks: Run Task"
3. Select one of the tasks below

### Quick Access

**Fastest Method:**
- Press `Ctrl+Shift+B` to run the default build task: **🚀 Build & Push**
- This will build for all platforms and push with `latest` + date tags!

**Alternative Method:**
1. Press `Ctrl+Shift+P`
2. Type `task`
3. Select "Tasks: Run Task"
4. Pick the task you want from the emoji menu

💡 **Pro Tip:** See [SHORTCUTS.md](SHORTCUTS.md) for a visual quick reference guide!

### Tasks Overview

#### 🚀 **Build & Push (latest + date tag)** ⭐ DEFAULT
- Builds the multi-platform image
- Auto-tags with today's date: `v2025.01.07` (generated from `date +%Y.%m.%d`)
- Also tags as `:latest`
- Pushes to `ghcr.io/xmutantson/aircraft_ops_tool`
- Uses registry cache for faster builds
- **Platforms:** `linux/amd64`, `linux/386`, `linux/arm/v7`, `linux/arm64`
- **This is your one-click build & push!**

#### 🏠 **Build Local (Fast Test)**
- Quick local build for testing
- Only builds for your current platform
- Doesn't push to registry
- Faster than multi-platform build
- Good for verifying changes before pushing

#### 🔧 **Setup Buildx (First Time)**
- Configures Docker buildx for cross-platform builds
- Creates a builder named `multiplatform`
- **Run this once before your first build!**
- Required for multi-platform support

#### 🔐 **Login to GHCR**
- Logs in to GitHub Container Registry
- Run this first if you get authentication errors
- You'll need your GitHub Personal Access Token

#### 📊 **Docker System Info**
- Shows Docker version
- Shows buildx version and configured builders
- Lists local images
- Shows disk usage
- Good for verifying setup

#### 🧹 **Clean Up Old Images**
- Removes dangling images
- Frees up disk space
- Docker builds accumulate over time

#### 🔍 **View GHCR Images**
- Lists your pushed images
- Shows available tags

## Prerequisites

### Required Software
- **Docker Desktop** with buildx support
- **Git Bash** (for Windows) or any bash shell
- **GitHub Personal Access Token** with `write:packages` permission

### First-Time Setup

1. **Install Docker Desktop**
   - Download from https://www.docker.com/products/docker-desktop
   - Make sure it's running before building

2. **Setup Docker Buildx** (REQUIRED!)
   - Run the task: **🔧 Setup Buildx (First Time)**
   - Or manually: `docker buildx create --use --name multiplatform --driver docker-container --bootstrap`
   - This enables cross-platform builds (ARM, x86, etc.)

3. **Login to GitHub Container Registry**
   - Create a Personal Access Token at https://github.com/settings/tokens
   - Give it `write:packages` and `read:packages` permissions
   - Run the task: **🔐 Login to GHCR**
   - When prompted, use your GitHub username and paste the token as password

4. **Verify Setup**
   - Run the task: **📊 Docker System Info**
   - You should see buildx version and a `multiplatform` builder listed

## Customization

Edit [`.vscode/tasks.json`](tasks.json) to customize:

- **GHCR_USER**: Change `xmutantson` to your GitHub username
- **Platforms**: Modify the `--platform` flag to add/remove architectures
- **Date format**: Change `date +%Y.%m.%d` if you want a different tag format

## Troubleshooting

### "docker buildx: command not found"
- Update Docker Desktop to the latest version
- Or run: `docker buildx create --use`

### "Permission denied" on GHCR push
- Run the "Docker: Login to GHCR" task
- Make sure your token has `write:packages` permission

### Build is slow
- The first build will be slow as it downloads base images
- Subsequent builds use the registry cache (`buildcache`)
- Local builds (amd64 only) are much faster for testing

### Task won't run
- Make sure Git Bash is installed (Windows)
- Or change `terminal.integrated.defaultProfile.windows` in settings.json to your preferred shell

## Tips

- Use **Ctrl+Shift+B** for quick access to build & push
- The date-based tags (`v2025.01.07`) help you track versions
- Always test with "Build Local" before doing a full multi-platform push
- First build takes 20-30 minutes; later builds with cache: ~5-10 minutes
- Run "Clean Up Old Images" periodically to free disk space
