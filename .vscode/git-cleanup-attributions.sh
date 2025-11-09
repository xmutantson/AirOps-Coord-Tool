#!/bin/bash
set -e

echo "=================================================="
echo "Git Cleanup: Remove Co-Authored-By Attributions"
echo "=================================================="
echo ""
echo "This script will:"
echo "  1. Create a backup branch"
echo "  2. Remove Co-Authored-By and Claude Code attributions"
echo "  3. Clean up git references"
echo "  4. Optionally delete backup and garbage collect"
echo "  5. Force push to remote"
echo ""
echo "WARNING: This rewrites git history!"
echo ""

# Step 1: Create backup branch
echo "Step 1/7: Creating backup branch..."
git branch backup-before-removing-attributions 2>/dev/null || {
    echo "Backup branch already exists. Delete it first if you want to recreate."
    read -p "Delete existing backup and continue? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        git branch -D backup-before-removing-attributions
        git branch backup-before-removing-attributions
    else
        echo "Aborted."
        exit 1
    fi
}
echo "✓ Backup branch created: backup-before-removing-attributions"
echo ""

# Step 1.5: Clean working directory (fix line ending issues between Windows/WSL)
echo "Step 1.5/7: Cleaning working directory..."
git reset --hard HEAD
git config core.autocrlf false
# Normalize the index to ignore line ending differences
git ls-files -z | xargs -0 git update-index --assume-unchanged || true
echo "✓ Working directory cleaned"
echo ""

# Step 2: Remove attributions
echo "Step 2/7: Removing attributions from commit messages..."
read -p "Continue with filter-branch? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 1
fi

# Temporarily disable autocrlf during filter-branch
FILTER_BRANCH_SQUELCH_WARNING=1 git -c core.autocrlf=false filter-branch --force --msg-filter 'sed -e "/^Co-Authored-By:/d" -e "/🤖 Generated with \[Claude Code\]/d" | sed -e :a -e "/^\s*$/{\$d;N;ba" -e "}"' -- --all

# Re-enable change tracking on all files
git ls-files -z | xargs -0 git update-index --no-assume-unchanged || true

echo "✓ Attributions removed"
echo ""

# Step 3: Clean up filter-branch refs
echo "Step 3/7: Cleaning up filter-branch backup refs..."
git for-each-ref --format="%(refname)" refs/original/ | xargs -n 1 git update-ref -d
echo "✓ Filter-branch refs cleaned"
echo ""

# Step 4: Delete backup branch (optional)
echo "Step 4/7: Delete backup branch (optional)..."
read -p "Delete backup branch? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    git branch -D backup-before-removing-attributions
    echo "✓ Backup branch deleted"
else
    echo "⊘ Backup branch kept"
fi
echo ""

# Step 5: Expire reflog (optional)
echo "Step 5/7: Expire reflog immediately (optional)..."
read -p "Expire reflog? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    git reflog expire --expire=now --all
    git reflog expire --expire-unreachable=now --all
    echo "✓ Reflog expired"
else
    echo "⊘ Reflog not expired"
fi
echo ""

# Step 6: Garbage collection (optional)
echo "Step 6/7: Aggressive garbage collection (optional)..."
read -p "Run garbage collection? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    git gc --prune=now --aggressive
    echo "✓ Garbage collection completed"
else
    echo "⊘ Garbage collection skipped"
fi
echo ""

# Step 7: Force push
echo "Step 7/7: Force push to remote..."
echo "WARNING: This will update remote history!"
read -p "Force push to origin main? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    git push --force-with-lease origin main
    echo "✓ Pushed to remote"
else
    echo "⊘ Push skipped (you can manually push later)"
fi
echo ""

echo "=================================================="
echo "✓ Cleanup complete!"
echo "=================================================="
