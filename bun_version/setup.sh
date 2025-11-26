#!/usr/bin/env bash

# Setup script for search_vulns Bun.js version
# This script helps set up the database files needed for search_vulns to work

set -e

echo "search_vulns Bun.js/TypeScript Setup"
echo "===================================="
echo ""

# Create resources directory
echo "[1/3] Creating resources directory..."
mkdir -p resources

# Check if database files exist in parent Python version
PYTHON_RESOURCES="../src/search_vulns/resources"
if [ -d "$PYTHON_RESOURCES" ]; then
    echo "[2/3] Found Python version resources. Copying database files..."
    
    if [ -f "$PYTHON_RESOURCES/vulndb.db3" ]; then
        cp "$PYTHON_RESOURCES/vulndb.db3" resources/
        echo "  ✓ Copied vulndb.db3"
    else
        echo "  ✗ vulndb.db3 not found in Python version"
    fi
    
    if [ -f "$PYTHON_RESOURCES/productdb.db3" ]; then
        cp "$PYTHON_RESOURCES/productdb.db3" resources/
        echo "  ✓ Copied productdb.db3"
    else
        echo "  ✗ productdb.db3 not found in Python version"
    fi
else
    echo "[2/3] Python version resources not found. You'll need to download database files manually."
    echo ""
    echo "To get the database files:"
    echo "  1. Install the Python version: pip install search_vulns"
    echo "  2. Run: search_vulns -u"
    echo "  3. Copy the database files from the Python installation to this directory's resources/ folder"
fi

# Check if database files were successfully copied
echo ""
echo "[3/3] Verifying setup..."
if [ -f "resources/vulndb.db3" ] && [ -f "resources/productdb.db3" ]; then
    echo "  ✓ Setup complete! Database files are in place."
    echo ""
    echo "You can now run:"
    echo "  bun src/cli.ts -q 'CVE-2024-27286'"
    echo "  bun src/server.ts"
else
    echo "  ✗ Database files are missing. Please obtain them as described above."
fi

echo ""
echo "===================================="
