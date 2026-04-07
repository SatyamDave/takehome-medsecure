#!/bin/bash
#
# SecureLoop Setup Script
# 
# This script initializes the medsecure-platform repository and commits all files.
# It sets up the initial state for the SecureLoop demo.
#
# Usage:
#   ./setup_repo.sh [--skip-install]
#

set -e

SKIP_INSTALL=false

for arg in "$@"; do
    case $arg in
        --skip-install)
            SKIP_INSTALL=true
            shift
            ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$SCRIPT_DIR/medsecure-platform"

echo "========================================"
echo "  SecureLoop Repository Setup"
echo "========================================"

# Check if medsecure-platform exists
if [ ! -d "$REPO_DIR" ]; then
    echo "ERROR: medsecure-platform directory not found at $REPO_DIR"
    exit 1
fi

cd "$REPO_DIR"

echo ""
echo "Step 1: Checking Python environment..."

if [ "$SKIP_INSTALL" = false ]; then
    # Check if Python is available
    if ! command -v python3 &> /dev/null; then
        echo "ERROR: python3 not found. Please install Python 3.8+"
        exit 1
    fi
    
    # Check if virtual environment exists, create if not
    if [ ! -d "venv" ]; then
        echo "Creating virtual environment..."
        python3 -m venv venv
    fi
    
    echo "Activating virtual environment..."
    source venv/bin/activate
    
    echo "Installing dependencies..."
    pip install --upgrade pip
    pip install flask flask-cors psycopg2-binary pymongo requests pyjwt cryptography
    pip install pytest
    
    echo "Dependencies installed successfully"
else
    echo "Skipping dependency installation (--skip-install)"
fi

echo ""
echo "Step 2: Verifying project structure..."

# Check critical files
REQUIRED_FILES=(
    "src/app.py"
    "src/config.py"
    "src/auth/login.py"
    "src/auth/tokens.py"
    "src/patients/records.py"
    "src/patients/search.py"
    "src/patients/export.py"
    "src/api/webhooks.py"
    "src/api/integrations.py"
    "SECURITY_ISSUES.json"
    "requirements.txt"
)

for file in "${REQUIRED_FILES[@]}"; do
    if [ ! -f "$file" ]; then
        echo "ERROR: Required file not found: $file"
        exit 1
    fi
    echo "  ✓ $file"
done

echo ""
echo "Step 3: Initializing git repository..."

if [ ! -d ".git" ]; then
    git init
    git config user.name "SecureLoop Demo"
    git config user.email "demo@secureloop.ai"
    echo "Git repository initialized"
fi

# Create .gitignore
cat > .gitignore << 'EOF'
venv/
__pycache__/
*.pyc
*.pyo
.env
*.egg-info/
dist/
build/
.pytest_cache/
.coverage
htmlcov/
*.log
state.json
.DS_Store
EOF

echo ""
echo "Step 4: Setting up test database (mock)..."

# Create mock database initialization
cat > init_db.py << 'EOF'
"""Initialize mock database for demo purposes."""
import psycopg2
from datetime import datetime

# Mock database initialization
def init_db():
    """Initialize the database with mock data."""
    print("Initializing mock database...")
    print("  - Creating healthcare_providers table")
    print("  - Creating user_sessions table") 
    print("  - Creating patient_records table")
    print("Database initialization complete (mock)")

if __name__ == "__main__":
    init_db()
EOF

echo "  ✓ init_db.py created"

echo ""
echo "Step 5: Testing application startup..."

# Quick syntax check
python3 -m py_compile src/app.py || {
    echo "ERROR: Application has syntax errors"
    exit 1
}
echo "  ✓ Application syntax valid"

echo ""
echo "Step 6: Creating initial state file..."

cat > ../secureloop/state.json << 'EOF'
{
  "issues": [],
  "sessions": [],
  "last_updated": "2025-04-06T12:00:00.000000Z",
  "metrics": {
    "total_issues": 10,
    "fixed": 0,
    "pending": 10,
    "in_progress": 0,
    "mean_time_to_remediation_hours": 0,
    "severity_breakdown": {
      "critical": 6,
      "high": 4,
      "medium": 0,
      "low": 0
    }
  }
}
EOF

echo "  ✓ state.json created"

echo ""
echo "========================================"
echo "  Setup Complete!"
echo "========================================"
echo ""
echo "Next steps:"
echo "  1. Start the Flask app:"
echo "     cd medsecure-platform && python src/app.py"
echo ""
echo "  2. Run the SecureLoop pipeline:"
echo "     cd secureloop && python run_full_pipeline.py --dry-run"
echo ""
echo "  3. Start the dashboard:"
echo "     cd secureloop/dashboard && npm install && npm start"
echo ""
echo "========================================"
