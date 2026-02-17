#!/bin/bash

# AivulnHunter PostgreSQL Setup Script
# This script automates the PostgreSQL setup process

set -e  # Exit on error

echo "🚀 AivulnHunter PostgreSQL Setup"
echo "=================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if PostgreSQL is installed
echo -e "\n${YELLOW}1️⃣ Checking PostgreSQL installation...${NC}"
if command -v psql &> /dev/null; then
    echo -e "${GREEN}✅ PostgreSQL is installed${NC}"
    psql --version
else
    echo -e "${RED}❌ PostgreSQL is not installed${NC}"
    echo ""
    echo "Please install PostgreSQL:"
    echo "  macOS:   brew install postgresql@15"
    echo "  Ubuntu:  sudo apt-get install postgresql postgresql-contrib"
    echo "  Windows: Download from https://www.postgresql.org/download/"
    exit 1
fi

# Check if PostgreSQL is running
echo -e "\n${YELLOW}2️⃣ Checking if PostgreSQL is running...${NC}"
if pg_isready &> /dev/null; then
    echo -e "${GREEN}✅ PostgreSQL is running${NC}"
else
    echo -e "${YELLOW}⚠️  PostgreSQL is not running. Attempting to start...${NC}"
    
    # Try to start PostgreSQL (macOS with Homebrew)
    if command -v brew &> /dev/null; then
        brew services start postgresql@15 || brew services start postgresql
        sleep 2
        if pg_isready &> /dev/null; then
            echo -e "${GREEN}✅ PostgreSQL started successfully${NC}"
        else
            echo -e "${RED}❌ Failed to start PostgreSQL${NC}"
            echo "Please start PostgreSQL manually"
            exit 1
        fi
    else
        echo -e "${RED}❌ Please start PostgreSQL manually${NC}"
        exit 1
    fi
fi

# Create database
echo -e "\n${YELLOW}3️⃣ Creating database...${NC}"
DB_NAME="aivulnhunter"

# Check if database exists
if psql -lqt | cut -d \| -f 1 | grep -qw $DB_NAME; then
    echo -e "${YELLOW}⚠️  Database '$DB_NAME' already exists${NC}"
    read -p "Do you want to drop and recreate it? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        dropdb $DB_NAME 2>/dev/null || true
        createdb $DB_NAME
        echo -e "${GREEN}✅ Database recreated${NC}"
    else
        echo -e "${YELLOW}Using existing database${NC}"
    fi
else
    createdb $DB_NAME
    echo -e "${GREEN}✅ Database '$DB_NAME' created${NC}"
fi

# Set environment variable
echo -e "\n${YELLOW}4️⃣ Setting environment variable...${NC}"
export DATABASE_URL="postgresql://postgres:postgres@localhost:5432/$DB_NAME"
echo -e "${GREEN}✅ DATABASE_URL set${NC}"
echo "   $DATABASE_URL"

# Install Python dependencies
echo -e "\n${YELLOW}5️⃣ Installing Python dependencies...${NC}"
cd "$(dirname "$0")/.."
pip3 install -q sqlalchemy psycopg2-binary alembic
echo -e "${GREEN}✅ Dependencies installed${NC}"

# Run migration
echo -e "\n${YELLOW}6️⃣ Running database migration...${NC}"
cd backend
python3 database/migrate.py

# Verify setup
echo -e "\n${YELLOW}7️⃣ Verifying setup...${NC}"
RULE_COUNT=$(psql -d $DB_NAME -t -c "SELECT COUNT(*) FROM rules;" 2>/dev/null | tr -d ' ')
USER_COUNT=$(psql -d $DB_NAME -t -c "SELECT COUNT(*) FROM users;" 2>/dev/null | tr -d ' ')

if [ ! -z "$RULE_COUNT" ] && [ "$RULE_COUNT" -gt 0 ]; then
    echo -e "${GREEN}✅ Database setup verified${NC}"
    echo "   Rules: $RULE_COUNT"
    echo "   Users: $USER_COUNT"
else
    echo -e "${RED}❌ Database verification failed${NC}"
    exit 1
fi

# Success message
echo -e "\n${GREEN}=================================="
echo "🎉 PostgreSQL setup complete!"
echo "==================================${NC}"
echo ""
echo "Next steps:"
echo "  1. Export DATABASE_URL in your shell:"
echo "     export DATABASE_URL=\"$DATABASE_URL\""
echo ""
echo "  2. Test the database-backed scan:"
echo "     cd backend"
echo "     python3 example_db_scan.py"
echo ""
echo "Default admin credentials:"
echo "  Username: admin"
echo "  Password: admin123"
echo "  ${RED}⚠️  Change this password in production!${NC}"
