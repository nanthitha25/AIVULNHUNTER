# PostgreSQL Setup Guide for AivulnHunter

## Prerequisites

You need PostgreSQL installed on your system.

### macOS Installation

```bash
# Install PostgreSQL using Homebrew
brew install postgresql@15

# Start PostgreSQL service
brew services start postgresql@15

# Or start manually
pg_ctl -D /opt/homebrew/var/postgresql@15 start
```

## Database Setup

### 1. Create Database

```bash
# Connect to PostgreSQL
psql postgres

# Create database and user
CREATE DATABASE aivulnhunter;
CREATE USER aivuln_user WITH PASSWORD 'your_secure_password';
GRANT ALL PRIVILEGES ON DATABASE aivulnhunter TO aivuln_user;

# Exit psql
\q
```

### 2. Set Environment Variable

Add to your `.env` file or export in terminal:

```bash
export DATABASE_URL="postgresql://aivuln_user:your_secure_password@localhost:5432/aivulnhunter"
```

Or for default local setup:

```bash
export DATABASE_URL="postgresql://postgres:postgres@localhost:5432/aivulnhunter"
```

### 3. Install Python Dependencies

```bash
cd /Users/nanthithavenkatachapathy/Desktop/AivulnHunter
pip install -r requirements.txt
```

### 4. Run Database Migration

```bash
cd backend
python3 database/migrate.py
```

This will:
- Create all database tables
- Migrate rules from `rules/rules.json` to PostgreSQL
- Create default admin user (username: `admin`, password: `admin123`)

## Verification

### Check Database Connection

```python
from backend.database.connection import check_connection

if check_connection():
    print("✅ Database connected successfully!")
else:
    print("❌ Database connection failed")
```

### View Tables

```bash
psql -d aivulnhunter -c "\dt"
```

### Query Data

```bash
# View rules
psql -d aivulnhunter -c "SELECT id, name, owasp, severity FROM rules;"

# View users
psql -d aivulnhunter -c "SELECT username, email, role FROM users;"
```

## Using Docker (Alternative)

If you prefer Docker:

```bash
# Run PostgreSQL in Docker
docker run -d \
  --name aivulnhunter-postgres \
  -e POSTGRES_DB=aivulnhunter \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=postgres \
  -p 5432:5432 \
  postgres:15

# Set DATABASE_URL
export DATABASE_URL="postgresql://postgres:postgres@localhost:5432/aivulnhunter"

# Run migration
cd backend
python3 database/migrate.py
```

## Troubleshooting

### Connection Refused

```bash
# Check if PostgreSQL is running
brew services list | grep postgresql

# Or check process
ps aux | grep postgres
```

### Permission Denied

```bash
# Grant permissions
psql -d aivulnhunter -c "GRANT ALL ON SCHEMA public TO aivuln_user;"
```

### Reset Database

```bash
# Drop and recreate database
psql postgres -c "DROP DATABASE IF EXISTS aivulnhunter;"
psql postgres -c "CREATE DATABASE aivulnhunter;"

# Run migration again
python3 backend/database/migrate.py
```
