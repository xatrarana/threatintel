# 🚀 ThreatIntel Processor Pro - Complete Deployment Guide


---

## 📋 Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [First Run](#first-run)
5. [Testing](#testing)
6. [Production Deployment](#production-deployment)
7. [Troubleshooting](#troubleshooting)

---

## ✅ Prerequisites

- **Python 3.8+** installed
- **pip** package manager
- **Internet connection** (for API calls)
- **Web browser** (Chrome, Firefox, Safari, Edge)

---

## 📦 Installation

### Step 1: Create Project Directory

```bash
# Create main directory
mkdir threat_intel_app
cd threat_intel_app

# Create subdirectories
mkdir models services routes utils templates
```

### Step 2: Create Package Init Files

```bash
# Create __init__.py for each package
touch models/__init__.py
touch services/__init__.py
touch routes/__init__.py
touch utils/__init__.py
```

### Step 3: Create All Python Files

Copy the following files from the artifacts:

**Core Files:**
- `config.py` - Configuration management
- `app.py` - Main application

**Models:**
- `models/__init__.py` - Package init
- `models/database.py` - Database operations

**Services:**
- `services/__init__.py` - Package init
- `services/abuseipdb.py` - AbuseIPDB integration
- `services/otx.py` - OTX integration
- `services/geo.py` - Geolocation service

**Routes:**
- `routes/__init__.py` - Package init
- `routes/auth.py` - Authentication
- `routes/dashboard.py` - Dashboard
- `routes/api.py` - API endpoints

**Utils:**
- `utils/__init__.py` - Package init
- `utils/validators.py` - Validation functions
- `utils/helpers.py` - Helper functions

**Templates:**
- `templates/login.html` - Login page
- `templates/setup.html` - API setup page
- `templates/dashboard.html` - Dashboard (use your original)

### Step 4: Create Configuration Files

**requirements.txt:**
```txt
Flask==3.0.0
requests==2.31.0
python-dotenv==1.0.0
```

**.env.example:**
```env
FLASK_SECRET_KEY=your-secret-key-here
FLASK_ENV=development
FLASK_DEBUG=True

ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin123

OTX_API_KEY=
ABUSEIPDB_API_KEY=

DATABASE_PATH=threat_intel.db

FLASK_HOST=0.0.0.0
FLASK_PORT=5000
```

**.gitignore:**
```
__pycache__/
*.py[cod]
.env
.venv
venv/
*.db
*.sqlite
api_keys.json
.DS_Store
*.log
```

### Step 5: Install Dependencies

```bash
pip install -r requirements.txt
```

---

## ⚙️ Configuration

### 1. Create Environment File

```bash
cp .env.example .env
```

### 2. Edit Configuration

Open `.env` and update:

```env
# Generate secure secret key:
# python -c "import secrets; print(secrets.token_hex(32))"
FLASK_SECRET_KEY=your-generated-secret-key-here

# Change default admin credentials
ADMIN_USERNAME=your_username
ADMIN_PASSWORD=your_secure_password

# For testing, add API keys here (optional)
OTX_API_KEY=your_otx_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_key_here
```

---

## 🎯 First Run

### 1. Start the Application

```bash
python app.py
```

You should see:
```
╔═══════════════════════════════════════════════════════════════╗
║          ThreatIntel Processor Pro - Starting...             ║
║                                                               ║
║  Developed & Designed by: Dip Kar                            ║
║  Server: http://0.0.0.0:5000                                 ║
║  Environment: development                                     ║
╚═══════════════════════════════════════════════════════════════╝

⚠️  WARNING: API keys not configured!
   Please configure your API keys after logging in.

 * Running on http://0.0.0.0:5000
```

### 2. Access the Application

Open browser and navigate to: `http://localhost:5000`

### 3. Login

Use credentials from `.env`:
- **Username:** `admin` (or your configured username)
- **Password:** `admin123` (or your configured password)

### 4. Configure API Keys

You'll be redirected to API setup page:

**Get OTX API Key:**
1. Visit https://otx.alienvault.com/
2. Sign up for free account
3. Go to Settings → API Integration
4. Copy API key

**Get AbuseIPDB API Key:**
1. Visit https://www.abuseipdb.com/api
2. Sign up for free account
3. Go to Account → API
4. Copy API key

**Save Keys:**
1. Paste both keys in setup form
2. Click "Save & Continue"

### 5. Start Using

You're now on the dashboard! Try:
- Enter an IP address (e.g., `8.8.8.8`) and click "Check"
- Click "Fetch Blacklist" to populate database
- View threat analytics and charts
- Export data in various formats

---

## 🧪 Testing

### Quick Test Checklist

```bash
# 1. Test login
curl -X POST http://localhost:5000/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=admin123"

# 2. Test health endpoint (no auth required)
curl http://localhost:5000/api/health

# 3. Test IP check (requires login)
# First login via browser, then:
curl -X POST http://localhost:5000/api/check_ip \
  -H "Content-Type: application/json" \
  -d '{"ip":"8.8.8.8"}' \
  --cookie "session=YOUR_SESSION_COOKIE"
```

### Test IPs

Use these for testing:
- **Clean IP:** `8.8.8.8` (Google DNS)
- **Suspicious IP:** Check AbuseIPDB for examples
- **Private IP:** `192.168.1.1` (should show as private)

---

## 🏭 Production Deployment

### 1. Update Environment

```env
FLASK_ENV=production
FLASK_DEBUG=False
FLASK_SECRET_KEY=very-strong-secret-key-here
```

### 2. Use Production Server

Install Gunicorn:
```bash
pip install gunicorn
```

Run with Gunicorn:
```bash
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

### 3. Use Nginx Reverse Proxy (Recommended)

**Nginx Configuration:**
```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

### 4. Setup SSL (Let's Encrypt)

```bash
sudo apt-get install certbot python3-certbot-nginx
sudo certbot --nginx -d your-domain.com
```

### 5. Run as Systemd Service

Create `/etc/systemd/system/threatintel.service`:
```ini
[Unit]
Description=ThreatIntel Processor Pro
After=network.target

[Service]
User=www-data
WorkingDirectory=/path/to/threat_intel_app
Environment="PATH=/path/to/venv/bin"
ExecStart=/path/to/venv/bin/gunicorn -w 4 -b 127.0.0.1:5000 app:app

[Install]
WantedBy=multi-user.target
```

Start service:
```bash
sudo systemctl start threatintel
sudo systemctl enable threatintel
```

---

## 🐛 Troubleshooting

### Issue: "Module not found" errors

**Solution:**
```bash
# Ensure all __init__.py files exist
ls models/__init__.py services/__init__.py routes/__init__.py utils/__init__.py

# If missing, create them:
touch models/__init__.py services/__init__.py routes/__init__.py utils/__init__.py
```

### Issue: "API key not configured" error

**Solution:**
1. Check `.env` file has keys OR
2. Navigate to `/setup` route and enter keys via UI
3. Verify `api_keys.json` file was created

### Issue: Database errors

**Solution:**
```bash
# Delete and recreate database
rm threat_intel.db

# Restart application - DB will auto-initialize
python app.py
```

### Issue: Port already in use

**Solution:**
```bash
# Find process using port 5000
lsof -i :5000

# Kill process or change port in .env
FLASK_PORT=8000
```

### Issue: Template not found

**Solution:**
```bash
# Ensure templates directory exists
mkdir -p templates

# Verify all template files are present
ls templates/login.html templates/setup.html templates/dashboard.html
```

### Issue: API rate limits

**Solution:**
- AbuseIPDB free tier: 1000 requests/day
- OTX: No rate limit on free tier
- Wait 24 hours or upgrade to paid plan

---

## 📊 Monitoring

### View Logs

```bash
# Development
python app.py  # Logs printed to console

# Production (systemd)
sudo journalctl -u threatintel -f

# Production (Gunicorn)
tail -f /var/log/gunicorn/threatintel.log
```

### Database Monitoring

```bash
# Check database size
du -h threat_intel.db

# View record count
sqlite3 threat_intel.db "SELECT COUNT(*) FROM iocs;"

# View recent checks
sqlite3 threat_intel.db "SELECT * FROM checks ORDER BY checked_at DESC LIMIT 10;"
```

---

## 🔐 Security Checklist

- [ ] Change default admin credentials
- [ ] Use strong `FLASK_SECRET_KEY`
- [ ] Set `FLASK_DEBUG=False` in production
- [ ] Use HTTPS (SSL/TLS)
- [ ] Keep API keys secure (never commit `.env`)
- [ ] Regular security updates (`pip install --upgrade -r requirements.txt`)
- [ ] Firewall configuration (only expose necessary ports)
- [ ] Regular database backups

---

## 📈 Performance Tips

1. **Database Optimization:**
   ```bash
   # Vacuum database periodically
   sqlite3 threat_intel.db "VACUUM;"
   ```

2. **Caching:**
   - Geo lookups are cached automatically
   - Consider Redis for session storage in production

3. **Rate Limiting:**
   - Implement rate limiting for API endpoints
   - Use Flask-Limiter extension

---

## 🆘 Support Resources

- **Documentation:** README.md
- **API Keys:** 
  - OTX: https://otx.alienvault.com/
  - AbuseIPDB: https://www.abuseipdb.com/api
- **Flask Docs:** https://flask.palletsprojects.com/
- **SQLite Docs:** https://www.sqlite.org/docs.html

---

## ✅ Post-Deployment Checklist

- [ ] Application starts without errors
- [ ] Can login successfully
- [ ] API keys configured and working
- [ ] IP lookup returns results
- [ ] Blacklist fetch works
- [ ] Charts display correctly
- [ ] Exports (CSV/JSON/STIX) download properly
- [ ] Database persists data
- [ ] Logs are accessible
- [ ] Backups configured

---

**Congratulations! Your ThreatIntel Processor Pro is now deployed! 🎉**
