# ThreatIntel Processor Pro 🛡️

A modular, professional threat intelligence platform for IP reputation analysis, IOC management, and SIEM integration.

---

## ✨ Features

- 🔍 **IP Reputation Lookup** - AbuseIPDB & OTX integration
- 📊 **Interactive Dashboard** - Real-time threat visualization
- 🗺️ **GeoMapping** - Visual threat geography with Leaflet
- 📈 **Threat Analytics** - Risk scoring and classification
- 💾 **IOC Database** - Persistent threat intelligence storage
- 📤 **SIEM Exports** - CSV, JSON, and STIX 2.1 formats
- 🔐 **Secure Authentication** - Login-protected access
- ⚙️ **Easy API Setup** - Web-based configuration interface

---

## 🏗️ Project Structure

```
threat_intel_app/
├── .env                      # Environment variables (create from .env.example)
├── .env.example              # Example environment file
├── requirements.txt          # Python dependencies
├── config.py                 # Configuration management
├── app.py                    # Main Flask application
├── models/
│   ├── __init__.py
│   └── database.py          # Database operations
├── services/
│   ├── __init__.py
│   ├── abuseipdb.py        # AbuseIPDB API service
│   ├── otx.py               # OTX API service
│   └── geo.py               # Geolocation service
├── routes/
│   ├── __init__.py
│   ├── auth.py              # Authentication routes
│   ├── dashboard.py         # Dashboard routes
│   └── api.py               # API endpoints
├── utils/
│   ├── __init__.py
│   ├── validators.py        # Input validation
│   └── helpers.py           # Helper functions
└── templates/
    ├── login.html           # Login page
    ├── setup.html           # API key setup
    └── dashboard.html       # Main dashboard
```

---

## 🚀 Quick Start

### 1. Clone or Download

```bash
git clone <repository-url>
cd threat_intel_app
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure Environment

Create `.env` file from example:

```bash
cp .env.example .env
```

Edit `.env` and update credentials:

```env
# Flask Configuration
FLASK_SECRET_KEY=your-random-secret-key-here
FLASK_ENV=development
FLASK_DEBUG=True

# Admin Credentials (change these!)
ADMIN_USERNAME=admin
ADMIN_PASSWORD=your-secure-password

# API Keys (optional - can configure via UI)
OTX_API_KEY=
ABUSEIPDB_API_KEY=

# Database
DATABASE_PATH=threat_intel.db

# Server
FLASK_HOST=0.0.0.0
FLASK_PORT=5000
```

### 4. Run Application

```bash
python app.py
```

The application will start at `http://localhost:5000`

---

## 🔑 First-Time Setup

### Step 1: Login
- Navigate to `http://localhost:5000`
- Use credentials from `.env`:
  - **Username:** `admin` (or your configured username)
  - **Password:** `admin123` (or your configured password)

### Step 2: Configure API Keys
After login, you'll be redirected to the API setup page:

1. **Get OTX API Key:**
   - Visit [AlienVault OTX](https://otx.alienvault.com/)
   - Create free account
   - Navigate to Settings → API Integration
   - Copy your API key

2. **Get AbuseIPDB API Key:**
   - Visit [AbuseIPDB](https://www.abuseipdb.com/api)
   - Create free account
   - Go to Account → API
   - Copy your API key

3. **Save Configuration:**
   - Paste both keys into the setup form
   - Click "Save & Continue"

### Step 3: Start Using
You'll be redirected to the dashboard. You can now:
- Check IP reputations
- Fetch blacklists
- View threat analytics
- Export IOC data

---

## 📋 Features Guide

### IP Lookup
1. Enter an IP address in the lookup field
2. Click "Check"
3. View comprehensive results:
   - Abuse confidence score
   - Risk classification
   - Geographic location
   - ISP information
   - WHOIS data
   - Passive DNS records

### Fetch Blacklist
- Click "Fetch Blacklist" to retrieve latest malicious IPs from AbuseIPDB
- Updates are stored in local database
- Automatically refreshes dashboard charts

### Dashboard Analytics
- **Threat Chart**: Visual breakdown of threats (Clean/Suspicious/Malicious)
- **Top Malicious IPs**: Table of highest-risk IPs
- **GeoMap**: Geographic distribution of threats
- **Database Stats**: Total records and last update time

### SIEM Exports
Export threat intelligence in multiple formats:
- **CSV**: Spreadsheet-compatible format
- **JSON**: Structured data with metadata
- **STIX 2.1**: Standard threat intelligence format

Click "Export (SIEM)" dropdown to download.

---

## 🧪 Testing Configuration

For testing, you can add API keys directly to `.env`:

```env
# Test API Keys
OTX_API_KEY=your_test_otx_key_here
ABUSEIPDB_API_KEY=your_test_abuseipdb_key_here
```

⚠️ **Security Note:** Never commit `.env` file to version control!

---

## 🔒 Security Best Practices

1. **Change Default Credentials:**
   ```env
   ADMIN_USERNAME=your_username
   ADMIN_PASSWORD=strong_password_here
   ```

2. **Generate Secure Secret Key:**
   ```python
   import secrets
   print(secrets.token_hex(32))
   ```
   Use output for `FLASK_SECRET_KEY`

3. **Production Deployment:**
   ```env
   FLASK_ENV=production
   FLASK_DEBUG=False
   ```

4. **API Key Storage:**
   - Keys are stored in `api_keys.json` (auto-created)
   - Add to `.gitignore`
   - Use environment variables in production

---

## 🐛 Troubleshooting

### API Keys Not Working
- Verify keys are valid and active
- Check API rate limits
- Review service status pages

### Database Errors
- Ensure write permissions in app directory
- Delete `threat_intel.db` to reset database

### Port Already in Use
Change port in `.env`:
```env
FLASK_PORT=8000
```

### Import Errors
Reinstall dependencies:
```bash
pip install --upgrade -r requirements.txt
```

---

## 📦 Dependencies

- **Flask 3.0.0** - Web framework
- **requests 2.31.0** - HTTP library
- **python-dotenv 1.0.0** - Environment management
- **sqlite3** - Built-in database (Python standard library)

---

## 🔄 Updating API Keys

To update API keys after initial setup:
1. Navigate to `/setup` route
2. Enter new keys
3. Save configuration

Or edit `api_keys.json` directly:
```json
{
  "otx_api_key": "new_key_here",
  "abuseipdb_api_key": "new_key_here"
}
```

---

## 📊 API Endpoints

### Authentication
- `GET/POST /login` - User login
- `GET /logout` - User logout
- `GET/POST /setup` - API key configuration

### Dashboard
- `GET /dashboard` - Main dashboard

### API Routes
- `POST /api/check_ip` - Check IP reputation
- `POST /api/fetch_blacklist` - Fetch AbuseIPDB blacklist
- `GET /api/top_malicious` - Get top malicious IPs
- `GET /api/totals` - Get database statistics
- `GET /api/geo?ip=x.x.x.x` - Get IP geolocation
- `GET /api/export/csv` - Export as CSV
- `GET /api/export/json` - Export as JSON
- `GET /api/export/stix` - Export as STIX 2.1

---

## 📝 License

This project is developed and designed by **Dip Kar**.

---

## 🤝 Support

For issues or questions:
1. Check troubleshooting section
2. Review API provider documentation
3. Verify environment configuration

---

## 🎯 Roadmap

- [ ] Multi-user support
- [ ] Advanced threat hunting
- [ ] Custom rule engine
- [ ] Email notifications
- [ ] Integration with more threat feeds
- [ ] Machine learning threat detection

---

Version 2.0 - Modular Architecture Release