"""
Configuration Management Module
Handles loading environment variables and storing API keys
Developed & Designed by Dip Kar
"""

import os
import json
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

class Config:
    """Application configuration class"""
    
    # Flask Configuration
    SECRET_KEY = os.getenv('FLASK_SECRET_KEY', 'change_this_secret_for_prod')
    ENV = os.getenv('FLASK_ENV', 'production')
    DEBUG = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    
    # Admin Credentials
    ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'admin')
    ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'admin123')
    
    # Database Configuration
    DATABASE_PATH = os.getenv('DATABASE_PATH', 'threat_intel.db')
    
    # Server Configuration
    HOST = os.getenv('FLASK_HOST', '0.0.0.0')
    PORT = int(os.getenv('FLASK_PORT', 5000))
    
    # API Keys Configuration File
    CONFIG_FILE = 'api_keys.json'
    
    @staticmethod
    def get_api_keys():
        """
        Get API keys from config file or environment variables
        Priority: config file > environment variables
        """
        keys = {
            'otx_api_key': os.getenv('OTX_API_KEY', ''),
            'abuseipdb_api_key': os.getenv('ABUSEIPDB_API_KEY', '')
        }
        
        if Path(Config.CONFIG_FILE).exists():
            try:
                with open(Config.CONFIG_FILE, 'r') as f:
                    stored_keys = json.load(f)
                    keys.update(stored_keys)
            except Exception as e:
                print(f"Error loading API keys from file: {e}")
        
        return keys
    
    @staticmethod
    def save_api_keys(otx_key, abuseipdb_key):
        """Save API keys to configuration file"""
        keys = {
            'otx_api_key': otx_key,
            'abuseipdb_api_key': abuseipdb_key
        }
        
        try:
            with open(Config.CONFIG_FILE, 'w') as f:
                json.dump(keys, f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving API keys: {e}")
            return False
    
    @staticmethod
    def are_api_keys_configured():
        """Check if API keys are configured"""
        keys = Config.get_api_keys()
        return bool(keys['otx_api_key'] and keys['abuseipdb_api_key'])
    
    # API Endpoints
    ABUSE_BLACKLIST_URL = "https://api.abuseipdb.com/api/v2/blacklist"
    ABUSE_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
    OTX_IPV4_GENERAL = "https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    OTX_IPV4_REPUTATION = "https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/reputation"
    IP_GEO_API = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,lat,lon,isp,org,as,query"