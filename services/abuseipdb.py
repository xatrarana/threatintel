"""
AbuseIPDB API Service Module
Handles all interactions with AbuseIPDB API
Developed & Designed by Dip Kar
"""

import requests
from config import Config
from models.database import db
from utils.helpers import reverse_dns, risk_label


class AbuseIPDBService:
    """AbuseIPDB API service handler"""
    
    def __init__(self, api_key=None):
        self.api_key = api_key or Config.get_api_keys()['abuseipdb_api_key']
        self.blacklist_url = Config.ABUSE_BLACKLIST_URL
        self.check_url = Config.ABUSE_CHECK_URL
    
    def fetch_blacklist(self, limit=50):
        """
        Fetch blacklist from AbuseIPDB and store in database.
        """

        # Stop if key is missing or blank
        if not self.api_key or not self.api_key.strip():
            return {
                "error": "AbuseIPDB API key not configured"
            }

        headers = {
            "Accept": "application/json",
            "Key": self.api_key
        }
        params = {"limit": limit}

        try:
            response = requests.get(
                self.blacklist_url,
                headers=headers,
                params=params,
                timeout=20
            )
        except Exception as e:
            return {
                "error": f"Request failed: {str(e)}"
            }

        # Check for invalid/unauthorized key BEFORE raising
        if response.status_code == 401:
            return {
                "error": "AbuseIPDB API key unauthorized or invalid"
            }

        try:
            response.raise_for_status()
        except Exception as e:
            return {
                "error": f"HTTP error: {str(e)}"
            }

        # Extract data safely
        data = response.json().get("data", [])
        added = 0

        print(f"{str(data)}")

        for record in data:
            ip = record.get("ipAddress") or record.get("ip")
            score = record.get("abuseConfidenceScore", 0)
            country = record.get("countryCode") or record.get("country") or ""

            if not ip:
                continue

            db.insert_ioc(ip, score, country)
            added += 1

        return {"added": added}

    
    def check_ip(self, ip):
        """
        Check IP address using AbuseIPDB.
        Stops execution immediately if API key is missing or invalid.
        """

        # HARD STOP: no request should be made if the key is missing or blank
        if not self.api_key or not self.api_key.strip():
            return {
                "error": "AbuseIPDB API key not configured",
                "ip": ip,
                "score": None,
                "country": None,
                "details": {}
            }

        headers = {
            "Accept": "application/json",
            "Key": self.api_key
        }

        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90
        }

        try:
            response = requests.get(
                self.check_url,
                headers=headers,
                params=params,
                timeout=12
            )

            # Catch invalid key BEFORE raising
            if response.status_code == 401:
                return {
                    "error": "AbuseIPDB API key unauthorized or invalid",
                    "ip": ip,
                    "score": None,
                    "country": None,
                    "details": {}
                }

            response.raise_for_status()

        except Exception as e:
            return {
                "error": f"Request failed: {str(e)}",
                "ip": ip,
                "score": None,
                "country": None,
                "details": {}
            }

        # Normal processing continues only if everything succeeded
        json_data = response.json()
        data = json_data.get("data", {}) if isinstance(json_data, dict) else {}

        score = data.get("abuseConfidenceScore", 0)
        country = data.get("countryCode") or "-"

        db.insert_check(ip, score, country, "AbuseIPDB")
        db.insert_ioc(ip, score, country)

        domain = data.get("domain") or reverse_dns(ip) or "-"
        rlabel, _ = risk_label(score)

        details = {
            "ipAddress": data.get("ipAddress") or ip,
            "isPublic": data.get("isPublic"),
            "ipVersion": data.get("ipVersion"),
            "isWhitelisted": data.get("isWhitelisted"),
            "abuseConfidenceScore": score,
            "riskLabel": rlabel,
            "countryCode": country,
            "usageType": data.get("usageType") or "-",
            "isp": data.get("isp") or "-",
            "domain": domain,
            "hostnames": data.get("hostnames") or [],
            "totalReports": data.get("totalReports", 0),
            "numDistinctUsers": data.get("numDistinctUsers", 0),
            "lastReportedAt": data.get("lastReportedAt"),
            "raw": data,
        }

        return {
            "ip": ip,
            "score": score,
            "country": country,
            "details": details
        }
