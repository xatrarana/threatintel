"""
AlienVault OTX API Service Module
Handles all interactions with OTX API
Developed & Designed by Dip Kar
"""

import requests
from config import Config
from models.database import db


class OTXService:
    """OTX API service handler"""
    
    def __init__(self, api_key=None):
        self.api_key = api_key or Config.get_api_keys()['otx_api_key']
        self.general_url = Config.OTX_IPV4_GENERAL
        self.reputation_url = Config.OTX_IPV4_REPUTATION
    
    def query_ip(self, ip):
        """
        Query IP information from OTX
        
        Args:
            ip: IP address to query
            
        Returns:
            Dictionary with OTX data
        """
        if not self.api_key:
            raise ValueError("OTX API key not configured")
        
        headers = {"X-OTX-API-KEY": self.api_key}
        
        # Try general endpoint first
        try:
            url = self.general_url.format(ip=ip)
            response = requests.get(url, headers=headers, timeout=12)
            
            if response.status_code == 200:
                data = response.json()
                country = (
                    data.get("country_name") or 
                    data.get("geolocation", {}).get("country_name") or 
                    ""
                )
                
                # Store in checks history
                db.insert_check(ip, None, country, "OTX-general")
                
                otx_summary = {
                    "indicator": data.get("indicator") or ip,
                    "reputation": data.get("reputation", 0),
                    "whois": data.get("whois"),
                    "country_name": country,
                    "pulse_count": data.get("pulse_info", {}).get("count", 0),
                    "passive_dns": data.get("passive_dns", []),
                    "sections": data.get("sections", []),
                    "raw": data,
                }
                
                return {
                    "source": "OTX-general",
                    "data": otx_summary
                }
        except Exception as e:
            pass  # Try reputation endpoint
        
        # Try reputation endpoint
        try:
            url = self.reputation_url.format(ip=ip)
            response = requests.get(url, headers=headers, timeout=12)
            
            if response.status_code == 200:
                data = response.json()
                country = data.get("country_name", "")
                
                # Store in checks history
                db.insert_check(ip, None, country, "OTX-reputation")
                
                otx_summary = {
                    "indicator": data.get("indicator") or ip,
                    "reputation": data.get("reputation", 0),
                    "country_name": country,
                    "raw": data,
                }
                
                return {
                    "source": "OTX-reputation",
                    "data": otx_summary
                }
            else:
                return {
                    "source": "OTX",
                    "status_code": response.status_code,
                    "text": response.text
                }
        except Exception as e:
            return {"error": str(e)}