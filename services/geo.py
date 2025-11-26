"""
Geolocation Service Module
Handles IP geolocation lookups with caching
Developed & Designed by Dip Kar
"""

import requests
from config import Config
from models.database import db


class GeoService:
    """Geolocation service handler"""
    
    def __init__(self):
        self.api_url = Config.IP_GEO_API
    
    def lookup(self, ip):
        """
        Lookup geolocation information for IP address
        Uses cache to reduce API calls
        
        Args:
            ip: IP address to lookup
            
        Returns:
            Dictionary with geo information
        """
        # Check cache first
        cached = db.get_geo_cache(ip)
        if cached:
            return cached
        
        # Fetch from API
        url = self.api_url.format(ip=ip)
        response = requests.get(url, timeout=8)
        data = response.json()
        
        if data.get("status") != "success":
            return {"ip": ip}
        
        # Store in cache
        db.insert_geo_cache(
            ip=ip,
            country=data.get("country"),
            country_code=data.get("countryCode"),
            region=data.get("regionName"),
            city=data.get("city"),
            lat=data.get("lat"),
            lon=data.get("lon"),
            isp=data.get("isp"),
            org=data.get("org"),
            asn=data.get("as")
        )
        
        # Return formatted data
        data["ip"] = ip
        data["country_code"] = data.get("countryCode")
        return data