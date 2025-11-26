"""
Validation Utilities Module
Input validation functions for ThreatIntel Processor Pro
Developed & Designed by Dip Kar
"""

import ipaddress
import re


def is_valid_ip(address):
    """
    Validate if string is a valid IP address (IPv4 or IPv6)
    
    Args:
        address: String to validate
        
    Returns:
        Boolean indicating if valid IP address
        
    Example:
        >>> is_valid_ip("8.8.8.8")
        True
        >>> is_valid_ip("256.1.1.1")
        False
        >>> is_valid_ip("2001:4860:4860::8888")
        True
    """
    try:
        ipaddress.ip_address(address)
        return True
    except (ValueError, TypeError):
        return False


def is_valid_ipv4(address):
    """
    Validate if string is a valid IPv4 address
    
    Args:
        address: String to validate
        
    Returns:
        Boolean indicating if valid IPv4 address
    """
    try:
        ip = ipaddress.ip_address(address)
        return isinstance(ip, ipaddress.IPv4Address)
    except (ValueError, TypeError):
        return False


def is_valid_ipv6(address):
    """
    Validate if string is a valid IPv6 address
    
    Args:
        address: String to validate
        
    Returns:
        Boolean indicating if valid IPv6 address
    """
    try:
        ip = ipaddress.ip_address(address)
        return isinstance(ip, ipaddress.IPv6Address)
    except (ValueError, TypeError):
        return False


def is_private_ip(address):
    """
    Check if IP address is in private range
    
    Args:
        address: IP address string
        
    Returns:
        Boolean indicating if IP is private
    """
    try:
        ip = ipaddress.ip_address(address)
        return ip.is_private
    except (ValueError, TypeError):
        return False


def is_valid_email(email):
    """
    Validate email address format
    
    Args:
        email: Email address string
        
    Returns:
        Boolean indicating if valid email format
    """
    if not email or not isinstance(email, str):
        return False
    
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def is_valid_domain(domain):
    """
    Validate domain name format
    
    Args:
        domain: Domain name string
        
    Returns:
        Boolean indicating if valid domain format
    """
    if not domain or not isinstance(domain, str):
        return False
    
    # Basic domain validation
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))


def sanitize_ip(ip_string):
    """
    Sanitize and normalize IP address string
    
    Args:
        ip_string: IP address string (potentially with whitespace)
        
    Returns:
        Sanitized IP string or None if invalid
    """
    if not ip_string:
        return None
    
    # Remove whitespace
    cleaned = ip_string.strip()
    
    # Validate
    if is_valid_ip(cleaned):
        return cleaned
    
    return None


def validate_api_key(api_key, min_length=20):
    """
    Basic API key validation
    
    Args:
        api_key: API key string
        min_length: Minimum required length (default 20)
        
    Returns:
        Boolean indicating if key meets basic requirements
    """
    if not api_key or not isinstance(api_key, str):
        return False
    
    # Check length
    if len(api_key.strip()) < min_length:
        return False
    
    # Check for suspicious patterns (optional)
    # Could add more sophisticated checks here
    
    return True


def validate_score_range(score, min_val=0, max_val=100):
    """
    Validate if score is within valid range
    
    Args:
        score: Score value to validate
        min_val: Minimum valid value (default 0)
        max_val: Maximum valid value (default 100)
        
    Returns:
        Boolean indicating if score is in valid range
    """
    try:
        score_num = float(score)
        return min_val <= score_num <= max_val
    except (ValueError, TypeError):
        return False