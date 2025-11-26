"""
Helper Functions Module
Utility helper functions for ThreatIntel Processor Pro
Developed & Designed by Dip Kar
"""

import socket
from datetime import datetime, timezone


def reverse_dns(ip):
    """
    Perform reverse DNS lookup for IP address
    
    Args:
        ip: IP address string
        
    Returns:
        Hostname string or None if lookup fails
        
    Example:
        >>> reverse_dns("8.8.8.8")
        'dns.google'
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        return None


def utcnow_iso():
    """
    Get current UTC time in ISO format
    
    Returns:
        String: ISO-formatted UTC timestamp
        
    Example:
        >>> utcnow_iso()
        '2025-01-15T10:30:45.123456+00:00'
    """
    return datetime.now(timezone.utc).isoformat()


def risk_label(score):
    """
    Calculate risk label and CSS class based on abuse confidence score
    
    Args:
        score: Abuse confidence score (0-100)
        
    Returns:
        Tuple of (label, css_class)
        
    Example:
        >>> risk_label(95)
        ('Critical', 'badge-red')
        >>> risk_label(50)
        ('Medium', 'badge-yellow')
        >>> risk_label(10)
        ('Low', 'badge-green')
    """
    try:
        s = int(score)
    except (ValueError, TypeError):
        return ("Unknown", "badge-yellow")
    
    if s >= 90:
        return ("Critical", "badge-red")
    if s >= 75:
        return ("High", "badge-red")
    if s >= 30:
        return ("Medium", "badge-yellow")
    if s >= 0:
        return ("Low", "badge-green")
    
    return ("Unknown", "badge-yellow")


def format_datetime(iso_string):
    """
    Format ISO datetime string to readable format
    
    Args:
        iso_string: ISO format datetime string
        
    Returns:
        Formatted datetime string (YYYY-MM-DD HH:MM:SS UTC)
        
    Example:
        >>> format_datetime('2025-01-15T10:30:45.123456+00:00')
        '2025-01-15 10:30:45 UTC'
    """
    if not iso_string:
        return ""
    
    try:
        # Handle both with and without timezone
        if 'Z' in iso_string:
            dt = datetime.fromisoformat(iso_string.replace('Z', '+00:00'))
        elif '+' in iso_string or iso_string.count('-') > 2:
            dt = datetime.fromisoformat(iso_string)
        else:
            dt = datetime.fromisoformat(iso_string)
        
        return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
    except (ValueError, AttributeError):
        return iso_string


def format_bytes(bytes_num):
    """
    Format bytes to human-readable string
    
    Args:
        bytes_num: Number of bytes
        
    Returns:
        Formatted string (e.g., '1.5 MB')
        
    Example:
        >>> format_bytes(1536)
        '1.5 KB'
        >>> format_bytes(1048576)
        '1.0 MB'
    """
    try:
        bytes_num = float(bytes_num)
    except (ValueError, TypeError):
        return "0 B"
    
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_num < 1024.0:
            return f"{bytes_num:.1f} {unit}"
        bytes_num /= 1024.0
    
    return f"{bytes_num:.1f} PB"


def truncate_string(text, max_length=50, suffix='...'):
    """
    Truncate string to maximum length
    
    Args:
        text: String to truncate
        max_length: Maximum length (default 50)
        suffix: Suffix to add if truncated (default '...')
        
    Returns:
        Truncated string
        
    Example:
        >>> truncate_string("This is a very long string", 10)
        'This is...'
    """
    if not text:
        return ""
    
    text = str(text)
    
    if len(text) <= max_length:
        return text
    
    return text[:max_length - len(suffix)] + suffix


def safe_int(value, default=0):
    """
    Safely convert value to integer
    
    Args:
        value: Value to convert
        default: Default value if conversion fails
        
    Returns:
        Integer value or default
    """
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def safe_float(value, default=0.0):
    """
    Safely convert value to float
    
    Args:
        value: Value to convert
        default: Default value if conversion fails
        
    Returns:
        Float value or default
    """
    try:
        return float(value)
    except (ValueError, TypeError):
        return default


def get_country_emoji(country_code):
    """
    Convert country code to flag emoji
    
    Args:
        country_code: Two-letter country code (ISO 3166-1 alpha-2)
        
    Returns:
        Flag emoji string or empty string if invalid
        
    Example:
        >>> get_country_emoji('US')
        '🇺🇸'
        >>> get_country_emoji('GB')
        '🇬🇧'
    """
    if not country_code or len(country_code) != 2:
        return ""
    
    country_code = country_code.upper()
    
    try:
        # Regional indicator symbols start at 0x1F1E6 (A)
        OFFSET = 0x1F1E6 - ord('A')
        code_points = [ord(char) + OFFSET for char in country_code]
        return ''.join(chr(cp) for cp in code_points)
    except (ValueError, OverflowError):
        return ""


def format_list(items, separator=', ', max_items=None):
    """
    Format list of items as string
    
    Args:
        items: List of items
        separator: Separator string (default ', ')
        max_items: Maximum items to show (optional)
        
    Returns:
        Formatted string
        
    Example:
        >>> format_list(['a', 'b', 'c'])
        'a, b, c'
        >>> format_list(['a', 'b', 'c'], max_items=2)
        'a, b and 1 more...'
    """
    if not items:
        return ""
    
    items = list(items)
    
    if max_items and len(items) > max_items:
        shown = items[:max_items]
        remaining = len(items) - max_items
        return f"{separator.join(str(i) for i in shown)} and {remaining} more..."
    
    return separator.join(str(i) for i in items)


def get_severity_color(score):
    """
    Get color code based on severity score
    
    Args:
        score: Severity score (0-100)
        
    Returns:
        Hex color code string
    """
    try:
        s = int(score)
    except (ValueError, TypeError):
        return "#6b7280"  # Gray for unknown
    
    if s >= 90:
        return "#dc2626"  # Red - Critical
    if s >= 75:
        return "#ea580c"  # Orange-red - High
    if s >= 50:
        return "#f59e0b"  # Orange - Medium-High
    if s >= 30:
        return "#eab308"  # Yellow - Medium
    if s >= 10:
        return "#84cc16"  # Light green - Low-Medium
    
    return "#22c55e"  # Green - Low