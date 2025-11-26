
import sqlite3
from datetime import datetime, timezone
from config import Config


class Database:
    """Database operations handler"""
    
    def __init__(self, db_path=None):
        """
        Initialize database handler
        
        Args:
            db_path: Path to SQLite database file (optional)
        """
        self.db_path = db_path or Config.DATABASE_PATH
    
    def get_connection(self):
        """
        Get database connection with row factory
        
        Returns:
            sqlite3.Connection: Database connection object
        """
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn
    
    def init_db(self):
        """
        Initialize database tables
        Creates all required tables if they don't exist
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # IOCs (Indicators of Compromise) table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS iocs (
                ip_address TEXT PRIMARY KEY,
                abuse_confidence INTEGER,
                country_code TEXT,
                last_seen TEXT
            )
        """)
        
        # Checks history table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS checks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                score INTEGER,
                country TEXT,
                checked_at TEXT,
                source TEXT
            )
        """)
        
        # Geo cache table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS geocache (
                ip TEXT PRIMARY KEY,
                country TEXT,
                country_code TEXT,
                region TEXT,
                city TEXT,
                lat REAL,
                lon REAL,
                isp TEXT,
                org TEXT,
                asn TEXT,
                updated_at TEXT
            )
        """)
        
        conn.commit()
        conn.close()
    
    # ========================================================================
    # IOC Operations
    # ========================================================================
    
    def insert_ioc(self, ip_address, abuse_confidence, country_code, last_seen=None):
        """
        Insert or replace IOC record
        
        Args:
            ip_address: IP address
            abuse_confidence: Abuse confidence score (0-100)
            country_code: Two-letter country code
            last_seen: ISO timestamp (optional, defaults to now)
        """
        if last_seen is None:
            last_seen = self._utcnow_iso()
        
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO iocs (ip_address, abuse_confidence, country_code, last_seen) VALUES (?,?,?,?)",
            (ip_address, abuse_confidence, country_code, last_seen)
        )
        conn.commit()
        conn.close()
    
    def get_all_iocs(self, limit=None):
        """
        Get all IOCs ordered by abuse confidence
        
        Args:
            limit: Maximum number of records to return (optional)
            
        Returns:
            List of dictionaries containing IOC data
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        
        query = "SELECT ip_address, abuse_confidence, country_code, last_seen FROM iocs ORDER BY abuse_confidence DESC"
        if limit:
            query += f" LIMIT {limit}"
        
        cursor.execute(query)
        rows = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return rows
    
    def get_ioc_by_ip(self, ip_address):
        """
        Get IOC record by IP address
        
        Args:
            ip_address: IP address to lookup
            
        Returns:
            Dictionary with IOC data or None if not found
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT ip_address, abuse_confidence, country_code, last_seen FROM iocs WHERE ip_address=?",
            (ip_address,)
        )
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None
    
    def get_ioc_count(self):
        """
        Get total count of IOCs
        
        Returns:
            Integer: Total number of IOC records
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as total FROM iocs")
        count = cursor.fetchone()["total"]
        conn.close()
        return count
    
    def delete_ioc(self, ip_address):
        """
        Delete IOC record by IP address
        
        Args:
            ip_address: IP address to delete
            
        Returns:
            Boolean: True if deleted, False if not found
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM iocs WHERE ip_address=?", (ip_address,))
        deleted = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return deleted
    
    # ========================================================================
    # Check History Operations
    # ========================================================================
    
    def insert_check(self, ip, score, country, source):
        """
        Insert check history record
        
        Args:
            ip: IP address checked
            score: Abuse score (can be None)
            country: Country code
            source: Source of check (e.g., 'AbuseIPDB', 'OTX')
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO checks (ip, score, country, checked_at, source) VALUES (?,?,?,?,?)",
            (ip, score, country, self._utcnow_iso(), source)
        )
        conn.commit()
        conn.close()
    
    def get_recent_checks(self, limit=100):
        """
        Get recent check history
        
        Args:
            limit: Maximum number of records (default 100)
            
        Returns:
            List of dictionaries with check history
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, ip, score, country, checked_at, source FROM checks ORDER BY checked_at DESC LIMIT ?",
            (limit,)
        )
        rows = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return rows
    
    def get_checks_by_ip(self, ip_address):
        """
        Get all checks for specific IP
        
        Args:
            ip_address: IP address to lookup
            
        Returns:
            List of check records for the IP
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, ip, score, country, checked_at, source FROM checks WHERE ip=? ORDER BY checked_at DESC",
            (ip_address,)
        )
        rows = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return rows
    
    # ========================================================================
    # Geo Cache Operations
    # ========================================================================
    
    def get_geo_cache(self, ip):
        """
        Get cached geo information for IP address
        
        Args:
            ip: IP address
            
        Returns:
            Dictionary with geo data or None if not cached
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM geocache WHERE ip=?", (ip,))
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None
    
    def insert_geo_cache(self, ip, country, country_code, region, city, lat, lon, isp, org, asn):
        """
        Insert or update geo cache
        
        Args:
            ip: IP address
            country: Country name
            country_code: Two-letter country code
            region: Region/state name
            city: City name
            lat: Latitude
            lon: Longitude
            isp: ISP name
            org: Organization name
            asn: Autonomous System Number
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO geocache 
            (ip, country, country_code, region, city, lat, lon, isp, org, asn, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """, (ip, country, country_code, region, city, lat, lon, isp, org, asn, self._utcnow_iso()))
        conn.commit()
        conn.close()
    
    def clear_old_geo_cache(self, days=30):
        """
        Clear geo cache entries older than specified days
        
        Args:
            days: Number of days (default 30)
            
        Returns:
            Number of records deleted
        """
        from datetime import timedelta
        cutoff_date = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM geocache WHERE updated_at < ?", (cutoff_date,))
        deleted = cursor.rowcount
        conn.commit()
        conn.close()
        return deleted
    
    # ========================================================================
    # Utility Methods
    # ========================================================================
    
    @staticmethod
    def _utcnow_iso():
        """
        Get current UTC time in ISO format
        
        Returns:
            String: ISO-formatted UTC timestamp
        """
        return datetime.now(timezone.utc).isoformat()
    
    def vacuum(self):
        """
        Optimize database by running VACUUM
        Reclaims unused space and defragments the database
        """
        conn = self.get_connection()
        conn.execute("VACUUM")
        conn.close()
    
    def get_database_stats(self):
        """
        Get database statistics
        
        Returns:
            Dictionary with database statistics
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        
        stats = {}
        
        # Get table counts
        cursor.execute("SELECT COUNT(*) as count FROM iocs")
        stats['total_iocs'] = cursor.fetchone()['count']
        
        cursor.execute("SELECT COUNT(*) as count FROM checks")
        stats['total_checks'] = cursor.fetchone()['count']
        
        cursor.execute("SELECT COUNT(*) as count FROM geocache")
        stats['total_geocache'] = cursor.fetchone()['count']
        
        # Get database file size
        import os
        if os.path.exists(self.db_path):
            stats['db_size_bytes'] = os.path.getsize(self.db_path)
            stats['db_size_mb'] = round(stats['db_size_bytes'] / (1024 * 1024), 2)
        else:
            stats['db_size_bytes'] = 0
            stats['db_size_mb'] = 0
        
        conn.close()
        return stats


# ============================================================================
# Global database instance
# ============================================================================
db = Database()