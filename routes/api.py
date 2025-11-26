from flask import Blueprint, request, jsonify, Response
from datetime import datetime
import json
import uuid

from models.database import db
from services.abuseipdb import AbuseIPDBService
from services.otx import OTXService
from services.geo import GeoService
from utils.validators import is_valid_ip
from utils.helpers import risk_label, utcnow_iso
from routes.auth import login_required, api_keys_required

api_bp = Blueprint('api', __name__, url_prefix='/api')


# ============================================================================
# IP Intelligence Endpoints
# ============================================================================

@api_bp.route('/check_ip', methods=['POST'])
@login_required
@api_keys_required
def check_ip():
    """
    Check IP address reputation using AbuseIPDB and OTX
    
    Request:
        POST /api/check_ip
        Body: {"ip": "x.x.x.x"}
    
    Response:
        {
            "abuse": {...},  # AbuseIPDB results
            "otx": {...}     # OTX results
        }
    """
    try:
        data = request.get_json() or {}
        ip = data.get('ip') or data.get('address') or ''
        ip = ip.strip()
        
        if not ip:
            return jsonify({"error": "No IP provided"}), 400
        
        if not is_valid_ip(ip):
            return jsonify({"error": "Invalid IP address"}), 400
        
        # Check with AbuseIPDB
        try:
            abuse_service = AbuseIPDBService()
            abuse_result = abuse_service.check_ip(ip)
        except Exception as e:
            abuse_result = {"error": f"AbuseIPDB error: {str(e)}"}
        
        # Check with OTX
        try:
            otx_service = OTXService()
            otx_result = otx_service.query_ip(ip)
        except Exception as e:
            otx_result = {"error": f"OTX error: {str(e)}"}
        
        return jsonify({
            "abuse": abuse_result,
            "otx": otx_result
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@api_bp.route('/fetch_blacklist', methods=['POST'])
@login_required
@api_keys_required
def fetch_blacklist():
    """
    Fetch blacklist from AbuseIPDB and store in database
    
    Request:
        POST /api/fetch_blacklist
    
    Response:
        {"added": 100}  # Number of records added/updated
    """
    try:
        abuse_service = AbuseIPDBService()
        added = abuse_service.fetch_blacklist(limit=100)
        return jsonify(added)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@api_bp.route('/top_malicious', methods=['GET'])
@login_required
@api_keys_required
def top_malicious():
    """
    Get top malicious IPs ordered by abuse confidence score
    
    Request:
        GET /api/top_malicious
    
    Response:
        {
            "items": [
                {
                    "ip": "x.x.x.x",
                    "score": 100,
                    "country": "US",
                    "last_seen": "2025-01-01T00:00:00Z"
                },
                ...
            ]
        }
    """
    try:
        items = db.get_all_iocs(limit=25)
        return jsonify({"items": items})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@api_bp.route('/totals', methods=['GET'])
@login_required
@api_keys_required
def totals():
    """
    Get database statistics and totals
    
    Request:
        GET /api/totals
    
    Response:
        {
            "total_records": 1000,
            "current_time": "2025-01-01 00:00:00"
        }
    """
    try:
        total = db.get_ioc_count()
        return jsonify({
            "total_records": total,
            "current_time": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@api_bp.route('/geo', methods=['GET'])
@login_required
@api_keys_required
def geo():
    """
    Get geolocation information for IP address
    
    Request:
        GET /api/geo?ip=x.x.x.x
    
    Response:
        {
            "ip": "x.x.x.x",
            "country": "United States",
            "country_code": "US",
            "city": "New York",
            "lat": 40.7128,
            "lon": -74.0060,
            ...
        }
    """
    ip = request.args.get("ip", "").strip()
    
    if not ip or not is_valid_ip(ip):
        return jsonify({"error": "Invalid IP"}), 400
    
    try:
        geo_service = GeoService()
        geo_data = geo_service.lookup(ip)
        return jsonify(geo_data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================================
# SIEM Export Endpoints
# ============================================================================

@api_bp.route('/export/csv')
@login_required
@api_keys_required
def export_csv():
    """
    Export IOCs as CSV file for SIEM integration
    
    Request:
        GET /api/export/csv
    
    Response:
        CSV file download with columns:
        ip_address, abuse_confidence, country_code, last_seen, risk_label
    """
    try:
        rows = db.get_all_iocs()
        
        # Build CSV content
        lines = ["ip_address,abuse_confidence,country_code,last_seen,risk_label"]
        
        for row in rows:
            label, _ = risk_label(row.get("abuse_confidence"))
            ip = row.get("ip_address") or ""
            score = row.get("abuse_confidence") if row.get("abuse_confidence") is not None else ""
            cc = row.get("country_code") or ""
            ls = row.get("last_seen") or ""
            lines.append(f"{ip},{score},{cc},{ls},{label}")
        
        csv_content = "\n".join(lines)
        
        return Response(
            csv_content,
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=iocs_export.csv"}
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@api_bp.route('/export/json')
@login_required
@api_keys_required
def export_json():
    """
    Export IOCs as JSON file for SIEM integration
    
    Request:
        GET /api/export/json
    
    Response:
        JSON file download with structure:
        {
            "generated_at": "ISO timestamp",
            "items": [...]
        }
    """
    try:
        rows = db.get_all_iocs()
        
        # Add risk labels to each record
        for row in rows:
            row["risk_label"] = risk_label(row.get("abuse_confidence"))[0]
        
        export_data = {
            "generated_at": utcnow_iso(),
            "total_items": len(rows),
            "items": rows
        }
        
        return Response(
            json.dumps(export_data, indent=2),
            mimetype="application/json",
            headers={"Content-Disposition": "attachment; filename=iocs_export.json"}
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@api_bp.route('/export/stix')
@login_required
@api_keys_required
def export_stix():
    """
    Export IOCs as STIX 2.1 bundle for SIEM integration
    
    Request:
        GET /api/export/stix
    
    Response:
        STIX 2.1 JSON file download
        Compatible with: MISP, OpenCTI, ThreatConnect, etc.
    """
    try:
        rows = db.get_all_iocs()
        now = utcnow_iso()
        objects = []
        
        # Create STIX indicator object for each IOC
        for row in rows:
            ip = row.get("ip_address")
            score = row.get("abuse_confidence", 0) or 0
            label = risk_label(score)[0]
            
            indicator = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "created": now,
                "modified": now,
                "name": f"IP reputation: {ip}",
                "description": f"AbuseIPDB score {score}, risk {label}",
                "indicator_types": ["malicious-activity"] if score >= 30 else ["anomalous-activity"],
                "pattern": f"[ipv4-addr:value = '{ip}']",
                "pattern_type": "stix",
                "valid_from": now,
                "x_abuseipdb_score": score,
                "x_country_code": row.get("country_code"),
                "x_risk_label": label
            }
            objects.append(indicator)
        
        # Create STIX bundle
        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "spec_version": "2.1",
            "objects": objects
        }
        
        return Response(
            json.dumps(bundle, indent=2),
            mimetype="application/stix+json",
            headers={"Content-Disposition": "attachment; filename=iocs_export.stix.json"}
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================================
# Health Check Endpoint
# ============================================================================

@api_bp.route('/health', methods=['GET'])
def health():
    """
    Health check endpoint for monitoring
    No authentication required
    
    Request:
        GET /api/health
    
    Response:
        {
            "status": "healthy",
            "timestamp": "ISO timestamp"
        }
    """
    return jsonify({
        "status": "healthy",
        "timestamp": utcnow_iso(),
        "version": "2.0.0"
    })