#!/usr/bin/env python3

"""

Premium License Server

Handles license validation, creation, and management

"""

import sqlite3
import hashlib
import uuid
import time
import json
from datetime import datetime
from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

# Database setup
def init_db():
    conn = sqlite3.connect('licenses.db')
    c = conn.cursor()
    
    # License table
    c.execute('''CREATE TABLE IF NOT EXISTS licenses
                 (id TEXT PRIMARY KEY,
                  license_key TEXT UNIQUE,
                  hwid TEXT,
                  hostname TEXT,
                  ip_address TEXT,
                  activated INTEGER DEFAULT 0,
                  activation_time INTEGER,
                  expiry_time INTEGER,
                  created_at INTEGER,
                  created_by TEXT,
                  product TEXT DEFAULT 'panel_installer',
                  last_validation INTEGER)''')
    
    # Audit log
    c.execute('''CREATE TABLE IF NOT EXISTS audit_log
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  license_key TEXT,
                  action TEXT,
                  details TEXT,
                  timestamp INTEGER,
                  ip_address TEXT)''')
    
    conn.commit()
    conn.close()

init_db()

# Configuration
SECRET_SALT = "1Jz+4,.+k,90<{PqDq|v]g&Ra;CMDpgn"  # Change this in production!
SERVER_ID = "main_server_001"
API_KEY = "cYukWqDZ0F1YFQooKVK3cDBIj6KdUpG_RKevvDOvPOY"  # For Discord bot communication

def generate_license_key():
    """Generate a unique license key"""
    raw_key = f"{uuid.uuid4()}-{int(time.time())}-{SECRET_SALT}"
    hash_key = hashlib.sha256(raw_key.encode()).hexdigest()[:20].upper()
    formatted = '-'.join([hash_key[i:i+5] for i in range(0, 20, 5)])
    return formatted

def log_audit(license_key, action, details, ip_address):
    """Log actions for security monitoring"""
    conn = sqlite3.connect('licenses.db')
    c = conn.cursor()
    c.execute('''INSERT INTO audit_log 
                 (license_key, action, details, timestamp, ip_address)
                 VALUES (?, ?, ?, ?, ?)''',
              (license_key, action, json.dumps(details), int(time.time()), ip_address))
    conn.commit()
    conn.close()

@app.route('/api/validate', methods=['POST'])
def validate_license():
    """Validate a license key"""
    data = request.json
    license_key = data.get('license_key')
    hwid = data.get('hwid')
    hostname = data.get('hostname')
    ip_address = request.remote_addr
    
    if not license_key:
        return jsonify({'valid': False, 'message': 'No license provided'})
    
    conn = sqlite3.connect('licenses.db')
    c = conn.cursor()
    
    c.execute('''SELECT * FROM licenses WHERE license_key = ?''', (license_key,))
    license_data = c.fetchone()
    
    if not license_data:
        log_audit(license_key, 'validation_failed', 
                 {'reason': 'invalid_key', 'hwid': hwid, 'hostname': hostname, 'ip': ip_address}, ip_address)
        return jsonify({'valid': False, 'message': 'Invalid license key'})
    
    # Convert to dict
    columns = ['id', 'license_key', 'hwid', 'hostname', 'ip_address', 'activated', 
               'activation_time', 'expiry_time', 'created_at', 'created_by', 'product', 'last_validation']
    license_dict = dict(zip(columns, license_data))
    
    # Check if expired
    if license_dict['expiry_time'] and time.time() > license_dict['expiry_time']:
        log_audit(license_key, 'validation_failed', 
                 {'reason': 'expired', 'hwid': hwid, 'hostname': hostname}, ip_address)
        return jsonify({'valid': False, 'message': 'License expired'})
    
    # Check if already activated
    if license_dict['activated'] == 1:
        # Update last validation time
        c.execute('''UPDATE licenses SET last_validation = ? WHERE license_key = ?''',
                  (int(time.time()), license_key))
        conn.commit()
        
        if license_dict['hwid'] != hwid:
            log_audit(license_key, 'validation_failed', 
                     {'reason': 'hwid_mismatch', 'stored_hwid': license_dict['hwid'], 
                      'provided_hwid': hwid, 'hostname': hostname}, ip_address)
            return jsonify({'valid': False, 'message': 'License already used on different system'})
        
        # Valid re-validation
        log_audit(license_key, 'validation_success', 
                 {'hwid': hwid, 'hostname': hostname, 'last_validation': time.time()}, ip_address)
        return jsonify({'valid': True, 'message': 'License valid', 'data': license_dict})
    
    # First-time activation
    c.execute('''UPDATE licenses SET 
                 hwid = ?, hostname = ?, ip_address = ?, 
                 activated = 1, activation_time = ?, last_validation = ?
                 WHERE license_key = ?''',
              (hwid, hostname, ip_address, int(time.time()), int(time.time()), license_key))
    conn.commit()
    
    log_audit(license_key, 'activation_success', 
             {'hwid': hwid, 'hostname': hostname, 'ip': ip_address}, ip_address)
    
    conn.close()
    return jsonify({'valid': True, 'message': 'License activated successfully', 'data': license_dict})

@app.route('/api/create', methods=['POST'])
def create_license():
    """Create a new license (called by Discord bot)"""
    auth_key = request.headers.get('X-API-Key')
    if auth_key != API_KEY:
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    data = request.json
    days_valid = data.get('days', 30)
    created_by = data.get('created_by', 'discord_bot')
    product = data.get('product', 'panel_installer')
    
    license_key = generate_license_key()
    expiry_time = int(time.time()) + (days_valid * 24 * 3600)
    
    conn = sqlite3.connect('licenses.db')
    c = conn.cursor()
    
    c.execute('''INSERT INTO licenses 
                 (id, license_key, expiry_time, created_at, created_by, product)
                 VALUES (?, ?, ?, ?, ?, ?)''',
              (str(uuid.uuid4()), license_key, expiry_time, int(time.time()), created_by, product))
    
    conn.commit()
    conn.close()
    
    log_audit(license_key, 'created', 
             {'by': created_by, 'days_valid': days_valid, 'product': product}, request.remote_addr)
    
    return jsonify({'success': True, 'license_key': license_key, 
                   'expiry_date': datetime.fromtimestamp(expiry_time).isoformat(),
                   'product': product})

@app.route('/api/list', methods=['GET'])
def list_licenses():
    """List all licenses (for Discord bot)"""
    auth_key = request.headers.get('X-API-Key')
    if auth_key != API_KEY:
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    conn = sqlite3.connect('licenses.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    c.execute('''SELECT license_key, activated, hwid, hostname, ip_address,
                 datetime(activation_time, 'unixepoch') as activated_at,
                 datetime(expiry_time, 'unixepoch') as expires_at,
                 datetime(last_validation, 'unixepoch') as last_validated,
                 created_by, product FROM licenses ORDER BY created_at DESC''')
    
    licenses = []
    for row in c.fetchall():
        licenses.append(dict(row))
    
    conn.close()
    return jsonify({'success': True, 'licenses': licenses})

@app.route('/api/revoke', methods=['POST'])
def revoke_license():
    """Revoke a license (for Discord bot)"""
    auth_key = request.headers.get('X-API-Key')
    if auth_key != API_KEY:
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    data = request.json
    license_key = data.get('license_key')
    
    if not license_key:
        return jsonify({'success': False, 'message': 'No license key provided'})
    
    conn = sqlite3.connect('licenses.db')
    c = conn.cursor()
    
    c.execute('DELETE FROM licenses WHERE license_key = ?', (license_key,))
    deleted = c.rowcount > 0
    
    conn.commit()
    conn.close()
    
    if deleted:
        log_audit(license_key, 'revoked', {'by': 'api'}, request.remote_addr)
        return jsonify({'success': True, 'message': 'License revoked'})
    else:
        return jsonify({'success': False, 'message': 'License not found'})

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get license statistics"""
    auth_key = request.headers.get('X-API-Key')
    if auth_key != API_KEY:
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    conn = sqlite3.connect('licenses.db')
    c = conn.cursor()
    
    c.execute('SELECT COUNT(*) FROM licenses')
    total = c.fetchone()[0]
    
    c.execute('SELECT COUNT(*) FROM licenses WHERE activated = 1')
    activated = c.fetchone()[0]
    
    c.execute('SELECT COUNT(*) FROM licenses WHERE expiry_time < ?', (int(time.time()),))
    expired = c.fetchone()[0]
    
    c.execute('SELECT COUNT(*) FROM licenses WHERE activated = 0 AND expiry_time > ?', (int(time.time()),))
    available = c.fetchone()[0]
    
    # Get active licenses count (activated and not expired)
    c.execute('''SELECT COUNT(*) FROM licenses 
                 WHERE activated = 1 AND expiry_time > ?''', (int(time.time()),))
    active = c.fetchone()[0]
    
    # Get soon to expire licenses (expiring in next 7 days)
    week_from_now = int(time.time()) + (7 * 24 * 3600)
    c.execute('''SELECT COUNT(*) FROM licenses 
                 WHERE expiry_time > ? AND expiry_time < ? AND activated = 1''', 
              (int(time.time()), week_from_now))
    expiring_soon = c.fetchone()[0]
    
    conn.close()
    
    return jsonify({
        'success': True,
        'stats': {
            'total': total,
            'activated': activated,
            'active': active,  # Activated and not expired
            'expired': expired,
            'available': available,
            'expiring_soon': expiring_soon
        }
    })

@app.route('/api/check', methods=['POST'])
def check_license():
    """Simple check if license exists (for bot validation)"""
    data = request.json
    license_key = data.get('license_key')
    
    if not license_key:
        return jsonify({'exists': False, 'message': 'No license provided'})
    
    conn = sqlite3.connect('licenses.db')
    c = conn.cursor()
    
    c.execute('SELECT license_key, activated, expiry_time FROM licenses WHERE license_key = ?', (license_key,))
    result = c.fetchone()
    conn.close()
    
    if result:
        license_key, activated, expiry_time = result
        is_valid = activated == 1 and (not expiry_time or expiry_time > time.time())
        return jsonify({
            'exists': True,
            'valid': is_valid,
            'activated': bool(activated),
            'expired': expiry_time and expiry_time < time.time()
        })
    
    return jsonify({'exists': False, 'message': 'License not found'})

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        conn = sqlite3.connect('licenses.db')
        c = conn.cursor()
        c.execute('SELECT COUNT(*) FROM licenses')
        conn.close()
        return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()})
    except Exception as e:
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 500

if __name__ == '__main__':
    # Important: Set debug=False in production!
    app.run(host='0.0.0.0', port=5000, debug=False)
