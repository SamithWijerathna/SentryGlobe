#!/usr/bin/env python3
import os
import re
import time
import json
import logging
import threading
import subprocess
from datetime import datetime, timedelta
from collections import defaultdict
from flask import Flask, Response, jsonify
from flask_cors import CORS
import requests


class IPSystem:
    def __init__(self):
        self.ip_attempts = defaultdict(int)
        self.blocked_ips = {}
        self.BLOCK_TIMEOUT = timedelta(hours=2)  # 2 hour block duration
        
    def record_attempt(self, ip):
        self.ip_attempts[ip] += 1
        
        # Auto-block IPs after 5 failed attempts
        if self.ip_attempts[ip] >= 5:
            self.block_ip(ip)
            
    def block_ip(self, ip):
        if ip not in self.blocked_ips:
            try:
                # Use iptables to block the IP
                subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
                self.blocked_ips[ip] = datetime.now()
                logging.warning(f"Blocked malicious IP: {ip}")
                return True
            except subprocess.CalledProcessError as e:
                logging.error(f"Failed to block IP {ip}: {str(e)}")
        return False
    
    def unblock_expired(self):
        now = datetime.now()
        expired = [ip for ip, time in self.blocked_ips.items() 
                  if (now - time) > self.BLOCK_TIMEOUT]
        
        for ip in expired:
            try:
                subprocess.run(['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
                del self.blocked_ips[ip]
                logging.info(f"Auto-unblocked IP: {ip}")
            except subprocess.CalledProcessError as e:
                logging.error(f"Failed to unblock IP {ip}: {str(e)}")
    
    def is_blocked(self, ip):
        return ip in self.blocked_ips
    
    def get_stats(self):
        return {
            'blocked_ips': len(self.blocked_ips),
            'recent_attempts': len(self.ip_attempts)
        }


app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

# Configuration
LOG_FILE = "/var/log/auth.log"
SERVER_IP = "209.74.64.184"
SERVER_LOCATION = {'lat': 6.9271, 'lng': 79.8612}
BLACKLIST_THRESHOLD = 5  
WHITELIST_IPS = ['127.0.0.1']  # Add trusted IPs here

ip_system = IPSystem()

# Schedule periodic IP unblocking
def schedule_unblock():
    while True:
        ip_system.unblock_expired()
        time.sleep(60 * 5)  # Run every 5 minutes

threading.Thread(target=schedule_unblock, daemon=True).start()


def get_ip_geo(ip):
    try:
        response = requests.get(f'https://ipwho.is/{ip}', timeout=2)
        data = response.json()
        if data.get("success", False):
            return {
                'lat': data.get("latitude", 0.0),
                'lng': data.get("longitude", 0.0),
                'country': data.get("country", "Unknown"),
                'isp': data.get("connection", {}).get("isp", "Unknown")
            }
    except Exception as e:
        logging.warning(f"GeoIP API error for IP {ip}: {str(e)}")
    
    return {
        'lat': 0,
        'lng': 0,
        'country': 'Unknown',
        'isp': 'Unknown'
    }


def tail_log():
    try:
        with open(LOG_FILE, 'r', errors='ignore') as f:
            f.seek(0, os.SEEK_END)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                yield line
    except Exception as e:
        logging.error(f"Log file error: {str(e)}")


@app.route('/api/ssh-stream')
def ssh_stream():
    def generate():
        for line in tail_log():
            if "Failed password" in line or "Invalid user" in line:
                ip_match = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', line)
                if ip_match:
                    ip = ip_match.group()
                    
                    # Skip whitelisted IPs
                    if ip in WHITELIST_IPS:
                        continue
                        
                    # Skip if already blocked
                    if ip_system.is_blocked(ip):
                        continue
                        
                    # Record and potentially block IP    
                    ip_system.record_attempt(ip)
                    
                    geo = get_ip_geo(ip)
                    attack = {
                        'ip': ip,
                        'server_ip': SERVER_IP,
                        'lat': geo['lat'],
                        'lng': geo['lng'],
                        'country': geo['country'],
                        'isp': geo['isp'],
                        'timestamp': datetime.utcnow().isoformat(),
                        'event': "Failed SSH attempt",
                        'attempts': ip_system.ip_attempts[ip],
                        'blocked': ip_system.is_blocked(ip)
                    }
                    yield f"data: {json.dumps(attack)}\n\n"
    return Response(generate(), mimetype='text/event-stream')


@app.route('/api/history')
def attack_history():
    attacks = []
    with open(LOG_FILE, 'r', errors='ignore') as f:
        for line in f:
            if "Failed password" in line or "Invalid user" in line:
                ip_match = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', line)
                if ip_match:
                    ip = ip_match.group()
                    if ip in WHITELIST_IPS:
                        continue
                        
                    geo = get_ip_geo(ip)
                    attacks.append({
                        'ip': ip,
                        'lat': geo['lat'],
                        'lng': geo['lng'],
                        'country': geo['country'],
                        'isp': geo['isp'],
                        'timestamp': datetime.utcnow().isoformat(),
                        'event': "Historical attack",
                        'attempts': ip_system.ip_attempts.get(ip, 1),
                        'blocked': ip_system.is_blocked(ip)
                    })
    return jsonify(attacks[-100:])  # Return last 100 attacks


@app.route('/api/blocked')
def get_blocked_ips():
    return jsonify({
        'blocked_ips': [
            {
                'ip': ip, 
                'time_blocked': time.strftime("%Y-%m-%d %H:%M:%S"),
                'time_remaining': str(ip_system.BLOCK_TIMEOUT - (datetime.now() - ip_system.blocked_ips[ip]))
            } for ip in ip_system.blocked_ips
        ],
        'stats': ip_system.get_stats()
    })


@app.route('/api/block/<ip>', methods=['POST'])
def manual_block_ip(ip):
    if not re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', ip):
        return jsonify({'error': 'Invalid IP format'}), 400
        
    if ip in WHITELIST_IPS:
        return jsonify({'error': 'Cannot block whitelisted IP'}), 400
        
    success = ip_system.block_ip(ip)
    return jsonify({'success': success, 'ip': ip})


@app.route('/api/unblock/<ip>', methods=['POST'])
def manual_unblock_ip(ip):
    if not re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', ip):
        return jsonify({'error': 'Invalid IP format'}), 400
        
    if ip in ip_system.blocked_ips:
        try:
            subprocess.run(['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
            del ip_system.blocked_ips[ip]
            return jsonify({'success': True, 'ip': ip})
        except subprocess.CalledProcessError as e:
            return jsonify({'error': str(e)}), 500
    else:
        return jsonify({'error': 'IP not currently blocked'}), 404


if __name__ == '__main__':
    # Ensure required packages
    try:
        import flask_cors
    except ImportError:
        os.system("pip3 install flask flask-cors requests")
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('/var/log/ssh_defender.log'),
            logging.StreamHandler()
        ]
    )
    
    # Check for root privileges (required for iptables)
    if os.geteuid() != 0:
        logging.warning("Running without root privileges - IP blocking features may not work!")
    
    app.run(
        host='0.0.0.0',
        port=5000,
        threaded=True
    )
