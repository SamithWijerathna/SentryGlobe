#!/usr/bin/env python3

import os

import re

import time

import json

import random

import logging

import threading

from collections import defaultdict

from flask import Flask, jsonify

from flask_cors import CORS

from flask_socketio import SocketIO, emit

import requests



app = Flask(__name__)

CORS(app, resources={r"/*": {"origins": "*"}})

socketio = SocketIO(app, cors_allowed_origins="*")



# Configuration

LOG_FILE = "/var/log/auth.log"

SERVER_IP = "209.74.64.184"

SERVER_LOCATION = {

    'lat': 6.9271,

    'lng': 79.8612,

    'name': "Production Server"

}



# Cache to avoid duplicate lookups

ip_cache = {}

# Attack counters

ip_attack_counts = defaultdict(int)

total_attacks = 0

live_attacks = 0



def get_ip_geo(ip):

    if ip in ip_cache:

        return ip_cache[ip]

    

    try:

        response = requests.get(f'https://ipwho.is/{ip}', timeout=2)

        data = response.json()

        if data.get("success", False):

            geo = {

                'lat': data.get("latitude", 0.0),

                'lng': data.get("longitude", 0.0),

                'country': data.get("country", "Unknown"),

                'timezone': data.get("timezone", {}).get("id", "UTC") if isinstance(data.get("timezone"), dict) else "UTC"

            }

            ip_cache[ip] = geo

            return geo

    except Exception as e:

        logging.warning(f"GeoIP API error for IP {ip}: {str(e)}")



    fallback = {

        'lat': random.uniform(-90, 90),

        'lng': random.uniform(-180, 180),

        'country': 'Unknown',

        'timezone': 'UTC'

    }

    ip_cache[ip] = fallback

    return fallback



def monitor_log():

    """Monitor log file and emit attacks via WebSocket"""

    global total_attacks, live_attacks

    try:

        with open(LOG_FILE, 'r') as f:

            # Move to end of file to only get new entries

            f.seek(0, os.SEEK_END)

            while True:

                line = f.readline()

                if not line:

                    time.sleep(0.1)

                    continue

                

                if "Failed password" in line or "Invalid user" in line:

                    ip_match = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', line)

                    if ip_match:

                        ip = ip_match.group()

                        geo = get_ip_geo(ip)

                        

                        # Update counters

                        ip_attack_counts[ip] += 1

                        total_attacks += 1

                        live_attacks += 1

                        

                        attack = {

                            'ip': ip,

                            'server_ip': SERVER_IP,

                            'lat': geo['lat'],

                            'lng': geo['lng'],

                            'country': geo['country'],

                            'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),

                            'event': "Failed SSH attempt",

                            'attempt_count': ip_attack_counts[ip],

                            'total_attacks': total_attacks,

                            'live_attacks': live_attacks

                        }

                        socketio.emit('ssh_attack', attack)

                        logging.info(f"Attack #{ip_attack_counts[ip]} detected from {ip} ({geo['country']})")

    except Exception as e:

        logging.error(f"Log monitoring error: {str(e)}")



@socketio.on('connect')

def handle_connect():

    logging.info('Client connected')

    emit('connected', {'data': 'Connected to SSH monitor'})



@socketio.on('disconnect')

def handle_disconnect():

    logging.info('Client disconnected')



@app.route('/api/history')

def attack_history():

    global total_attacks

    attacks = []

    ip_counts = defaultdict(int)

    

    try:

        with open(LOG_FILE, 'r') as f:

            for line in f:

                if "Failed password" in line or "Invalid user" in line:

                    ip_match = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', line)

                    if ip_match:

                        ip = ip_match.group()

                        ip_counts[ip] += 1

                        geo = get_ip_geo(ip)

                        attacks.append({

                            'ip': ip,

                            'lat': geo['lat'],

                            'lng': geo['lng'],

                            'country': geo['country'],

                            'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),

                            'event': "Historical attack",

                            'attempt_count': ip_counts[ip]

                        })

        

        # Update global counters

        total_attacks = len(attacks)

        ip_attack_counts.update(ip_counts)

        

    except Exception as e:

        logging.error(f"Error reading log: {str(e)}")

    

    return jsonify({

        'attacks': attacks[-50:],

        'stats': {

            'total_attacks': total_attacks,

            'unique_ips': len(ip_counts),

            'top_attackers': sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]

        }

    })



@app.route('/api/stats')

def get_stats():

    return jsonify({

        'total_attacks': total_attacks,

        'live_attacks': live_attacks,

        'unique_ips': len(ip_attack_counts),

        'top_attackers': sorted(ip_attack_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    })



if __name__ == '__main__':

    # Ensure required packages

    try:

        import flask_socketio

    except ImportError:

        os.system("pip3 install flask flask-cors flask-socketio requests")



    logging.basicConfig(level=logging.INFO)
    
    # Start log monitoring in background thread

    log_thread = threading.Thread(target=monitor_log, daemon=True)

    log_thread.start()



    socketio.run(

        app,

        host='0.0.0.0',

        port=5000,

        debug=False

    )
