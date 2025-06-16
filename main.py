#!/usr/bin/env python3

import os

import re

import time

import json

import random

import logging

from flask import Flask, Response, jsonify

from flask_cors import CORS

import requests



app = Flask(__name__)

CORS(app)



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



def tail_log():

    try:

        with open(LOG_FILE, 'r') as f:

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

                    geo = get_ip_geo(ip)

                    attack = {

                        'ip': ip,

                        'server_ip': SERVER_IP,

                        'lat': geo['lat'],

                        'lng': geo['lng'],

                        'country': geo['country'],

                        'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),

                        'event': "Failed SSH attempt"

                    }

                    yield f"data: {json.dumps(attack)}\n\n"

    return Response(generate(), mimetype='text/event-stream')



@app.route('/api/history')

def attack_history():

    attacks = []

    try:

        with open(LOG_FILE, 'r') as f:

            for line in f:

                if "Failed password" in line or "Invalid user" in line:

                    ip_match = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', line)

                    if ip_match:

                        ip = ip_match.group()

                        geo = get_ip_geo(ip)

                        attacks.append({

                            'ip': ip,

                            'lat': geo['lat'],

                            'lng': geo['lng'],

                            'country': geo['country'],

                            'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),

                            'event': "Historical attack"

                        })

    except Exception as e:

        logging.error(f"Error reading log: {str(e)}")

    return jsonify(attacks[-50:])



if __name__ == '__main__':

    # Ensure required packages

    try:

        import flask_cors

    except ImportError:

        os.system("pip3 install flask flask-cors requests")



    logging.basicConfig(level=logging.INFO)



    app.run(

        host='0.0.0.0',

        port=5000,

        threaded=True

    )
