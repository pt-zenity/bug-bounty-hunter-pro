#!/usr/bin/env python3
"""
Bug Bounty Hunter Pro - Main Server
Serves static files and proxies to API
"""
from flask import Flask, send_from_directory, send_file, redirect
from flask_cors import CORS
import os

app = Flask(__name__, static_folder='static', template_folder='templates')
CORS(app)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

@app.route('/')
def index():
    return send_file(os.path.join(BASE_DIR, 'templates', 'index.html'))

@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory(os.path.join(BASE_DIR, 'static'), filename)

@app.route('/favicon.ico')
def favicon():
    return '', 204

if __name__ == '__main__':
    print("[*] Bug Bounty Hunter Pro - Frontend Server")
    print("[*] Listening on http://127.0.0.1:8080")
    app.run(host='127.0.0.1', port=8080, debug=False)
