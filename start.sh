#!/bin/bash
# Bug Bounty Hunter Pro - Startup Script

set -e

WEBAPP_DIR="/home/user/webapp"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  🔴 Bug Bounty Hunter Pro - Starting Services"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Create logs directory
mkdir -p "$WEBAPP_DIR/logs"

# Kill existing processes
echo "[*] Cleaning up existing processes..."
pkill -f "app.py" 2>/dev/null || true
pkill -f "server.py" 2>/dev/null || true
nginx -s stop 2>/dev/null || true
fuser -k 3000/tcp 2>/dev/null || true
fuser -k 5000/tcp 2>/dev/null || true
fuser -k 8080/tcp 2>/dev/null || true
sleep 1

# Start Python API backend
echo "[*] Starting API backend (port 5000)..."
cd "$WEBAPP_DIR"
nohup python3 -u api/app.py > logs/api.log 2>&1 &
echo $! > logs/api.pid
sleep 2

# Start Frontend server
echo "[*] Starting Frontend server (port 8080)..."
nohup python3 -u server.py > logs/frontend.log 2>&1 &
echo $! > logs/frontend.pid
sleep 1

# Start Nginx
echo "[*] Starting Nginx (port 3000)..."
nginx -c "$WEBAPP_DIR/nginx.conf" -p "$WEBAPP_DIR/"
sleep 1

# Verify services
echo ""
echo "[*] Checking services..."

check_port() {
    local port=$1
    local name=$2
    if curl -s "http://localhost:$port" > /dev/null 2>&1 || nc -z localhost $port 2>/dev/null; then
        echo "  ✅ $name (port $port) - Running"
    else
        echo "  ❌ $name (port $port) - Not responding"
    fi
}

sleep 2
check_port 5000 "API Backend"
check_port 8080 "Frontend"
check_port 3000 "Nginx Proxy"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  🌐 Application: http://localhost:3000"
echo "  🔌 API Health:  http://localhost:3000/api/health"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
