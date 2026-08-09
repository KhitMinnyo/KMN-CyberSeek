#!/bin/bash

# KMN-CyberSeek Startup Script
# Starts both FastAPI backend and Streamlit frontend

echo "🚀 Starting KMN-CyberSeek - AI-Driven Autonomous Red Team Operator"
echo "================================================================"

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 is not installed. Please install Python 3.8+ first."
    exit 1
fi

# Check if required packages are installed
echo "📦 Checking dependencies..."
if [ ! -f "requirements.txt" ]; then
    echo "❌ requirements.txt not found!"
    exit 1
fi

# Check if virtual environment exists, create if not
if [ ! -d "venv" ]; then
    echo "🔧 Creating virtual environment..."
    python3 -m venv venv
    if [ $? -ne 0 ]; then
        echo "❌ Failed to create virtual environment"
        exit 1
    fi
fi

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source venv/bin/activate

# Install requirements if not already installed
echo "📦 Installing dependencies..."
pip install -r requirements.txt --quiet
if [ $? -ne 0 ]; then
    echo "❌ Failed to install dependencies"
    exit 1
fi

# Check if Nmap is installed
if ! command -v nmap &> /dev/null; then
    echo "⚠️  Warning: Nmap is not installed. Some features may not work."
    echo "   Install with: brew install nmap (macOS) or apt install nmap (Ubuntu)"
fi

echo "ℹ️  AI is optional at startup — configure it from Settings in the web UI."

# Create .env file if it doesn't exist
if [ ! -f ".env" ]; then
    echo "🔧 Creating .env file..."
    cp .env.example .env 2>/dev/null || touch .env
    echo "⚠️  .env created. You can configure AI settings directly from the Web UI."
    # DO NOT exit here. Let the script continue.
fi

# Kill whatever is holding a port.  After killing, verify the port is free.
# System services (e.g. Apache on :8000) restart themselves — we detect that
# and tell the user exactly what to do instead of silently failing later.
_port_in_use() {
    if command -v ss &>/dev/null; then
        ss -tlnp | grep -q ":$1 "
    elif command -v lsof &>/dev/null; then
        lsof -Pi :"$1" -sTCP:LISTEN -t >/dev/null 2>&1
    else
        return 1
    fi
}

_kill_port() {
    local port=$1 pids
    _port_in_use "$port" || return 0          # already free, nothing to do

    if command -v ss &>/dev/null; then
        pids=$(ss -tlnp | awk -F'pid=' "/\":${port} \"/{print \$2}" | cut -d',' -f1)
    elif command -v lsof &>/dev/null; then
        pids=$(lsof -ti :"$port" 2>/dev/null)
    fi

    if [ -n "$pids" ]; then
        echo "⚠️  Port $port in use — stopping existing process(es): $pids"
        kill -TERM $pids 2>/dev/null
        sleep 1
        kill -KILL $pids 2>/dev/null
        sleep 1
    fi

    # Verify port is actually free now (system service may have restarted)
    if _port_in_use "$port"; then
        echo ""
        echo "❌  Port $port is still in use after kill attempt."
        echo "    A system service (e.g. Apache2) may be holding it."
        echo ""
        echo "    Fix options:"
        echo "      1. Stop the service:  sudo systemctl stop apache2"
        echo "         (or whichever service owns :$port)"
        echo "      2. Use a different port: add BACKEND_PORT=8080 to .env"
        echo ""
        exit 1
    fi
}

# Read ports from .env (fallback: 6000 / 8501)
BACKEND_PORT=$(grep -m1 "^BACKEND_PORT=" .env 2>/dev/null | cut -d'=' -f2 | tr -d '"' | tr -d "'" | tr -d ' ')
BACKEND_PORT="${BACKEND_PORT:-6000}"
FRONTEND_PORT=$(grep -m1 "^FRONTEND_PORT=" .env 2>/dev/null | cut -d'=' -f2 | tr -d '"' | tr -d "'" | tr -d ' ')
FRONTEND_PORT="${FRONTEND_PORT:-8501}"
export BACKEND_PORT FRONTEND_PORT

echo "🔍 Checking port availability..."
_kill_port "$BACKEND_PORT"
_kill_port "$FRONTEND_PORT"

# Start services
echo "🚀 Starting services..."

# Function to handle cleanup
cleanup() {
    echo "🛑 Shutting down services..."
    kill $BACKEND_PID 2>/dev/null
    kill $FRONTEND_PID 2>/dev/null
    echo "✅ Services stopped"
    exit 0
}

# Trap SIGINT (Ctrl+C) and SIGTERM
trap cleanup SIGINT SIGTERM

# Start FastAPI backend
echo "🔧 Starting FastAPI backend on http://localhost:${BACKEND_PORT}"
echo "📚 API Documentation: http://localhost:${BACKEND_PORT}/api/docs"
python3 main.py &
BACKEND_PID=$!

# Wait for backend to start
sleep 5

# Check if backend started successfully
if ! curl -s "http://localhost:${BACKEND_PORT}/health" > /dev/null; then
    echo "❌ Backend failed to start"
    kill $BACKEND_PID 2>/dev/null
    exit 1
fi

# Start Streamlit frontend
echo "🎨 Starting Streamlit frontend on http://localhost:${FRONTEND_PORT}"
streamlit run frontend.py --server.port "$FRONTEND_PORT" --server.headless true &
FRONTEND_PID=$!

# Wait for frontend to start
sleep 3

echo ""
echo "✅ KMN-CyberSeek started successfully!"
echo ""
echo "🌐 Access Points:"
echo "   Dashboard:    http://localhost:${FRONTEND_PORT}"
echo "   API Docs:     http://localhost:${BACKEND_PORT}/api/docs"
echo "   Health Check: http://localhost:${BACKEND_PORT}/health"
echo ""
echo "📋 Quick Start:"
echo "   1. Open http://localhost:${FRONTEND_PORT} in your browser"
echo "   2. Go to ⚙️  Settings → AI Configuration to set up Ollama or DeepSeek API"
echo "   3. Create a new session with target IP/domain"
echo "   4. Monitor AI-driven reconnaissance and approve high-risk commands"
echo ""
echo "🛑 Press Ctrl+C to stop all services"

# Wait for user interrupt
wait $BACKEND_PID $FRONTEND_PID