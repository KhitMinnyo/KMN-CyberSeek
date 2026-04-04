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

# Check if Ollama is running (for local AI)
if ! pgrep -x "ollama" > /dev/null; then
    echo "⚠️  Warning: Ollama is not running. Local AI features will not work."
    echo "   Start Ollama with: ollama serve"
fi

# Create .env file if it doesn't exist
if [ ! -f ".env" ]; then
    echo "🔧 Creating .env file..."
    cp .env.example .env 2>/dev/null || touch .env
    echo "⚠️  .env created. You can configure AI settings directly from the Web UI."
    # DO NOT exit here. Let the script continue.
fi

# Check if ports are available
echo "🔍 Checking port availability..."
if lsof -Pi :8000 -sTCP:LISTEN -t >/dev/null ; then
    echo "❌ Port 8000 (FastAPI) is already in use"
    exit 1
fi

if lsof -Pi :8501 -sTCP:LISTEN -t >/dev/null ; then
    echo "❌ Port 8501 (Streamlit) is already in use"
    exit 1
fi

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
echo "🔧 Starting FastAPI backend on http://localhost:8000"
echo "📚 API Documentation: http://localhost:8000/api/docs"
python3 main.py &
BACKEND_PID=$!

# Wait for backend to start
sleep 5

# Check if backend started successfully
if ! curl -s http://localhost:8000/health > /dev/null; then
    echo "❌ Backend failed to start"
    kill $BACKEND_PID 2>/dev/null
    exit 1
fi

# Start Streamlit frontend
echo "🎨 Starting Streamlit frontend on http://localhost:8501"
streamlit run frontend.py --server.port 8501 --server.headless true &
FRONTEND_PID=$!

# Wait for frontend to start
sleep 3

echo ""
echo "✅ KMN-CyberSeek started successfully!"
echo ""
echo "🌐 Access Points:"
echo "   Dashboard:    http://localhost:8501"
echo "   API Docs:     http://localhost:8000/api/docs"
echo "   Health Check: http://localhost:8000/health"
echo ""
echo "📋 Quick Start:"
echo "   1. Open http://localhost:8501 in your browser"
echo "   2. Create a new session with target IP/domain"
echo "   3. Monitor AI-driven reconnaissance and attacks"
echo "   4. Approve high-risk commands as needed"
echo ""
echo "🛑 Press Ctrl+C to stop all services"

# Wait for user interrupt
wait $BACKEND_PID $FRONTEND_PID