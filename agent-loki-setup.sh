#!/bin/bash

# Loki Agent Setup Script
# Usage: curl -sSL https://raw.githubusercontent.com/Incrisz/elk-stack/main/agent-loki-setup.sh | bash
# Usage with custom server: curl -sSL https://raw.githubusercontent.com/Incrisz/elk-stack/main/agent-loki-setup.sh | bash -s YOUR_LOKI_SERVER_IP

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================================${NC}"
}

# Default Loki server IP (user should change this)
LOKI_SERVER_IP="YOUR_LOKI_SERVER_IP"

# Allow override via environment variable or parameter
if [[ -n "$1" ]]; then
    LOKI_SERVER_IP="$1"
elif [[ -n "$