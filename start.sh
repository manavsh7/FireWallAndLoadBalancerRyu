#!/bin/bash
#
# Quick Start Script for SDN Load Balancer and Firewall
#
# This script helps you start the Ryu controller and Mininet topology.
#

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}SDN Load Balancer + Firewall${NC}"
echo -e "${GREEN}Quick Start Script${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Check if running as root for Mininet
if [ "$EUID" -ne 0 ]; then 
    echo -e "${YELLOW}Note: Mininet requires sudo privileges${NC}"
    echo ""
fi

# Function to check if port is in use
check_port() {
    if lsof -Pi :$1 -sTCP:LISTEN -t >/dev/null 2>&1 ; then
        return 0  # Port is in use
    else
        return 1  # Port is free
    fi
}

# Check if Ryu controller is already running
if check_port 6633; then
    echo -e "${YELLOW}Port 6633 is already in use. Ryu controller may already be running.${NC}"
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Start Ryu controller in background
echo -e "${GREEN}[1/2] Starting Ryu Controller...${NC}"
echo "Running: ryu-manager ryu_app_lb_fw.py --verbose"
echo ""

# Check if ryu-manager exists
if ! command -v ryu-manager &> /dev/null; then
    echo -e "${RED}Error: ryu-manager not found. Please install Ryu first.${NC}"
    echo "Install with: pip3 install ryu"
    exit 1
fi

# Start Ryu in background
ryu-manager ryu_app_lb_fw.py --verbose > /tmp/ryu.log 2>&1 &
RYU_PID=$!

echo -e "${GREEN}Ryu controller started (PID: $RYU_PID)${NC}"
echo "Logs: /tmp/ryu.log"
echo ""

# Wait for controller to start
echo "Waiting for controller to initialize..."
sleep 3

# Check if controller is running
if ! kill -0 $RYU_PID 2>/dev/null; then
    echo -e "${RED}Error: Ryu controller failed to start${NC}"
    echo "Check logs: cat /tmp/ryu.log"
    exit 1
fi

# Start Mininet
echo -e "${GREEN}[2/2] Starting Mininet Topology...${NC}"
echo "Running: sudo python3 topo_lb_fw.py"
echo ""
echo -e "${YELLOW}Note: You will need to manually exit Mininet CLI when done${NC}"
echo -e "${YELLOW}Use 'exit' command in Mininet CLI to stop${NC}"
echo ""

# Check if topo_lb_fw.py exists
if [ ! -f "topo_lb_fw.py" ]; then
    echo -e "${RED}Error: topo_lb_fw.py not found${NC}"
    kill $RYU_PID 2>/dev/null || true
    exit 1
fi

# Function to cleanup on exit
cleanup() {
    echo ""
    echo -e "${YELLOW}Cleaning up...${NC}"
    kill $RYU_PID 2>/dev/null || true
    echo -e "${GREEN}Done${NC}"
}

trap cleanup EXIT INT TERM

# Start Mininet (requires sudo)
sudo python3 topo_lb_fw.py

# Cleanup will be called automatically via trap

