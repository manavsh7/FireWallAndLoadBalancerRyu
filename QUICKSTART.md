# Quick Start Guide

## Prerequisites Check

```bash
# Check Python version (need 3.6+)
python3 --version

# Check if Mininet is installed
mn --version

# Check if Ryu is installed
ryu-manager --version
```

## Installation (if needed)

```bash
# Install Mininet (Ubuntu)
sudo apt-get update
sudo apt-get install mininet

# Install Ryu
pip3 install ryu
```

## Running the Project

### Option 1: Using the Start Script (Recommended)

```bash
# Make script executable (if not already)
chmod +x start.sh

# Run the start script
./start.sh
```

### Option 2: Manual Start

**Terminal 1 - Start Ryu Controller:**
```bash
ryu-manager ryu_app_lb_fw.py --verbose
```

**Terminal 2 - Start Mininet:**
```bash
sudo python3 topo_lb_fw.py
```

## Quick Tests

Once Mininet CLI is running:

```bash
# Test 1: Ping test
mininet> h1 ping -c 3 10.0.0.11

# Test 2: Load balancing (make 5 requests)
mininet> h1 bash -c 'for i in {1..5}; do curl -s 10.0.0.100; done'

# Test 3: Check server logs
mininet> h4 tail /tmp/h4_http.log

# Test 4: Run full test suite
mininet> sh test_lb_fw.sh
```

## Common Commands

```bash
# View flow table
mininet> dpctl dump-flows

# Check ARP table
mininet> h1 arp -a

# Test firewall (SSH should be blocked)
mininet> h1 nc -zv 10.0.0.11 22

# Test HTTP (should work)
mininet> h1 curl -s 10.0.0.11:80

# Exit Mininet
mininet> exit
```

## Troubleshooting

**Controller not connecting?**
- Make sure Ryu is running first
- Check: `sudo netstat -tulpn | grep 6633`

**ARP not resolving?**
- Wait a few seconds after starting
- Try: `mininet> h1 ping -c 1 10.0.0.100`

**Load balancing not working?**
- Check Ryu logs for LB decisions
- Verify backend IPs in `ryu_app_lb_fw.py`

**HTTP servers not responding?**
- Check logs: `mininet> h4 cat /tmp/h4_http.log`
- Manually start: `mininet> h4 python3 -m http.server 80 &`

## Configuration

Edit `ryu_app_lb_fw.py` to change:
- Firewall rules (BLOCKED_SRC_IPS, BLOCKED_TCP_PORTS)
- Load balancer settings (VIP_IP, BACKEND_SERVERS)
- Adaptive LB (ENABLE_ADAPTIVE_LB)

## Files Overview

- `ryu_app_lb_fw.py` - Main Ryu controller application
- `topo_lb_fw.py` - Mininet topology script
- `test_lb_fw.sh` - Comprehensive test suite
- `start.sh` - Quick start script
- `README.md` - Full documentation

