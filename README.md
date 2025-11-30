# SDN-based Adaptive Load Balancer + Firewall

A unified Software-Defined Networking (SDN) application that combines stateless ACL-based firewall functionality with round-robin load balancing, implemented using Ryu controller and Mininet emulation platform.

## Project Overview

This project implements a single SDN controller application that provides:

1. **Stateless ACL-based Firewall**
   - Blocks traffic from specific source IPs
   - Blocks/restricts specific destination TCP/UDP ports
   - Configurable default allow/deny behavior

2. **Round-Robin Load Balancer**
   - Virtual IP (VIP): `10.0.0.100`
   - Backend servers: `10.0.0.11`, `10.0.0.12`, `10.0.0.13`
   - ARP spoofing for VIP → fake MAC mapping
   - Packet rewriting for load distribution
   - Optional adaptive load balancing based on traffic statistics

3. **Mininet Topology**
   - 1 Open vSwitch (s1)
   - 3 Client hosts (h1, h2, h3)
   - 3 Server hosts (h4, h5, h6)
   - Automatic HTTP server startup on backend hosts

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Project Structure](#project-structure)
- [Usage](#usage)
- [Testing](#testing)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)
- [Architecture Details](#architecture-details)

## Prerequisites

### System Requirements

- **Operating System**: Linux (Ubuntu 18.04+ recommended) or macOS
- **Python**: Python 3.6 or higher
- **Root/Sudo Access**: Required for Mininet operations

### Required Software

1. **Mininet**: Network emulation platform
2. **Ryu**: SDN controller framework
3. **Open vSwitch (OVS)**: Software switch (usually comes with Mininet)
4. **Python packages**: See installation section

## Installation

### Step 1: Install Mininet

#### On Ubuntu/Debian:
```bash
# Update package list
sudo apt-get update

# Install Mininet
git clone https://github.com/mininet/mininet.git
cd mininet
git checkout 2.3.0  # Use stable version
cd util
./install.sh -a  # Install all components including OVS
```

#### On macOS:
```bash
# Install using Homebrew
brew install mininet
```

### Step 2: Install Ryu Controller

```bash
# Install Ryu using pip
pip3 install ryu

# Or install from source
git clone https://github.com/faucetsdn/ryu.git
cd ryu
pip3 install .
```

### Step 3: Install Additional Python Dependencies

```bash
pip3 install mininet
```

### Step 4: Verify Installation

```bash
# Test Mininet
sudo mn --test pingall

# Test Ryu
ryu-manager --version
```

## Project Structure

```
project/
├── ryu_app_lb_fw.py      # Unified Ryu controller application
├── topo_lb_fw.py         # Mininet topology script
├── README.md             # This file
├── test_lb_fw.sh         # Testing script (optional)
└── lec_files/            # Lecture materials (not required for project)
```

## Usage

### Step 1: Start the Ryu Controller

Open a terminal and start the Ryu controller with our application:

```bash
# Navigate to project directory
cd /path/to/project

# Start Ryu controller
ryu-manager ryu_app_lb_fw.py --verbose
```

You should see output like:
```
loading app ryu_app_lb_fw.py
loading app ryu.controller.ofp_handler
...
connected socket:<eventlet.greenio.base.GreenSocket object at 0x...> address:('127.0.0.1', 6633)
```

**Keep this terminal open** - the controller must be running.

### Step 2: Start Mininet Topology

Open a **new terminal** (keep the Ryu terminal running) and start Mininet:

```bash
# Navigate to project directory
cd /path/to/project

# Start Mininet with our topology
sudo python3 topo_lb_fw.py
```

You should see:
```
*** Creating Mininet topology
*** Adding controller
*** Adding switch
...
*** Network Topology Created Successfully
mininet>
```

### Step 3: Test the Network

Once Mininet CLI is running, you can test the network:

#### Test 1: Basic Connectivity

```bash
# From Mininet CLI
mininet> h1 ping -c 3 h4
```

#### Test 2: Load Balancing

```bash
# From Mininet CLI - make multiple requests to VIP
mininet> h1 curl -s 10.0.0.100
mininet> h1 curl -s 10.0.0.100
mininet> h1 curl -s 10.0.0.100

# Check server logs to see which server handled each request
mininet> h4 cat /tmp/h4_http.log
mininet> h5 cat /tmp/h5_http.log
mininet> h6 cat /tmp/h6_http.log
```

#### Test 3: Firewall Rules

```bash
# Test blocked port (SSH - port 22)
mininet> h1 nc -zv 10.0.0.11 22

# Test allowed port (HTTP - port 80)
mininet> h1 curl -s 10.0.0.11:80
```

#### Test 4: Multiple Clients

```bash
# Open xterm windows for multiple clients
mininet> xterm h1 h2 h3

# In each xterm, run:
curl -s 10.0.0.100
```

### Step 4: Exit

```bash
# From Mininet CLI
mininet> exit

# Stop Ryu controller with Ctrl+C in the Ryu terminal
```

## Testing

### Automated Testing Script

A testing script is provided for comprehensive testing:

```bash
# Make script executable
chmod +x test_lb_fw.sh

# Run tests (requires both Ryu and Mininet to be running)
./test_lb_fw.sh
```

### Manual Testing Commands

#### 1. Connectivity Tests

```bash
# Ping from client to server
mininet> h1 ping -c 3 10.0.0.11

# Ping VIP (should work after ARP resolution)
mininet> h1 ping -c 3 10.0.0.100
```

#### 2. Load Balancing Tests

```bash
# Make 10 requests and observe distribution
mininet> h1 bash -c 'for i in {1..10}; do echo "Request $i:"; curl -s 10.0.0.100 | grep "Server"; sleep 0.5; done'

# Check which servers handled requests
mininet> h4 tail -20 /tmp/h4_http.log
mininet> h5 tail -20 /tmp/h5_http.log
mininet> h6 tail -20 /tmp/h6_http.log
```

#### 3. Firewall Tests

```bash
# Test blocked source IP (if configured)
# First, configure a blocked IP in ryu_app_lb_fw.py:
# BLOCKED_SRC_IPS = ['10.0.0.1']
# Then restart Ryu and test:
mininet> h1 curl -s 10.0.0.100  # Should be blocked if h1 IP is in list

# Test blocked port (SSH)
mininet> h1 nc -zv 10.0.0.11 22  # Should fail

# Test allowed port (HTTP)
mininet> h1 curl -s 10.0.0.11:80  # Should succeed
```

#### 4. Performance Testing with ApacheBench

```bash
# Install ApacheBench if not available
sudo apt-get install apache2-utils  # Ubuntu/Debian
brew install httpd  # macOS

# From Mininet CLI
mininet> h1 ab -n 100 -c 10 http://10.0.0.100/
```

### Expected Results

1. **Load Balancing**: Requests to VIP should be distributed across h4, h5, h6 in round-robin fashion
2. **Firewall**: Blocked ports/IPs should be denied, allowed traffic should pass
3. **Connectivity**: All hosts should be able to ping each other
4. **HTTP Servers**: Each backend server should log requests in `/tmp/hX_http.log`

## Configuration

### Firewall Configuration

Edit `ryu_app_lb_fw.py` to configure firewall rules:

```python
# Block specific source IPs
BLOCKED_SRC_IPS = [
    '10.0.0.1',  # Block h1
    # Add more IPs as needed
]

# Block specific TCP ports
BLOCKED_TCP_PORTS = [
    22,  # SSH
    23,  # Telnet
    # Add more ports as needed
]

# Allow only specific ports (whitelist mode)
ALLOWED_TCP_PORTS = [
    80,   # HTTP
    443,  # HTTPS
    # Add more ports as needed
]

# Firewall mode
ALLOW_MODE = False  # False = blacklist, True = whitelist
DEFAULT_ALLOW = True  # Default action when no rule matches
```

### Load Balancer Configuration

Edit `ryu_app_lb_fw.py` to configure load balancing:

```python
# Virtual IP
VIP_IP = '10.0.0.100'
VIP_MAC = '00:00:00:00:00:01'

# Backend servers
BACKEND_SERVERS = {
    '10.0.0.11': {'mac': None, 'port': None, 'weight': 1},
    '10.0.0.12': {'mac': None, 'port': None, 'weight': 1},
    '10.0.0.13': {'mac': None, 'port': None, 'weight': 1},
}

# Adaptive load balancing
ENABLE_ADAPTIVE_LB = False  # Set to True to enable adaptive balancing
STATS_POLL_INTERVAL = 5  # Seconds between statistics polling
ADAPTIVE_THRESHOLD = 0.8  # Load threshold (0.0-1.0)
```

**Note**: See `ADAPTIVE_LB_GUIDE.md` for detailed instructions on enabling and using adaptive load balancing.

### Topology Configuration

Edit `topo_lb_fw.py` to modify network topology:

```python
# Controller settings
CONTROLLER_IP = '127.0.0.1'
CONTROLLER_PORT = 6633

# Host IPs
CLIENT_IPS = {
    'h1': '10.0.0.1',
    'h2': '10.0.0.2',
    'h3': '10.0.0.3',
}

SERVER_IPS = {
    'h4': '10.0.0.11',
    'h5': '10.0.0.12',
    'h6': '10.0.0.13',
}
```

## Troubleshooting

### Issue: Controller Connection Failed

**Symptoms**: Mininet shows "Unable to contact the remote controller"

**Solutions**:
1. Ensure Ryu controller is running before starting Mininet
2. Check controller IP and port in `topo_lb_fw.py`
3. Verify firewall isn't blocking port 6633
4. Try: `sudo netstat -tulpn | grep 6633` to check if controller is listening

### Issue: ARP Not Resolving for VIP

**Symptoms**: Ping to VIP fails, curl to VIP fails

**Solutions**:
1. Check Ryu controller logs for ARP handling
2. Verify VIP_IP and VIP_MAC in `ryu_app_lb_fw.py`
3. Try: `mininet> h1 arp -a` to check ARP table
4. Manually add ARP entry: `mininet> h1 arp -s 10.0.0.100 00:00:00:00:00:01`

### Issue: Load Balancing Not Working

**Symptoms**: All requests go to same server

**Solutions**:
1. Check Ryu controller logs for load balancing decisions
2. Verify backend server IPs are correct
3. Check if flow entries are being installed: `mininet> dpctl dump-flows`
4. Clear flows and retry: `mininet> dpctl del-flows`

### Issue: Firewall Not Blocking Traffic

**Symptoms**: Blocked ports/IPs still allow traffic

**Solutions**:
1. Verify firewall rules in `ryu_app_lb_fw.py`
2. Check Ryu controller logs for firewall decisions
3. Ensure rules are applied before load balancing logic
4. Restart Ryu controller after changing firewall rules

### Issue: HTTP Servers Not Starting

**Symptoms**: curl to servers returns connection refused

**Solutions**:
1. Check server logs: `mininet> h4 cat /tmp/h4_http.log`
2. Manually start server: `mininet> h4 python3 -m http.server 80 &`
3. Check if port 80 is already in use
4. Verify Python3 is available on hosts

### Issue: Permission Denied

**Symptoms**: Cannot run Mininet or Ryu commands

**Solutions**:
1. Use `sudo` for Mininet: `sudo python3 topo_lb_fw.py`
2. Check file permissions: `chmod +x topo_lb_fw.py`
3. Ensure user is in sudoers group

## Architecture Details

### OpenFlow Flow Table Structure

The application uses OpenFlow 1.3 with the following flow priorities:

- **Priority 0**: Table-miss (send to controller)
- **Priority 10**: L2 learning flows
- **Priority 100**: Load balancer flows (VIP → backend)
- **Priority 100**: Return traffic flows (backend → VIP → client)

### Packet Flow

1. **Client → VIP Request**:
   - Client sends packet to VIP (10.0.0.100)
   - Switch sends PACKET_IN to controller
   - Controller applies firewall rules
   - Controller selects backend using round-robin
   - Controller rewrites destination IP/MAC
   - Controller installs flow entry
   - Packet forwarded to selected backend

2. **Backend → Client Response**:
   - Backend sends response to client
   - Switch sends PACKET_IN to controller
   - Controller rewrites source IP/MAC to VIP
   - Controller installs reverse flow entry
   - Packet forwarded to client

### ARP Handling

- Controller responds to ARP requests for VIP
- Uses fake MAC address (00:00:00:00:00:01) for VIP
- Learns real MAC addresses from ARP packets

### Firewall Implementation

- Stateless ACL-based filtering
- Checks source IP against blacklist
- Checks destination port against blacklist/whitelist
- Default action configurable (allow/deny)

### Load Balancing Algorithm

- **Round-Robin**: Simple counter-based selection
- **Adaptive (Optional)**: Based on traffic statistics (placeholder for future implementation)

## Future Enhancements

1. **Full Adaptive Load Balancing**: Implement complete statistics polling and weight adjustment
2. **Stateful Firewall**: Track connection state for more sophisticated filtering
3. **Health Checks**: Monitor backend server health and remove failed servers
4. **Session Persistence**: Maintain client-server affinity
5. **REST API**: Add REST API for dynamic rule management
6. **Web Dashboard**: Visual interface for monitoring and configuration

## References

- [Ryu Documentation](https://ryu.readthedocs.io/)
- [Mininet Documentation](http://mininet.org/)
- [OpenFlow Specification](https://opennetworking.org/software-defined-standards/specifications/)
- [Open vSwitch Documentation](https://www.openvswitch.org/)

## License

This project is for educational purposes as part of a class assignment.

## Authors

- Sanskar Pal - Topology design and system integration
- Pratham Saxena - Firewall implementation and REST API policy interface
- Manav Sharma - Load balancing logic, adaptive algorithm, and performance metrics

## Acknowledgments

This project uses the Ryu SDN framework and Mininet network emulation platform.

