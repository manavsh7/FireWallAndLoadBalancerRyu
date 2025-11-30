#!/usr/bin/env python
"""
Mininet Topology Script for SDN Load Balancer and Firewall Project

This script creates a custom Mininet topology with:
- 1 Open vSwitch (s1)
- 3 Client hosts (h1, h2, h3)
- 3 Server hosts (h4, h5, h6)

The topology connects to a remote Ryu controller and automatically
starts HTTP servers on the backend hosts.
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import time
import os

# ============================================================================
# Configuration
# ============================================================================

# Ryu controller configuration
CONTROLLER_IP = '127.0.0.1'
CONTROLLER_PORT = 6633

# Network configuration
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

# HTTP server configuration
HTTP_PORT = 80
HTTP_LOG_DIR = '/tmp'

# ============================================================================
# Topology Creation
# ============================================================================

def create_topology():
    """
    Create and configure the Mininet topology.
    
    Returns:
        Mininet network object
    """
    info('*** Creating Mininet topology\n')
    
    # Create network with remote controller
    net = Mininet(
        controller=RemoteController,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True
    )
    
    # Add remote controller
    info('*** Adding controller\n')
    c0 = net.addController(
        'c0',
        controller=RemoteController,
        ip=CONTROLLER_IP,
        port=CONTROLLER_PORT
    )
    
    # Add switch
    info('*** Adding switch\n')
    s1 = net.addSwitch('s1', protocols='OpenFlow13')
    
    # Add client hosts
    info('*** Adding client hosts\n')
    h1 = net.addHost('h1', ip=CLIENT_IPS['h1'])
    h2 = net.addHost('h2', ip=CLIENT_IPS['h2'])
    h3 = net.addHost('h3', ip=CLIENT_IPS['h3'])
    
    # Add server hosts
    info('*** Adding server hosts\n')
    h4 = net.addHost('h4', ip=SERVER_IPS['h4'])
    h5 = net.addHost('h5', ip=SERVER_IPS['h5'])
    h6 = net.addHost('h6', ip=SERVER_IPS['h6'])
    
    # Connect clients to switch
    info('*** Connecting clients to switch\n')
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)
    
    # Connect servers to switch
    info('*** Connecting servers to switch\n')
    net.addLink(h4, s1)
    net.addLink(h5, s1)
    net.addLink(h6, s1)
    
    return net

# ============================================================================
# HTTP Server Management
# ============================================================================

def start_http_server(host, server_ip, server_name):
    """
    Start a simple HTTP server on a host.
    
    Args:
        host: Mininet host object
        server_ip: IP address of the server
        server_name: Name identifier for the server (e.g., 'h4')
    """
    log_file = os.path.join(HTTP_LOG_DIR, f'{server_name}_http.log')
    
    # Create a simple HTML page that identifies the server
    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Server {server_name}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            text-align: center;
            padding: 50px;
            background-color: #f0f0f0;
        }}
        .container {{
            background-color: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            max-width: 600px;
            margin: 0 auto;
        }}
        h1 {{
            color: #333;
        }}
        .info {{
            color: #666;
            margin: 20px 0;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Welcome to Server {server_name}</h1>
        <div class="info">
            <p><strong>Server IP:</strong> {server_ip}</p>
            <p><strong>Server Name:</strong> {server_name}</p>
            <p><strong>Time:</strong> <span id="time"></span></p>
        </div>
        <p>This server is part of the SDN Load Balancer testbed.</p>
    </div>
    <script>
        document.getElementById('time').textContent = new Date().toLocaleString();
    </script>
</body>
</html>
"""
    
    # Create HTML file
    html_file = f'/tmp/{server_name}_index.html'
    host.cmd(f'echo \'{html_content}\' > {html_file}')
    
    # Start HTTP server in background
    # Using Python's http.server module
    cmd = f'python3 -m http.server {HTTP_PORT} > {log_file} 2>&1 &'
    host.cmd(cmd)
    
    info(f'*** Started HTTP server on {server_name} ({server_ip}:{HTTP_PORT})\n')
    info(f'*** Log file: {log_file}\n')

def start_all_http_servers(net):
    """
    Start HTTP servers on all backend hosts.
    
    Args:
        net: Mininet network object
    """
    info('*** Starting HTTP servers on backend hosts\n')
    
    # Wait a bit for network to stabilize
    time.sleep(2)
    
    # Start servers
    start_http_server(net.get('h4'), SERVER_IPS['h4'], 'h4')
    time.sleep(0.5)
    start_http_server(net.get('h5'), SERVER_IPS['h5'], 'h5')
    time.sleep(0.5)
    start_http_server(net.get('h6'), SERVER_IPS['h6'], 'h6')
    
    info('*** All HTTP servers started\n')

def stop_all_http_servers(net):
    """
    Stop all HTTP servers.
    
    Args:
        net: Mininet network object
    """
    info('*** Stopping HTTP servers\n')
    
    for server_name in ['h4', 'h5', 'h6']:
        host = net.get(server_name)
        if host:
            # Kill any Python HTTP server processes
            host.cmd('pkill -f "python.*http.server"')
            info(f'*** Stopped HTTP server on {server_name}\n')

# ============================================================================
# Network Testing Functions
# ============================================================================

def test_connectivity(net):
    """
    Test basic network connectivity.
    
    Args:
        net: Mininet network object
    """
    info('*** Testing network connectivity\n')
    
    h1 = net.get('h1')
    h4 = net.get('h4')
    
    # Test ping from client to server
    info('*** Testing ping from h1 to h4\n')
    result = h1.cmd('ping -c 3', SERVER_IPS['h4'])
    info(result)
    
    # Test ping to VIP (should work after ARP resolution)
    info('*** Testing ping from h1 to VIP (10.0.0.100)\n')
    result = h1.cmd('ping -c 3 10.0.0.100')
    info(result)

def test_load_balancing(net):
    """
    Test load balancing by making multiple requests to VIP.
    
    Args:
        net: Mininet network object
    """
    info('*** Testing load balancing\n')
    
    h1 = net.get('h1')
    vip = '10.0.0.100'
    
    info(f'*** Making 10 requests from h1 to {vip}\n')
    for i in range(10):
        result = h1.cmd(f'curl -s {vip} | grep "Server"')
        info(f'Request {i+1}: {result.strip()}\n')
        time.sleep(0.5)

def test_firewall(net):
    """
    Test firewall functionality.
    
    Args:
        net: Mininet network object
    """
    info('*** Testing firewall rules\n')
    
    h1 = net.get('h1')
    h4 = net.get('h4')
    
    # Test SSH port (should be blocked if configured)
    info('*** Testing SSH port (22) - should be blocked\n')
    result = h1.cmd('timeout 2 nc -zv', SERVER_IPS['h4'], '22 2>&1 || true')
    info(result)
    
    # Test HTTP port (should be allowed)
    info('*** Testing HTTP port (80) - should be allowed\n')
    result = h1.cmd(f'curl -s -o /dev/null -w "%{{http_code}}" {SERVER_IPS["h4"]}:80 || echo "Failed"')
    info(f'HTTP response code: {result}\n')

# ============================================================================
# Main Function
# ============================================================================

def main():
    """
    Main function to create and run the topology.
    """
    # Set logging level
    setLogLevel('info')
    
    # Create topology
    net = create_topology()
    
    try:
        # Start network
        info('*** Starting network\n')
        net.start()
        
        # Wait for controller connection
        info('*** Waiting for controller connection...\n')
        time.sleep(3)
        
        # Start HTTP servers
        start_all_http_servers(net)
        
        # Wait a bit more for everything to stabilize
        time.sleep(2)
        
        # Print network information
        info('\n' + '='*60 + '\n')
        info('*** Network Topology Created Successfully\n')
        info('='*60 + '\n')
        info('Clients:\n')
        for name, ip in CLIENT_IPS.items():
            info(f'  {name}: {ip}\n')
        info('\nServers:\n')
        for name, ip in SERVER_IPS.items():
            info(f'  {name}: {ip}\n')
        info(f'\nVirtual IP (VIP): 10.0.0.100\n')
        info('='*60 + '\n')
        
        # Run optional tests
        # Uncomment to run automatic tests
        # test_connectivity(net)
        # test_load_balancing(net)
        # test_firewall(net)
        
        # Start CLI
        info('*** Starting Mininet CLI\n')
        info('*** Use "exit" to stop the network\n')
        CLI(net)
        
    except KeyboardInterrupt:
        info('\n*** Interrupted by user\n')
    except Exception as e:
        info(f'\n*** Error: {e}\n')
        import traceback
        traceback.print_exc()
    finally:
        # Cleanup
        info('*** Stopping HTTP servers\n')
        stop_all_http_servers(net)
        
        info('*** Stopping network\n')
        net.stop()
        
        info('*** Network stopped\n')

if __name__ == '__main__':
    main()

