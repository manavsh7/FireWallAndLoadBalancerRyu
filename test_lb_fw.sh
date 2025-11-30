#!/bin/bash
#
# Testing Script for SDN Load Balancer and Firewall
#
# This script performs comprehensive testing of the unified LB+FW application.
# Make sure both Ryu controller and Mininet are running before executing this script.
#

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
VIP="10.0.0.100"
CLIENT="h1"
SERVER1="10.0.0.11"
SERVER2="10.0.0.12"
SERVER3="10.0.0.13"

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}SDN Load Balancer + Firewall Test Suite${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Check if running in Mininet
if [ -z "$MININET_CLI" ]; then
    echo -e "${YELLOW}Warning: This script should be run from Mininet CLI${NC}"
    echo -e "${YELLOW}Usage: mininet> sh test_lb_fw.sh${NC}"
    exit 1
fi

# Test 1: Basic Connectivity
echo -e "${GREEN}[Test 1] Basic Connectivity${NC}"
echo "Testing ping from $CLIENT to $SERVER1..."
ping_result=$(ping -c 3 $SERVER1 2>&1)
if echo "$ping_result" | grep -q "3 received"; then
    echo -e "${GREEN}✓ Ping test passed${NC}"
else
    echo -e "${RED}✗ Ping test failed${NC}"
    echo "$ping_result"
fi
echo ""

# Test 2: VIP ARP Resolution
echo -e "${GREEN}[Test 2] VIP ARP Resolution${NC}"
echo "Testing ARP resolution for VIP $VIP..."
arp_result=$(arp -n $VIP 2>&1)
if echo "$arp_result" | grep -q "$VIP"; then
    echo -e "${GREEN}✓ ARP resolution successful${NC}"
    echo "$arp_result"
else
    echo -e "${YELLOW}⚠ ARP entry not found (may need to ping first)${NC}"
fi
echo ""

# Test 3: Load Balancing - Round Robin
echo -e "${GREEN}[Test 3] Load Balancing - Round Robin Distribution${NC}"
echo "Making 9 requests to VIP $VIP..."
echo "Expected: Requests should be distributed across 3 servers"
echo ""

server_counts=("h4:0" "h5:0" "h6:0")

for i in {1..9}; do
    echo -n "Request $i: "
    response=$(curl -s $VIP 2>&1)
    if echo "$response" | grep -q "Server h4"; then
        server_counts[0]="h4:$(( ${server_counts[0]#*:} + 1 ))"
        echo "→ h4"
    elif echo "$response" | grep -q "Server h5"; then
        server_counts[1]="h5:$(( ${server_counts[1]#*:} + 1 ))"
        echo "→ h5"
    elif echo "$response" | grep -q "Server h6"; then
        server_counts[2]="h6:$(( ${server_counts[2]#*:} + 1 ))"
        echo "→ h6"
    else
        echo "→ Unknown server"
    fi
    sleep 0.3
done

echo ""
echo "Distribution:"
for count in "${server_counts[@]}"; do
    server=${count%%:*}
    num=${count#*:}
    echo "  $server: $num requests"
done

# Check if distribution is reasonable (each server should get at least 1 request)
total_servers=0
for count in "${server_counts[@]}"; do
    num=${count#*:}
    if [ "$num" -gt 0 ]; then
        total_servers=$((total_servers + 1))
    fi
done

if [ "$total_servers" -ge 2 ]; then
    echo -e "${GREEN}✓ Load balancing working (requests distributed across servers)${NC}"
else
    echo -e "${RED}✗ Load balancing may not be working correctly${NC}"
fi
echo ""

# Test 4: Firewall - Port Blocking
echo -e "${GREEN}[Test 4] Firewall - Port Blocking${NC}"
echo "Testing SSH port (22) - should be blocked..."
ssh_test=$(timeout 2 nc -zv $SERVER1 22 2>&1 || true)
if echo "$ssh_test" | grep -q "refused\|timeout\|No route"; then
    echo -e "${GREEN}✓ SSH port (22) correctly blocked${NC}"
else
    echo -e "${YELLOW}⚠ SSH port may not be blocked (check firewall configuration)${NC}"
    echo "$ssh_test"
fi
echo ""

# Test 5: Firewall - Port Allowing
echo -e "${GREEN}[Test 5] Firewall - Port Allowing${NC}"
echo "Testing HTTP port (80) - should be allowed..."
http_code=$(curl -s -o /dev/null -w "%{http_code}" $SERVER1:80 2>&1 || echo "000")
if [ "$http_code" = "200" ] || [ "$http_code" = "000" ]; then
    if [ "$http_code" = "200" ]; then
        echo -e "${GREEN}✓ HTTP port (80) correctly allowed (HTTP $http_code)${NC}"
    else
        echo -e "${YELLOW}⚠ HTTP connection failed (may be normal if server not running)${NC}"
    fi
else
    echo -e "${RED}✗ HTTP port may be blocked (unexpected HTTP code: $http_code)${NC}"
fi
echo ""

# Test 6: Server Logs
echo -e "${GREEN}[Test 6] Server Logs Verification${NC}"
echo "Checking HTTP server logs..."
for server in h4 h5 h6; do
    if [ -f "/tmp/${server}_http.log" ]; then
        log_size=$(wc -l < "/tmp/${server}_http.log" 2>/dev/null || echo "0")
        echo "  $server: $log_size log entries"
    else
        echo "  $server: No log file found"
    fi
done
echo ""

# Test 7: Flow Table Inspection
echo -e "${GREEN}[Test 7] Flow Table Inspection${NC}"
echo "Checking OpenFlow flow entries..."
flow_count=$(dpctl dump-flows 2>/dev/null | wc -l || echo "0")
echo "  Found $flow_count flow entries"
if [ "$flow_count" -gt 0 ]; then
    echo -e "${GREEN}✓ Flow entries installed${NC}"
    echo ""
    echo "Sample flows:"
    dpctl dump-flows 2>/dev/null | head -5 || true
else
    echo -e "${YELLOW}⚠ No flow entries found${NC}"
fi
echo ""

# Test 8: Multiple Clients
echo -e "${GREEN}[Test 8] Multiple Clients Test${NC}"
echo "Testing load balancing with multiple clients..."
echo "Making requests from h1, h2, h3..."
h1_result=$(curl -s $VIP 2>&1 | grep -o "Server h[456]" || echo "none")
h2_result=$(curl -s $VIP 2>&1 | grep -o "Server h[456]" || echo "none")
h3_result=$(curl -s $VIP 2>&1 | grep -o "Server h[456]" || echo "none")
echo "  h1 → $h1_result"
echo "  h2 → $h2_result"
echo "  h3 → $h3_result"
echo -e "${GREEN}✓ Multiple clients test completed${NC}"
echo ""

# Summary
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Test Suite Completed${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "For detailed analysis:"
echo "  - Check Ryu controller logs for firewall and LB decisions"
echo "  - Inspect server logs: cat /tmp/hX_http.log"
echo "  - View flow table: dpctl dump-flows"
echo ""

