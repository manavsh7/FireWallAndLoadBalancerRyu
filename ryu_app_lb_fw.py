# Copyright (C) 2024 SDN Project - Unified Firewall and Load Balancer
# 
# This application implements a unified SDN controller that combines:
# - Stateless ACL-based Firewall
# - Round-Robin Load Balancer (with optional adaptive balancing)
# 
# OpenFlow 1.3 compatible

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import ether_types
from ryu.lib import mac
from ryu.lib import ip
import struct
import threading
import time
import random
import socket
from ryu.lib import hub

# ============================================================================
# Configuration Constants
# ============================================================================

# Virtual IP (VIP) for load balancer
VIP_IP = '10.0.0.100'
VIP_MAC = '00:00:00:00:00:01'  # Fake MAC for VIP

# Backend server IPs and their corresponding switch ports
# Note: Ports will be learned dynamically, but we'll maintain a mapping
BACKEND_SERVERS = {
    '10.0.0.11': {'mac': None, 'port': None, 'weight': 1},  # h4
    '10.0.0.12': {'mac': None, 'port': None, 'weight': 1},  # h5
    '10.0.0.13': {'mac': None, 'port': None, 'weight': 1},  # h6
}

# Firewall Configuration
# Blocked source IPs (will be denied)
BLOCKED_SRC_IPS = [
    # Add IPs to block here, e.g.:
    # '10.0.0.1',
]

# Blocked destination TCP ports (will be denied)
BLOCKED_TCP_PORTS = [
    22,  # SSH
    # Add more ports to block here
]

# Allowed destination TCP ports (if ALLOW_MODE is True, only these are allowed)
ALLOWED_TCP_PORTS = [
    80,  # HTTP
    # Add more allowed ports here
]

# Firewall mode: True = allow only listed ports, False = block listed ports
ALLOW_MODE = False  # Set to True for whitelist mode

# Default action when no rule matches
# True = allow by default, False = drop by default
DEFAULT_ALLOW = True

# Adaptive Load Balancing Configuration
ENABLE_ADAPTIVE_LB = False  # Set to True to enable adaptive load balancing
STATS_POLL_INTERVAL = 5  # Seconds between statistics polling
ADAPTIVE_THRESHOLD = 0.8  # Load threshold to trigger rebalancing (0.0-1.0)

# Health Check Configuration
ENABLE_HEALTH_CHECK = True # Set to True to enable health checking
HEALTH_CHECK_INTERVAL = 5 # Seconds between health checks
HEALTH_CHECK_TIMEOUT = 1 # Seconds for health check connection timeout
FAILURE_THRESHOLD = 3 # Consecutive failures before marking server DOWN
SUCCESS_THRESHOLD = 2 # Consecutive successes before marking server UP
HEALTH_CHECK_PORT = 80 # TCP port to check on backend servers (e.g., HTTP)

# ============================================================================
# Main Application Class
# ============================================================================

class UnifiedLBFW(app_manager.RyuApp):
    """
    Unified Load Balancer and Firewall SDN Controller Application.
    
    This application provides:
    1. Stateless ACL-based firewall functionality
    2. Round-robin load balancing for a Virtual IP (VIP)
    3. Optional adaptive load balancing based on traffic statistics
    """
    
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(UnifiedLBFW, self).__init__(*args, **kwargs)
        
        # MAC address to port mapping for L2 learning
        self.mac_to_port = {}
        
        # IP to MAC mapping (learned from ARP)
        self.ip_to_mac = {}
        
        # Round-robin counter for load balancing
        self.lb_counter = 0
        
        # Backend server list for round-robin
        self.backend_list = list(BACKEND_SERVERS.keys())
        
        # Statistics for adaptive load balancing
        self.port_stats = {}  # {dpid: {port: {tx_bytes, rx_bytes, ...}}}
        self.flow_stats = {}  # {dpid: {flow: {packet_count, byte_count, ...}}}
        self.backend_load = {}  # {backend_ip: load_metric} - normalized load (0.0-1.0)
        self.backend_weights = {}  # {backend_ip: weight} - selection weights
        self.datapaths = {}  # {dpid: datapath} - track connected switches
        self.waiters = {}  # For statistics requests
        
        # Initialize backend weights (equal weights initially)
        for backend_ip in self.backend_list:
            self.backend_weights[backend_ip] = 1.0
            self.backend_load[backend_ip] = 0.0
        
        # Health check status
        self.backend_health = {ip: 'UP' for ip in self.backend_list}
        self.backend_failure_count = {ip: 0 for ip in self.backend_list}
        self.backend_success_count = {ip: 0 for ip in self.backend_list}

        # Lock for thread-safe operations
        self.lock = threading.Lock()
        
        # Start adaptive polling thread if enabled
        if ENABLE_ADAPTIVE_LB:
            self.logger.info("Adaptive load balancing enabled")
            self._start_adaptive_polling()

        # Start health checking thread if enabled
        if ENABLE_HEALTH_CHECK:
            self.logger.info("Health checking enabled")
            self._start_health_checking()

    # ========================================================================
    # OpenFlow Event Handlers
    # ========================================================================

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Handle switch features event - called when switch connects.
        Install table-miss flow entry to send unknown packets to controller.
        """
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id

        self.logger.info("Switch connected: dpid=%016x", dpid)
        
        # Store datapath for statistics polling
        self.datapaths[dpid] = datapath
        
        # Install table-miss flow entry
        # This sends all unmatched packets to the controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=0, match=match,
                               instructions=inst)
        datapath.send_msg(mod)
        
        # Initialize statistics tracking
        self.port_stats[dpid] = {}
        self.flow_stats[dpid] = {}
        self.waiters.setdefault(dpid, {})
        
        self.logger.info("Table-miss flow entry installed for dpid=%016x", dpid)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """
        Main packet processing handler.
        Processes incoming packets and applies firewall rules and load balancing.
        """
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        dpid = datapath.id

        # Parse the packet
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        
        if not eth:
            return

        # Ignore LLDP packets (used for topology discovery)
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        # Update MAC-to-port mapping for L2 learning
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port

        # Handle ARP packets
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self._handle_arp(datapath, in_port, pkt, msg)
            return

        # Handle IP packets (IPv4)
        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            if ip_pkt:
                # Extract destination port for firewall checking
                dst_port = self._get_dst_port(pkt)
                
                # Apply firewall rules first
                if not self._check_firewall_rules(ip_pkt, in_port, dst_port):
                    self.logger.info("Firewall: Blocked packet from %s to %s:%s",
                                   ip_pkt.src, ip_pkt.dst, dst_port or "N/A")
                    return  # Drop packet
                
                # Handle load balancing for VIP
                if ip_pkt.dst == VIP_IP:
                    self._handle_vip_traffic(datapath, in_port, pkt, msg, eth, ip_pkt)
                else:
                    # Regular forwarding - check if this is return traffic from backend
                    self._handle_regular_traffic(datapath, in_port, pkt, msg, eth, ip_pkt)
            return

        # For other packet types, use simple L2 learning
        self._handle_l2_forwarding(datapath, in_port, pkt, msg, eth)

    # ========================================================================
    # ARP Handling
    # ========================================================================

    def _handle_arp(self, datapath, in_port, pkt, msg):
        """
        Handle ARP packets - respond to ARP requests for VIP.
        """
        arp_pkt = pkt.get_protocol(arp.arp)
        if not arp_pkt:
            return

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Learn IP-to-MAC mapping
        self.ip_to_mac[arp_pkt.src_ip] = arp_pkt.src_mac

        # Check if this is an ARP request for our VIP
        if arp_pkt.opcode == arp.ARP_REQUEST and arp_pkt.dst_ip == VIP_IP:
            self.logger.info("ARP request for VIP %s from %s", VIP_IP, arp_pkt.src_ip)
            
            # Build ARP reply
            arp_reply = packet.Packet()
            arp_reply.add_protocol(ethernet.ethernet(
                ethertype=ether_types.ETH_TYPE_ARP,
                dst=arp_pkt.src_mac,
                src=VIP_MAC))
            arp_reply.add_protocol(arp.arp(
                opcode=arp.ARP_REPLY,
                src_mac=VIP_MAC,
                src_ip=VIP_IP,
                dst_mac=arp_pkt.src_mac,
                dst_ip=arp_pkt.src_ip))
            arp_reply.serialize()

            # Send ARP reply
            actions = [parser.OFPActionOutput(in_port)]
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=ofproto.OFP_NO_BUFFER,
                in_port=ofproto.OFPP_CONTROLLER,
                actions=actions,
                data=arp_reply.data)
            datapath.send_msg(out)
            
            self.logger.info("Sent ARP reply: VIP %s -> %s", VIP_IP, arp_pkt.src_ip)

    # ========================================================================
    # Firewall Logic
    # ========================================================================

    def _check_firewall_rules(self, ip_pkt, in_port, dst_port=None):
        """
        Check if packet should be allowed based on firewall rules.
        Returns True if allowed, False if blocked.
        
        Args:
            ip_pkt: IPv4 packet object
            in_port: Input port number
            dst_port: Destination port (TCP/UDP) if available
        """
        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst
        protocol = ip_pkt.proto

        # Check blocked source IPs
        if src_ip in BLOCKED_SRC_IPS:
            self.logger.info("Firewall: Blocked source IP %s", src_ip)
            return False

        # Check TCP/UDP port rules if port is available
        if dst_port is not None:
            if not self._check_port_firewall(dst_port, protocol):
                self.logger.info("Firewall: Blocked port %s (protocol %s)", dst_port, protocol)
                return False

        # If we reach here and DEFAULT_ALLOW is False, deny
        if not DEFAULT_ALLOW:
            return False

        return True

    def _get_dst_port(self, pkt):
        """Extract destination port from packet (TCP or UDP)."""
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        if tcp_pkt:
            return tcp_pkt.dst_port
        udp_pkt = pkt.get_protocol(udp.udp)
        if udp_pkt:
            return udp_pkt.dst_port
        return None

    def _check_port_firewall(self, dst_port, protocol):
        """
        Check if destination port is allowed/blocked.
        Returns True if allowed, False if blocked.
        """
        if protocol != ipv4.inet.IPPROTO_TCP and protocol != ipv4.inet.IPPROTO_UDP:
            return DEFAULT_ALLOW  # Allow non-TCP/UDP if default is allow

        if ALLOW_MODE:
            # Whitelist mode: only allow listed ports
            return dst_port in ALLOWED_TCP_PORTS
        else:
            # Blacklist mode: block listed ports
            return dst_port not in BLOCKED_TCP_PORTS

    # ========================================================================
    # Load Balancer Logic
    # ========================================================================

    def _handle_vip_traffic(self, datapath, in_port, pkt, msg, eth, ip_pkt):
        """
        Handle traffic destined for the Virtual IP (VIP).
        Selects a backend server using round-robin and rewrites the packet.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Get list of currently UP backend servers
        with self.lock:
            up_backends = [ip for ip, status in self.backend_health.items() if status == 'UP']

        if not up_backends:
            self.logger.warning("No UP backend servers available to handle VIP traffic. Dropping packet.")
            return # Drop packet

        selected_backend = None
        if ENABLE_ADAPTIVE_LB:
            # Use weighted selection based on current load (only from UP servers)
            selected_backend = self._select_backend_adaptive()
        else:
            # Use simple round-robin from UP servers
            with self.lock:
                # Ensure the counter wraps around correctly for only UP backends
                self.lb_counter = (self.lb_counter + 1) % len(up_backends)
                selected_backend = up_backends[self.lb_counter]

        if selected_backend is None:
            self.logger.warning("Load balancer failed to select a backend (possibly no healthy servers). Dropping packet.")
            return # Should be handled by up_backends check, but as a safeguard
            
        # Get backend server info
        backend_info = BACKEND_SERVERS[selected_backend]
        backend_mac = backend_info['mac']
        backend_port = backend_info['port']

        # If we don't know the backend MAC/port yet, learn it
        if not backend_mac or not backend_port:
            # Try to get from learned mappings
            if selected_backend in self.ip_to_mac:
                backend_mac = self.ip_to_mac[selected_backend]
            else:
                self.logger.warning("Backend %s MAC unknown, flooding ARP", selected_backend)
                # Send ARP request (simplified - in real scenario, we'd handle this better)
                return

            # Find port for backend MAC
            dpid = datapath.id
            if backend_mac in self.mac_to_port.get(dpid, {}):
                backend_port = self.mac_to_port[dpid][backend_mac]
            else:
                self.logger.warning("Backend %s port unknown, cannot forward", selected_backend)
                return

            # Update backend info
            backend_info['mac'] = backend_mac
            backend_info['port'] = backend_port

        self.logger.info("LB: Routing %s -> %s (backend: %s)",
                        ip_pkt.src, VIP_IP, selected_backend)

        # Port-based firewall rules are already checked in main handler
        # No need to check again here

        # Rewrite packet: change destination IP and MAC
        # Create new packet with modified headers
        new_pkt = packet.Packet()
        
        # New Ethernet header
        new_eth = ethernet.ethernet(
            src=eth.src,  # Keep original source MAC
            dst=backend_mac,  # Change to backend MAC
            ethertype=eth.ethertype)
        new_pkt.add_protocol(new_eth)
        
        # New IP header
        new_ip = ipv4.ipv4(
            src=ip_pkt.src,  # Keep original source IP
            dst=selected_backend,  # Change to backend IP
            proto=ip_pkt.proto,
            ttl=ip_pkt.ttl - 1)
        new_pkt.add_protocol(new_ip)
        
        # Copy transport layer (TCP/UDP)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        if tcp_pkt:
            new_pkt.add_protocol(tcp_pkt)
        udp_pkt = pkt.get_protocol(udp.udp)
        if udp_pkt:
            new_pkt.add_protocol(udp_pkt)
        
        new_pkt.serialize()

        # Install flow entry for this connection
        # Match: src_ip, dst_ip=VIP, protocol, ports
        match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=ip_pkt.src,
            ipv4_dst=VIP_IP,
            ip_proto=ip_pkt.proto)
        
        # Add port matching if TCP/UDP
        if tcp_pkt:
            match = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_src=ip_pkt.src,
                ipv4_dst=VIP_IP,
                ip_proto=ip_pkt.proto,
                tcp_src=tcp_pkt.src_port,
                tcp_dst=tcp_pkt.dst_port)
        elif udp_pkt:
            match = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_src=ip_pkt.src,
                ipv4_dst=VIP_IP,
                ip_proto=ip_pkt.proto,
                udp_src=udp_pkt.src_port,
                udp_dst=udp_pkt.dst_port)

        # Actions: rewrite destination IP and MAC, output to backend port
        actions = [
            parser.OFPActionSetField(ipv4_dst=selected_backend),
            parser.OFPActionSetField(eth_dst=backend_mac),
            parser.OFPActionOutput(backend_port)
        ]

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=100,  # Higher priority than table-miss
            match=match,
            instructions=inst,
            buffer_id=msg.buffer_id,
            idle_timeout=60,  # Flow expires after 60s of inactivity
            hard_timeout=300)  # Flow expires after 5 minutes
        
        if msg.buffer_id != ofproto.OFP_NO_BUFFER:
            datapath.send_msg(mod)
        else:
            # Send packet out if no buffer
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=ofproto.OFP_NO_BUFFER,
                in_port=in_port,
                actions=actions,
                data=new_pkt.data)
            datapath.send_msg(out)

    def _handle_regular_traffic(self, datapath, in_port, pkt, msg, eth, ip_pkt):
        """
        Handle regular (non-VIP) traffic.
        This includes return traffic from backend servers to clients.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id

        # Check if this is return traffic from a backend server
        # (source is one of our backends, going to a client)
        if ip_pkt.src in BACKEND_SERVERS:
            # This is return traffic - rewrite source IP/MAC back to VIP
            self._handle_return_traffic(datapath, in_port, pkt, msg, eth, ip_pkt)
            return

        # Regular L2 forwarding
        self._handle_l2_forwarding(datapath, in_port, pkt, msg, eth)

    def _handle_return_traffic(self, datapath, in_port, pkt, msg, eth, ip_pkt):
        """
        Handle return traffic from backend servers to clients.
        Rewrites source IP/MAC back to VIP.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Find the client MAC (destination of return traffic)
        client_ip = ip_pkt.dst
        client_mac = self.ip_to_mac.get(client_ip)
        
        if not client_mac:
            # Try to get from MAC-to-port mapping (reverse lookup)
            dpid = datapath.id
            # We need to find which MAC corresponds to this IP
            # For now, we'll use L2 learning
            self.logger.warning("Client MAC unknown for %s, using L2 learning", client_ip)
            self._handle_l2_forwarding(datapath, in_port, pkt, msg, eth)
            return

        # Rewrite packet: change source IP and MAC back to VIP
        new_pkt = packet.Packet()
        
        # New Ethernet header
        new_eth = ethernet.ethernet(
            src=VIP_MAC,  # Change to VIP MAC
            dst=client_mac,  # Client MAC
            ethertype=eth.ethertype)
        new_pkt.add_protocol(new_eth)
        
        # New IP header
        new_ip = ipv4.ipv4(
            src=VIP_IP,  # Change to VIP IP
            dst=client_ip,  # Keep client IP
            proto=ip_pkt.proto,
            ttl=ip_pkt.ttl - 1)
        new_pkt.add_protocol(new_ip)
        
        # Copy transport layer
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        if tcp_pkt:
            new_pkt.add_protocol(tcp_pkt)
        udp_pkt = pkt.get_protocol(udp.udp)
        if udp_pkt:
            new_pkt.add_protocol(udp_pkt)
        
        new_pkt.serialize()

        # Install reverse flow entry
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)
        
        if tcp_pkt:
            match = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_src=ip_pkt.src,  # Backend IP
                ipv4_dst=client_ip,
                ip_proto=ip_pkt.proto,
                tcp_src=tcp_pkt.src_port,
                tcp_dst=tcp_pkt.dst_port)
        elif udp_pkt:
            match = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_src=ip_pkt.src,
                ipv4_dst=client_ip,
                ip_proto=ip_pkt.proto,
                udp_src=udp_pkt.src_port,
                udp_dst=udp_pkt.dst_port)
        else:
            match = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_src=ip_pkt.src,
                ipv4_dst=client_ip,
                ip_proto=ip_pkt.proto)

        # Find client port
        dpid = datapath.id
        client_port = self.mac_to_port.get(dpid, {}).get(client_mac)
        if not client_port:
            self.logger.warning("Client port unknown, flooding")
            client_port = ofproto.OFPP_FLOOD

        # Actions: rewrite source IP and MAC to VIP, output to client
        actions = [
            parser.OFPActionSetField(ipv4_src=VIP_IP),
            parser.OFPActionSetField(eth_src=VIP_MAC),
            parser.OFPActionOutput(client_port)
        ]

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=100,
            match=match,
            instructions=inst,
            buffer_id=msg.buffer_id,
            idle_timeout=60,
            hard_timeout=300)
        
        if msg.buffer_id != ofproto.OFP_NO_BUFFER:
            datapath.send_msg(mod)
        else:
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=ofproto.OFP_NO_BUFFER,
                in_port=in_port,
                actions=actions,
                data=new_pkt.data)
            datapath.send_msg(out)

    # ========================================================================
    # L2 Learning Switch Logic
    # ========================================================================

    def _handle_l2_forwarding(self, datapath, in_port, pkt, msg, eth):
        """
        Simple L2 learning switch forwarding.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id

        dst = eth.dst
        src = eth.src

        # Learn MAC address
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        # Determine output port
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        # Install flow entry
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            actions = [parser.OFPActionOutput(out_port)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=10,
                match=match,
                instructions=inst,
                buffer_id=msg.buffer_id)
            
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                datapath.send_msg(mod)
                return

        # Send packet out
        actions = [parser.OFPActionOutput(out_port)]
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data)
        datapath.send_msg(out)

    # ========================================================================
    # Adaptive Load Balancing (Optional)
    # ========================================================================

    def _start_adaptive_polling(self):
        """Start background thread for adaptive load balancing statistics polling."""
        def poll_loop():
            while True:
                time.sleep(STATS_POLL_INTERVAL)
                self._poll_statistics()
                self._adjust_weights()
        
        thread = threading.Thread(target=poll_loop, daemon=True)
        thread.start()
        self.logger.info("Started adaptive load balancing polling thread")

    def _poll_statistics(self):
        """
        Poll OpenFlow statistics from switches.
        Collects port statistics and flow statistics to calculate backend load.
        """
        if not self.datapaths:
            return
        
        self.logger.debug("Polling statistics for adaptive load balancing")
        
        # Poll statistics from all connected switches
        for dpid, datapath in self.datapaths.items():
            try:
                # Request port statistics
                self._request_port_stats(datapath)
                
                # Request flow statistics (for flows going to backends)
                self._request_flow_stats(datapath)
            except Exception as e:
                self.logger.error("Error polling statistics for dpid=%016x: %s", dpid, e)

    def _request_port_stats(self, datapath):
        """Request port statistics from switch."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    def _request_flow_stats(self, datapath):
        """Request flow statistics from switch."""
        parser = datapath.ofproto_parser
        
        # Request all flow statistics
        match = parser.OFPMatch()
        req = parser.OFPFlowStatsRequest(datapath, 0, match)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        """
        Handle port statistics reply.
        Updates port statistics and calculates backend load.
        """
        msg = ev.msg
        dpid = msg.datapath.id
        body = msg.body
        
        # Update port statistics
        self.port_stats[dpid] = {}
        for stat in body:
            port_no = stat.port_no
            self.port_stats[dpid][port_no] = {
                'rx_packets': stat.rx_packets,
                'tx_packets': stat.tx_packets,
                'rx_bytes': stat.rx_bytes,
                'tx_bytes': stat.tx_bytes,
                'rx_dropped': stat.rx_dropped,
                'tx_dropped': stat.tx_dropped,
                'rx_errors': stat.rx_errors,
                'tx_errors': stat.tx_errors,
            }
        
        # Calculate backend load based on port statistics
        self._calculate_backend_load(dpid)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        """
        Handle flow statistics reply.
        Updates flow statistics for load calculation.
        """
        msg = ev.msg
        dpid = msg.datapath.id
        body = msg.body
        
        # Update flow statistics
        self.flow_stats[dpid] = {}
        for stat in body:
            # Store flow statistics keyed by match fields
            match_str = str(stat.match)
            self.flow_stats[dpid][match_str] = {
                'packet_count': stat.packet_count,
                'byte_count': stat.byte_count,
                'duration_sec': stat.duration_sec,
                'duration_nsec': stat.duration_nsec,
            }

    def _calculate_backend_load(self, dpid):
        """
        Calculate load metrics for each backend server.
        Load is based on traffic volume (bytes) on backend ports.
        """
        if dpid not in self.port_stats:
            return
        
        # Map backend IPs to their switch ports
        backend_ports = {}
        for backend_ip, backend_info in BACKEND_SERVERS.items():
            if backend_info['port'] is not None:
                backend_ports[backend_ip] = backend_info['port']
        
        if not backend_ports:
            return
        
        # Calculate total traffic across all backends
        total_traffic = 0
        backend_traffic = {}
        
        for backend_ip, port_no in backend_ports.items():
            if port_no in self.port_stats[dpid]:
                port_stat = self.port_stats[dpid][port_no]
                # Use tx_bytes as indicator of server load (outgoing = server response)
                # Also consider rx_bytes (incoming = client requests)
                traffic = port_stat['tx_bytes'] + port_stat['rx_bytes']
                backend_traffic[backend_ip] = traffic
                total_traffic += traffic
        
        # Normalize load (0.0 = no load, 1.0 = maximum load)
        if total_traffic > 0:
            with self.lock:
                for backend_ip in self.backend_list:
                    if backend_ip in backend_traffic:
                        # Normalize: load = backend_traffic / total_traffic
                        # But we want inverse for weights (less load = higher weight)
                        traffic = backend_traffic[backend_ip]
                        self.backend_load[backend_ip] = traffic / total_traffic
                    else:
                        self.backend_load[backend_ip] = 0.0
        else:
            # No traffic yet, equal load
            with self.lock:
                for backend_ip in self.backend_list:
                    self.backend_load[backend_ip] = 0.0

    def _adjust_weights(self):
        """
        Adjust backend server weights based on traffic statistics.
        Weights are inversely proportional to load (less load = higher weight).
        """
        if not ENABLE_ADAPTIVE_LB:
            return
        
        with self.lock:
            total_weight = 0.0
            
            # Calculate new weights based on load
            # Weight = 1.0 / (load + epsilon) to avoid division by zero
            # Higher load = lower weight
            epsilon = 0.1  # Small value to prevent division by zero
            
            for backend_ip in self.backend_list:
                load = self.backend_load.get(backend_ip, 0.0)
                # Inverse relationship: less load = higher weight
                # Add 1.0 to ensure minimum weight
                weight = 1.0 / (load + epsilon) + 1.0
                self.backend_weights[backend_ip] = weight
                total_weight += weight
            
            # Normalize weights to sum to number of backends
            # This maintains fair distribution when all servers have equal load
            if total_weight > 0:
                normalization_factor = len(self.backend_list) / total_weight
                for backend_ip in self.backend_list:
                    self.backend_weights[backend_ip] *= normalization_factor
            
            # Log weight changes
            weight_str = ", ".join([f"{ip}: {self.backend_weights[ip]:.2f}" 
                                   for ip in self.backend_list])
            self.logger.info("Adjusted weights: %s", weight_str)

    def _select_backend_adaptive(self):
        """
        Select backend server using weighted random selection.
        Servers with lower load (higher weight) are more likely to be selected.
        Only selects from currently UP servers.
        """
        with self.lock:
            # Filter out DOWN servers
            available_backends = [ip for ip in self.backend_list if self.backend_health[ip] == 'UP']
            
            if not available_backends:
                self.logger.warning("No UP backend servers available for adaptive LB.")
                return None

            # Get current weights for available backends
            weights = [self.backend_weights.get(ip, 1.0) for ip in available_backends]
            
            # Weighted random selection
            # random.choices returns a list, we take the first element
            selected = random.choices(available_backends, weights=weights, k=1)[0]
            
            # Log selection for debugging
            load = self.backend_load.get(selected, 0.0)
            weight = self.backend_weights.get(selected, 1.0)
            self.logger.debug("Adaptive LB: Selected %s (load=%.2f, weight=%.2f)", 
                            selected, load, weight)
            
            return selected

    # ========================================================================
    # Health Checking (Optional)
    # ========================================================================

    def _start_health_checking(self):
        """Start a greenlet for periodic health checking of backend servers."""
        # Use ryu.lib.hub to spawn a greenlet (cooperative thread)
        # This is preferred over threading.Thread in Ryu for better integration
        hub.spawn(self._health_check_loop)
        self.logger.info("Started backend health checking loop")

    def _health_check_loop(self):
        """
        Main loop for health checking.
        Periodically checks the health of each backend server.
        """
        while True:
            for backend_ip in list(self.backend_list): # Iterate over a copy
                self._perform_health_check(backend_ip)
            hub.sleep(HEALTH_CHECK_INTERVAL)

    def _perform_health_check(self, backend_ip):
        """
        Performs a single health check on a given backend server.
        Updates its health status based on TCP connection attempt.
        """
        is_healthy = False
        try:
            # Attempt to establish a TCP connection to the HEALTH_CHECK_PORT
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(HEALTH_CHECK_TIMEOUT)
            sock.connect((backend_ip, HEALTH_CHECK_PORT))
            sock.close()
            is_healthy = True
        except socket.timeout:
            self.logger.debug("Health check: %s:%s timed out", backend_ip, HEALTH_CHECK_PORT)
        except ConnectionRefusedError:
            self.logger.debug("Health check: %s:%s connection refused", backend_ip, HEALTH_CHECK_PORT)
        except Exception as e:
            self.logger.debug("Health check: %s:%s error - %s", backend_ip, HEALTH_CHECK_PORT, e)

        with self.lock:
            current_status = self.backend_health[backend_ip]

            if is_healthy:
                self.backend_failure_count[backend_ip] = 0
                self.backend_success_count[backend_ip] += 1
                
                if current_status == 'DOWN' and self.backend_success_count[backend_ip] >= SUCCESS_THRESHOLD:
                    self.backend_health[backend_ip] = 'UP'
                    self.backend_success_count[backend_ip] = 0
                    self.logger.info("Backend %s:%s is UP again.", backend_ip, HEALTH_CHECK_PORT)
                elif current_status == 'UP':
                    # If already UP, just reset success count to avoid overflow
                    # or keep it capped at SUCCESS_THRESHOLD
                    self.backend_success_count[backend_ip] = SUCCESS_THRESHOLD # Cap it
            else: # Not healthy
                self.backend_success_count[backend_ip] = 0
                self.backend_failure_count[backend_ip] += 1
                
                if current_status == 'UP' and self.backend_failure_count[backend_ip] >= FAILURE_THRESHOLD:
                    self.backend_health[backend_ip] = 'DOWN'
                    self.backend_failure_count[backend_ip] = 0
                    self.logger.warning("Backend %s:%s is DOWN.", backend_ip, HEALTH_CHECK_PORT)
                elif current_status == 'DOWN':
                    # If already DOWN, just reset failure count to avoid overflow
                    # or keep it capped at FAILURE_THRESHOLD
                    self.backend_failure_count[backend_ip] = FAILURE_THRESHOLD # Cap it


