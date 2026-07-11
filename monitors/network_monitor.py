"""
ClaudioSec - Network Monitor
Packet sniffing, port scan detection, suspicious traffic analysis
"""

import asyncio
import os
import time
from collections import defaultdict
from typing import Dict, List, Optional
from datetime import datetime
from loguru import logger

from core.database import insert_event, is_threat_ip

# Config
INTERFACE = os.getenv("NETWORK_INTERFACE", "eth0")
PORT_SCAN_THRESHOLD = int(os.getenv("PORT_SCAN_THRESHOLD", 10))
PORT_SCAN_TIME_WINDOW = int(os.getenv("PORT_SCAN_TIME_WINDOW", 60))

# Track port scan attempts: {src_ip: [(timestamp, dst_port), ...]}
_port_scan_tracker: Dict[str, List] = defaultdict(list)
# Track connection rates: {src_ip: [timestamps]}
_connection_tracker: Dict[str, List] = defaultdict(list)
# Track DNS requests: {src_ip: [timestamps]}
_dns_tracker: Dict[str, List] = defaultdict(list)

# Suspicious ports to flag
SUSPICIOUS_PORTS = {
    22: "SSH", 23: "Telnet", 3389: "RDP", 445: "SMB",
    1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL",
    6379: "Redis", 27017: "MongoDB", 2375: "Docker",
    4444: "Metasploit", 5555: "Android Debug Bridge",
    31337: "Elite/Backdoor", 12345: "NetBus",
}

PRIVATE_RANGES = [
    ("10.0.0.0", "10.255.255.255"),
    ("172.16.0.0", "172.31.255.255"),
    ("192.168.0.0", "192.168.255.255"),
    ("127.0.0.0", "127.255.255.255"),
]


def _is_private_ip(ip: str) -> bool:
    """Check if IP is in private range"""
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback
    except Exception:
        return False


async def _check_port_scan(src_ip: str, dst_port: int) -> bool:
    """Detect port scanning behavior"""
    now = time.time()
    tracker = _port_scan_tracker[src_ip]

    # Clean old entries
    tracker[:] = [(ts, port) for ts, port in tracker if now - ts < PORT_SCAN_TIME_WINDOW]
    tracker.append((now, dst_port))

    unique_ports = len(set(port for _, port in tracker))
    if unique_ports >= PORT_SCAN_THRESHOLD:
        ports_hit = sorted(set(port for _, port in tracker))
        await insert_event(
            event_type="port_scan",
            severity="high",
            source_module="network_monitor",
            title=f"Port Scan Detected from {src_ip}",
            description=f"Host {src_ip} scanned {unique_ports} unique ports in {PORT_SCAN_TIME_WINDOW}s. Ports: {ports_hit[:20]}",
            source_ip=src_ip,
            raw_data={"ports": ports_hit, "window_seconds": PORT_SCAN_TIME_WINDOW},
        )
        logger.warning(f"[Network] Port scan: {src_ip} → {unique_ports} ports")
        _port_scan_tracker[src_ip] = []  # Reset after alert
        return True
    return False


async def _check_threat_intel(src_ip: str, dst_ip: str, protocol: str, dst_port: int):
    """Check IPs against threat intel database"""
    for ip in [src_ip, dst_ip]:
        if ip and not _is_private_ip(ip):
            threat = await is_threat_ip(ip)
            if threat:
                await insert_event(
                    event_type="threat_ip_connection",
                    severity="critical",
                    source_module="network_monitor",
                    title=f"Connection to/from Known Threat IP: {ip}",
                    description=f"Traffic detected involving threat IP {ip}. Type: {threat.get('threat_type')}. Confidence: {threat.get('confidence_score')}%",
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    raw_data={"threat_intel": threat, "protocol": protocol, "port": dst_port},
                )
                logger.critical(f"[Network] Threat IP detected: {ip}")


async def _check_suspicious_port(src_ip: str, dst_ip: str, dst_port: int, protocol: str):
    """Flag connections to sensitive ports from external IPs"""
    if dst_port in SUSPICIOUS_PORTS and not _is_private_ip(src_ip):
        service = SUSPICIOUS_PORTS[dst_port]
        await insert_event(
            event_type="suspicious_connection",
            severity="medium",
            source_module="network_monitor",
            title=f"External {service} Connection Attempt",
            description=f"External IP {src_ip} attempted connection to {service} port {dst_port} on {dst_ip}",
            source_ip=src_ip,
            destination_ip=dst_ip,
            raw_data={"port": dst_port, "service": service, "protocol": protocol},
        )


async def _check_high_connection_rate(src_ip: str):
    """Detect connection flooding / DDoS indicators"""
    now = time.time()
    tracker = _connection_tracker[src_ip]
    tracker[:] = [ts for ts in tracker if now - ts < 60]
    tracker.append(now)

    if len(tracker) > 200:  # 200+ connections/minute
        await insert_event(
            event_type="connection_flood",
            severity="high",
            source_module="network_monitor",
            title=f"High Connection Rate from {src_ip}",
            description=f"IP {src_ip} established {len(tracker)} connections in the last 60 seconds (possible DDoS/flood)",
            source_ip=src_ip,
            raw_data={"connections_per_minute": len(tracker)},
        )
        _connection_tracker[src_ip] = []


def _packet_callback(packet):
    """Process each captured packet — runs in thread"""
    try:
        from scapy.layers.inet import IP, TCP, UDP
        from scapy.layers.dns import DNS, DNSQR

        if not packet.haslayer(IP):
            return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Schedule async tasks
        loop = asyncio.get_event_loop()

        if packet.haslayer(TCP):
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags
            protocol = "TCP"

            # SYN scan detection (SYN only, no ACK)
            if flags == 0x02:  # SYN flag
                asyncio.run_coroutine_threadsafe(
                    _check_port_scan(src_ip, dst_port), loop
                )
                asyncio.run_coroutine_threadsafe(
                    _check_suspicious_port(src_ip, dst_ip, dst_port, protocol), loop
                )
                asyncio.run_coroutine_threadsafe(
                    _check_threat_intel(src_ip, dst_ip, protocol, dst_port), loop
                )
                asyncio.run_coroutine_threadsafe(
                    _check_high_connection_rate(src_ip), loop
                )

        elif packet.haslayer(UDP):
            dst_port = packet[UDP].dport
            protocol = "UDP"

            # DNS monitoring
            if packet.haslayer(DNS) and packet[DNS].qr == 0:  # DNS query
                asyncio.run_coroutine_threadsafe(
                    _check_dns_anomaly(src_ip, packet), loop
                )

    except Exception as e:
        pass  # Silently skip malformed packets


async def _check_dns_anomaly(src_ip: str, packet):
    """Detect DNS exfiltration and suspicious queries"""
    try:
        from scapy.layers.dns import DNSQR
        if not packet.haslayer(DNSQR):
            return

        query = packet[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")

        # High-rate DNS (exfiltration indicator)
        now = time.time()
        tracker = _dns_tracker[src_ip]
        tracker[:] = [ts for ts in tracker if now - ts < 60]
        tracker.append(now)

        dns_rate_threshold = int(os.getenv("DNS_RATE_THRESHOLD", 100))
        if len(tracker) > dns_rate_threshold:
            await insert_event(
                event_type="dns_exfiltration_suspected",
                severity="high",
                source_module="network_monitor",
                title=f"High DNS Query Rate from {src_ip}",
                description=f"IP {src_ip} made {len(tracker)} DNS queries in 60s (possible data exfiltration). Last query: {query}",
                source_ip=src_ip,
                raw_data={"queries_per_minute": len(tracker), "sample_query": query},
            )
            _dns_tracker[src_ip] = []

        # Long subdomains (exfil indicator)
        parts = query.split(".")
        if parts and len(parts[0]) > 50:
            await insert_event(
                event_type="dns_exfiltration_suspected",
                severity="medium",
                source_module="network_monitor",
                title=f"Suspicious DNS Query (Possible Exfiltration)",
                description=f"Unusually long DNS subdomain from {src_ip}: {query[:100]}",
                source_ip=src_ip,
                raw_data={"query": query, "subdomain_length": len(parts[0])},
            )

    except Exception as e:
        logger.debug(f"[Network] DNS parse error: {e}")


async def start_network_monitor():
    """Start the network packet capture in a background thread"""
    try:
        from scapy.all import sniff
        import threading

        logger.info(f"[Network] Starting packet capture on {INTERFACE}")

        def sniff_thread():
            sniff(
                iface=INTERFACE,
                prn=_packet_callback,
                store=False,
                filter="ip",
            )

        thread = threading.Thread(target=sniff_thread, daemon=True)
        thread.start()
        logger.info("[Network] Packet capture active")

    except ImportError:
        logger.warning("[Network] Scapy not available — using simulation mode")
        await _simulate_network_events()
    except Exception as e:
        logger.error(f"[Network] Failed to start capture: {e}. Running in simulation mode.")
        await _simulate_network_events()


async def _simulate_network_events():
    """Simulate network events for testing without root/scapy"""
    import random
    import asyncio

    logger.info("[Network] Running in simulation mode")

    sim_events = [
        {
            "fn": insert_event,
            "kwargs": {
                "event_type": "port_scan",
                "severity": "high",
                "source_module": "network_monitor",
                "title": "Port Scan Detected from 203.0.113.42",
                "description": "Host 203.0.113.42 scanned 15 unique ports in 60s",
                "source_ip": "203.0.113.42",
                "raw_data": {"ports": [22, 23, 80, 443, 3389, 8080, 8443], "simulated": True},
            },
        },
        {
            "fn": insert_event,
            "kwargs": {
                "event_type": "suspicious_connection",
                "severity": "medium",
                "source_module": "network_monitor",
                "title": "External RDP Connection Attempt",
                "description": "External IP 198.51.100.5 attempted connection to RDP port 3389",
                "source_ip": "198.51.100.5",
                "destination_ip": "10.0.0.1",
                "raw_data": {"port": 3389, "service": "RDP", "simulated": True},
            },
        },
    ]

    while True:
        await asyncio.sleep(random.randint(15, 45))
        event = random.choice(sim_events)
        await event["fn"](**event["kwargs"])
        logger.info("[Network SIM] Simulated network event generated")