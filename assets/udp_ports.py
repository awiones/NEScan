# Dictionary mapping service categories to their common UDP ports
UDP_SERVICE_PORTS = {
    'DNS': {
        53,     # Domain Name System
        5353,   # Multicast DNS (mDNS)
        5355    # LLMNR (Link-Local Multicast Name Resolution)
    },
    
    'DHCP': {
        67,     # DHCP Server / BOOTP
        68,     # DHCP Client
        69      # TFTP (Trivial File Transfer Protocol)
    },
    
    'NetBIOS': {
        137,    # NetBIOS Name Service
        138,    # NetBIOS Datagram Service
        139     # NetBIOS Session Service
    },
    
    'SMB': {
        445     # SMB over IP (Direct Host)
    },
    
    'SNMP': {
        161,    # SNMP
        162     # SNMP Trap
    },
    
    'VPN': {
        500,    # ISAKMP/IKE
        1194,   # OpenVPN
        1701,   # L2TP
        1723,   # PPTP
        4500    # IPSec NAT Traversal
    },
    
    'Gaming': {
        27015,  # Source Engine (Steam)
        27016,  # Source Engine (Steam)
        27017,  # Source Engine (Steam)
        27018,  # Source Engine (Steam)
        27019,  # Source Engine (Steam)
        27020,  # Source Engine (Steam)
        3074,   # Xbox Live
        3075,   # Xbox Live
        3478,   # PlayStation Network
        3479,   # PlayStation Network
        3480,   # PlayStation Network
        3658,   # PlayStation Network
        6672,   # Battle.net
        6881,   # Battle.net
        6882,   # Battle.net
        19132,  # Minecraft
        19133,  # Minecraft Bedrock
        25565,  # Minecraft Java
        7777,   # Terraria
        8766,   # Terraria
        28960,  # Call of Duty
        28961,  # Call of Duty
        9987,   # TeamSpeak 3
        64738   # Mumble
    },
    
    'Time': {
        123,    # NTP (Network Time Protocol)
        372     # Time Protocol
    },
    
    'Streaming': {
        1935,   # RTMP (Real-Time Messaging Protocol)
        554,    # RTSP (Real-Time Streaming Protocol)
        5004,   # RTP (Real-time Transport Protocol)
        5005,   # RTCP (Real-time Transport Control Protocol)
        6970,   # QuickTime Streaming Server
        7070,   # Real Audio
        8554,   # RTSP Alternate
        10000,  # Network Data Management Protocol
        1755,   # MMS (Microsoft Media Server)
        2326,   # RTSP Alternate
        5000    # UPnP
    },
    
    'IoT': {
        1883,   # MQTT
        1884,   # MQTT over SSL
        5683,   # CoAP (Constrained Application Protocol)
        5684,   # CoAP over DTLS
        5688,   # MQTT-SN
        47808,  # BACnet
        44818,  # EtherNet/IP
        2404,   # IEC 60870-5-104
        20000,  # DNP3
        502,    # Modbus
        789,    # Red Lion Crimson
        9600,   # OMRON FINS
        1962    # PCWorx
    },
    
    'Security': {
        500,    # ISAKMP/IKE
        4500,   # IPSec NAT Traversal
        1701,   # L2TP
        1723,   # PPTP
        1194,   # OpenVPN
        1813,   # RADIUS Authentication
        1812,   # RADIUS Accounting
        1645,   # RADIUS (Old)
        1646,   # RADIUS (Old)
        500,    # IKE
        2746,   # HKCP
        2912,   # DPCM
        4172,   # Teradici PCoIP
        8472,   # VXLAN
        4789    # VXLAN GPE
    },
    
    'Monitoring': {
        161,    # SNMP
        162,    # SNMP Traps
        199,    # SNMP Unix Multiplexer
        1098,   # RMIBrowser
        1099,   # RMI Registry
        4445,   # RMI Registry
        10050,  # Zabbix Agent
        10051,  # Zabbix Server
        8125,   # StatsD
        8649,   # Ganglia
        9273    # Prometheus Node Exporter
    },
    
    'Database': {
        1434,   # MS-SQL Browser
        27017,  # MongoDB
        27018,  # MongoDB Shard
        27019,  # MongoDB Config Server
        28015,  # RethinkDB
        28016,  # RethinkDB Admin
        11211,  # Memcached
        6379,   # Redis
        7000,   # Cassandra Internode
        7001,   # Cassandra JMX
        9042,   # Cassandra Native Protocol
        8087,   # Riak Protocol Buffer
        8098    # Riak HTTP
    },
    
    'Cloud': {
        2049,   # NFS
        2375,   # Docker
        2376,   # Docker SSL
        3260,   # iSCSI
        6443,   # Kubernetes API
        10250,  # Kubernetes Kubelet
        10255,  # Kubernetes Read-Only Kubelet
        2379,   # etcd Client
        2380,   # etcd Server
        8472    # Flannel Overlay Network
    },
    
    'Messaging': {
        5222,   # XMPP Client
        5223,   # XMPP Client SSL
        5269,   # XMPP Server
        5298,   # XMPP Link-Local
        5349,   # STUN/TURN over TLS
        3478,   # STUN/TURN
        3479,   # STUN/TURN Alt
        5060,   # SIP
        5061,   # SIP TLS
        16384,  # RTP Voice Data
        16385,  # RTP Voice Control
        4569    # IAX2 (Inter-Asterisk Exchange)
    },
    
    'FileSharing': {
        2049,   # NFS
        137,    # NetBIOS Name Service
        138,    # NetBIOS Datagram
        139,    # NetBIOS Session
        445,    # SMB Direct
        20,     # FTP Data
        21,     # FTP Control
        69,     # TFTP
        548,    # AFP (Apple Filing Protocol)
        9091,   # Transmission BitTorrent
        51413,  # BitTorrent DHT
        6881    # BitTorrent
    },
    
    'DevOps': {
        8125,   # StatsD
        8086,   # InfluxDB
        8088,   # InfluxDB RPC
        4242,   # OpenTSDB
        2003,   # Graphite
        2004,   # Graphite Pickle
        8125,   # Grafana
        9090,   # Prometheus
        9100,   # Node Exporter
        9200,   # Elasticsearch HTTP
        9300    # Elasticsearch Transport
    },
    
    'Email': {
        25,     # SMTP
        465,    # SMTP over SSL
        587,    # SMTP Submission
        110,    # POP3
        995,    # POP3 over SSL
        143,    # IMAP
        993,    # IMAP over SSL
        24,     # LMTP
        50      # RMCP
    },
    
    'WebRTC': {
        3478,   # STUN
        3479,   # STUN TLS
        5349,   # TURN TLS
        5350,   # TURN
        19302,  # Google STUN
        19303,  # Google STUN
        19304,  # Google STUN
        19305,  # Google STUN
        19306,  # Google STUN
        19307   # Google STUN
    },
    
    'ServiceDiscovery': {
        5353,   # mDNS
        5355,   # LLMNR
        1900,   # SSDP/UPnP
        3702,   # WS-Discovery
        5354,   # NAT-PMP
        5350,   # NAT-PMP Status
        1026,   # Syslog
        1027,   # Syslog
        1028    # Syslog
    },
    
    'Industrial': {
        102,    # Siemens S7
        502,    # Modbus
        20000,  # DNP3
        44818,  # EtherNet/IP
        2222,   # EtherCAT
        789,    # Red Lion
        1962,   # PCWorx
        2404,   # IEC-104
        18245,  # GE-SRTP
        1089,   # FF Annunciation
        1090,   # FF Fieldbus
        1091,   # FF System Management
        47808,  # BACnet
        4840,   # OPC UA Discovery Server
        4843    # OPC UA HTTPS
    },
    
    'Media': {
        1900,   # SSDP (UPnP)
        5004,   # RTP media data
        5005,   # RTP control protocol
        554,    # RTSP
        1755    # MMS (Microsoft Media Server)
    },
    
    'Time': {
        123,    # NTP (Network Time Protocol)
        372     # Time Protocol
    },
    
    'Logging': {
        514     # Syslog
    },
    
    'Routing': {
        520,    # RIP (Routing Information Protocol)
        521     # RIPng (RIP for IPv6)
    },
    
    'Voice': {
        5060,   # SIP
        5061,   # SIP over TLS
        16384,  # RTP Voice Data
        16385   # RTP Voice Control
    },

    'Authentication': {
        1645,   # RADIUS Authentication
        1646,   # RADIUS Accounting
        1812,   # RADIUS New Authentication
        1813    # RADIUS New Accounting
    },
    
    'FileSharing': {
        2049,   # NFS (Network File System)
        111     # RPCBind/Portmapper
    },
    
    'Monitoring': {
        161,    # SNMP
        162,    # SNMP Traps
        199     # SNMP Unix Multiplexer
    },
    
    'Printing': {
        631,    # IPP (Internet Printing Protocol)
        515     # LPD/LPR (Line Printer Daemon)
    }
}

# Consolidated list of all UDP ports
ALL_UDP_PORTS = set()
for ports in UDP_SERVICE_PORTS.values():
    ALL_UDP_PORTS.update(ports)

# High-risk UDP ports that should be monitored closely
HIGH_RISK_UDP_PORTS = {
    69,     # TFTP
    111,    # RPCBind
    161,    # SNMP
    1434,   # MS-SQL Browser
    1900,   # UPnP
    11211,  # Memcached
    27017,  # MongoDB
    2049,   # NFS
    137,    # NetBIOS
    138,    # NetBIOS
    139,    # NetBIOS
    445,    # SMB Direct
    520,    # RIP
    502,    # Modbus
    102,    # Siemens S7
    20000,  # DNP3
    44818,  # EtherNet/IP
    47808,  # BACnet
}

# Common UDP ports that are frequently scanned
COMMON_UDP_PORTS = {
    53,     # DNS
    67,     # DHCP Server
    68,     # DHCP Client
    69,     # TFTP
    123,    # NTP
    137,    # NetBIOS Name Service
    138,    # NetBIOS Datagram Service
    161,    # SNMP
    162,    # SNMP Trap
    500,    # ISAKMP/IKE
    514,    # Syslog
    520,    # RIP
    1194,   # OpenVPN
    1434,   # MS-SQL Browser
    1900,   # UPNP
    4500,   # IPSec NAT-T
    5353,   # mDNS
    11211,  # Memcached
    27015,  # Source Engine Games
    1883,   # MQTT
    5683,   # CoAP
    27015,  # Source Engine
    3074,   # Xbox Live
    3478,   # PlayStation Network
    19132,  # Minecraft
    5222,   # XMPP
    5060,   # SIP
    1935,   # RTMP
    6379,   # Redis
    8086,   # InfluxDB
    9200,   # Elasticsearch
    102,    # Siemens S7
    502,    # Modbus
    44818,  # EtherNet/IP
    47808,  # BACnet
}

# UDP Port probes and their corresponding services
UDP_PROBES = {
    53: b'\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03',  # DNS Query
    161: b'\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x28\xf3\x17\x95\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00',  # SNMP
    137: b'\x80\xf0\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01',  # NetBIOS
    1900: b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n',  # SSDP/UPnP
    5353: b'\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07_services\x04_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01'  # mDNS
}

# UDP service response patterns for identifying services
UDP_RESPONSE_PATTERNS = {
    'DNS': rb'.*\x00\x00\x01\x00\x00.*',
    'SNMP': rb'\x30[\x00-\xff]+\x02\x01\x00',
    'NTP': rb'[\x24\x1c\x00\x00]{4}',
    'NetBIOS': rb'\x80[\x00-\xff]+\x00\x00\x00',
    'SSDP': rb'HTTP/1\.1 200 OK',
    'mDNS': rb'.*_services.*_dns-sd.*_udp.*local.*'
}

def get_service_ports(service_name: str) -> set:
    """Get UDP ports for a specific service category."""
    return UDP_SERVICE_PORTS.get(service_name, set())

def get_service_name(port: int) -> str:
    """Get service category name for a specific port."""
    for service, ports in UDP_SERVICE_PORTS.items():
        if port in ports:
            return service
    return "Unknown"

def is_high_risk_port(port: int) -> bool:
    """Check if a UDP port is considered high-risk."""
    return port in HIGH_RISK_UDP_PORTS

def get_probe_for_port(port: int) -> bytes:
    """Get the appropriate probe payload for a specific UDP port."""
    return UDP_PROBES.get(port, b'\x00' * 8)  # Default to null bytes if no specific probe

def get_response_pattern(service: str) -> bytes:
    """Get the response pattern for identifying a specific service."""
    return UDP_RESPONSE_PATTERNS.get(service, rb'.*')
