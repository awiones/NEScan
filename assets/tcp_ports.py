# Dictionary mapping service categories to their common TCP ports
TCP_SERVICE_PORTS = {
    'Web': {
        80,     # HTTP
        443,    # HTTPS
        8080,   # HTTP Alternate
        8443,   # HTTPS Alternate
        8000,   # HTTP Development
        8008,   # HTTP Alternative
        8081,   # HTTP Proxy
        8888,   # HTTP Alternative
        3000,   # Development Servers
        4000,   # Development Servers
        8090,   # HTTP Alternative
        9000,   # Jenkins
        9090    # HTTP Alternative
    },

    'Email': {
        25,     # SMTP
        587,    # SMTP Submission
        465,    # SMTP over SSL
        110,    # POP3
        995,    # POP3 over SSL
        143,    # IMAP
        993,    # IMAP over SSL
        994,    # IMAP over TLS
    },

    'Database': {
        1433,   # Microsoft SQL Server
        1434,   # Microsoft SQL Monitor
        3306,   # MySQL/MariaDB
        5432,   # PostgreSQL
        6379,   # Redis
        27017,  # MongoDB
        27018,  # MongoDB Shard
        27019,  # MongoDB Config
        28015,  # RethinkDB
        3050,   # Firebird
        5984,   # CouchDB
        6082,   # Varnish Cache
        9042,   # Cassandra
        7474,   # Neo4j
        8529    # ArangoDB
    },

    'RemoteAccess': {
        22,     # SSH
        23,     # Telnet
        3389,   # RDP
        5900,   # VNC
        5901,   # VNC-1
        5902,   # VNC-2
        5903,   # VNC-3
        5800,   # VNC Web
        3283,   # Net Assistant
        5988,   # WBEM HTTP
        5989    # WBEM HTTPS
    },

    'FileTransfer': {
        20,     # FTP Data
        21,     # FTP Control
        22,     # SFTP (via SSH)
        69,     # TFTP
        115,    # SFTP
        989,    # FTPS Data
        990,    # FTPS Control
        2049,   # NFS
        445,    # SMB
        139,    # NetBIOS Session
        137,    # NetBIOS Name
        138     # NetBIOS Datagram
    },

    'VersionControl': {
        9418,   # Git
        3690,   # SVN
        443,    # GitHub HTTPS
        22,     # GitHub SSH
        8443    # GitLab HTTPS
    },

    'Monitoring': {
        161,    # SNMP
        162,    # SNMP Trap
        199,    # SNMP Unix
        1098,   # RMI
        1099,   # RMI Registry
        4445,   # RMI Registry
        10050,  # Zabbix Agent
        10051,  # Zabbix Server
        9100,   # Prometheus Node
        9090    # Prometheus
    },

    'DevOps': {
        2375,   # Docker
        2376,   # Docker SSL
        2377,   # Docker Swarm
        4243,   # Docker
        6443,   # Kubernetes API
        8001,   # Kubernetes API
        10248,  # Kubernetes Health
        10249,  # Kubernetes Metrics
        10250,  # Kubernetes Kubelet
        10255,  # Kubernetes Read
        10256,  # Kubernetes Health
        30000,  # Kubernetes NodePort Start
        32767   # Kubernetes NodePort End
    },

    'WebServices': {
        8089,   # Splunk
        9997,   # Splunk Forwarder
        9998,   # Splunk Indexer
        9999,   # Splunk Search
        5601,   # Kibana
        9200,   # Elasticsearch HTTP
        9300,   # Elasticsearch Transport
        15672,  # RabbitMQ Management
        5672,   # AMQP
        6379,   # Redis
        11211   # Memcached
    },

    'Gaming': {
        25565,  # Minecraft
        25575,  # Minecraft RCON
        27015,  # Source Games
        27016,  # Source Games
        7777,   # Terraria
        19132,  # Minecraft Bedrock
        19133,  # Minecraft Bedrock IPv6
        3724,   # World of Warcraft
        6112,   # Battle.net
        6113,   # Battle.net
        6114,   # Battle.net
        4000    # GameSpy
    },

    'Security': {
        1194,   # OpenVPN
        1723,   # PPTP
        1701,   # L2TP
        500,    # ISAKMP
        4500,   # IPSec NAT
        636,    # LDAPS
        389,    # LDAP
        88,     # Kerberos
        464,    # Kerberos Change/Set
        749     # Kerberos Admin
    }
}

# High-risk TCP ports that should be monitored closely
HIGH_RISK_TCP_PORTS = {
    21,     # FTP
    22,     # SSH
    23,     # Telnet
    25,     # SMTP
    445,    # SMB
    1433,   # MSSQL
    1434,   # MSSQL Browser
    3306,   # MySQL
    3389,   # RDP
    5432,   # PostgreSQL
    27017,  # MongoDB
    11211,  # Memcached
    6379,   # Redis
    9200,   # Elasticsearch
    8080,   # Alternative HTTP
    8443,   # Alternative HTTPS
    2375,   # Docker
    10250,  # Kubernetes
    5601    # Kibana
}

# Common TCP ports that are frequently scanned
COMMON_TCP_PORTS = {
    20,     # FTP Data
    21,     # FTP Control
    22,     # SSH
    23,     # Telnet
    25,     # SMTP
    53,     # DNS
    80,     # HTTP
    110,    # POP3
    111,    # RPC
    135,    # MSRPC
    139,    # NetBIOS
    143,    # IMAP
    443,    # HTTPS
    445,    # SMB
    993,    # IMAPS
    995,    # POP3S
    1433,   # MSSQL
    1723,   # PPTP
    3306,   # MySQL
    3389,   # RDP
    5900,   # VNC
    8080,   # HTTP Proxy
    8443    # HTTPS Alt
}

# TCP Service banner patterns for identifying services
TCP_SERVICE_PATTERNS = {
    'HTTP': rb'HTTP/[0-9.]+ [0-9]+ .*|<html>.*</html>',
    'SSH': rb'SSH-[0-9.]+',
    'FTP': rb'220.*FTP|^220-.*\r\n220 .*',
    'SMTP': rb'220.*SMTP|^220-.*\r\n220 .*',
    'POP3': rb'\+OK.*POP3.*',
    'IMAP': rb'\* OK.*IMAP.*',
    'MySQL': rb'.\x00\x00\x00\x0a[1-9].*mysql|^\x4a\x00\x00\x00\x0a.*',
    'MSSQL': rb'^\x04\x01\x00.*MSSQL.*',
    'RDP': rb'^\x03\x00\x00.*\xE0.*\x00\x00\x00\x00.*$',
    'PostgreSQL': rb'.*PostgreSQL.*',
    'MongoDB': rb'.*MongoDB.*',
    'Redis': rb'-ERR.*|+PONG.*|\$\d+.*',
    'Elasticsearch': rb'.*"cluster_name".*"version".*'
}

# TCP probe payloads for service detection
TCP_PROBES = {
    'HTTP': b'GET / HTTP/1.0\r\n\r\n',
    'HTTPS': b'GET / HTTP/1.1\r\nHost: localhost\r\n\r\n',
    'SSH': b'SSH-2.0-OpenSSH_8.2p1\r\n',
    'FTP': b'USER anonymous\r\n',
    'SMTP': b'EHLO test\r\n',
    'POP3': b'CAPA\r\n',
    'IMAP': b'a001 CAPABILITY\r\n',
    'MySQL': b'\x0c\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
    'Redis': b'PING\r\n',
    'MongoDB': b'\x41\x00\x00\x00\x3a\x30\x00\x00\xff\xff\xff\xff\xd4\x07\x00\x00\x00\x00\x00\x00test.$cmd\x00\x00\x00\x00\x00\xff\xff\xff\xff\x1b\x00\x00\x00\x01ismaster\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
}

def get_service_ports(service_name: str) -> set:
    """Get TCP ports for a specific service category."""
    return TCP_SERVICE_PORTS.get(service_name, set())

def get_service_name(port: int) -> str:
    """Get service category name for a specific port."""
    for service, ports in TCP_SERVICE_PORTS.items():
        if port in ports:
            return service
    return "Unknown"

def is_high_risk_port(port: int) -> bool:
    """Check if a TCP port is considered high-risk."""
    return port in HIGH_RISK_TCP_PORTS

def get_probe_for_port(port: int) -> bytes:
    """Get the appropriate probe payload for a specific TCP port."""
    # Map common ports to their services
    port_service_map = {
        80: 'HTTP',
        443: 'HTTPS',
        22: 'SSH',
        21: 'FTP',
        25: 'SMTP',
        110: 'POP3',
        143: 'IMAP',
        3306: 'MySQL',
        6379: 'Redis',
        27017: 'MongoDB'
    }
    service = port_service_map.get(port)
    return TCP_PROBES.get(service, b'')  # Return empty bytes if no specific probe

def get_service_pattern(service: str) -> bytes:
    """Get the response pattern for identifying a specific service."""
    return TCP_SERVICE_PATTERNS.get(service, rb'.*')

def is_common_port(port: int) -> bool:
    """Check if a port is in the common ports list."""
    return port in COMMON_TCP_PORTS
