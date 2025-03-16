# =============================================================================
# Author      : awiones
# Created     : 2025-02-18
# License     : GNU General Public License v3.0
# Description : This code was developed by awiones. It is a comprehensive network
#               scanning tool designed to enumerate hosts, scan for open TCP and UDP
#               ports, retrieve DNS and HTTP information, and generate detailed reports
#               on network security and potential vulnerabilities.
# =============================================================================


import socket
import threading
import logging
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass
import time
from tqdm import tqdm
import re 
from colorama import Fore, Style, init 
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue
import asyncio
from functools import lru_cache
import os  

# Initialize colorama
init(autoreset=True)

@dataclass
class RTSPCredential:
    username: str
    password: str

@dataclass
class RTSPPath:
    path: str
    description: str
    priority: int  # 1: Common, 2: Standard, 3: Rare

# Common RTSP credentials
DEFAULT_CREDENTIALS = [
    # Basic admin combinations
    RTSPCredential("admin", "admin"),
    RTSPCredential("admin", ""),
    RTSPCredential("admin", "password"),
    RTSPCredential("admin", "admin123"),
    RTSPCredential("admin", "pass123"),
    RTSPCredential("admin", "12345"),
    RTSPCredential("admin", "123456"),
    
    # Common word-based passwords
    RTSPCredential("admin", "welcome"),
    RTSPCredential("admin", "welcome123"),
    RTSPCredential("admin", "letmein"),
    RTSPCredential("admin", "letmein123"),
    RTSPCredential("admin", "qwerty"),
    RTSPCredential("admin", "abc123"),
    RTSPCredential("admin", "monkey"),
    RTSPCredential("admin", "dragon"),
    RTSPCredential("admin", "master"),
    RTSPCredential("admin", "login"),
    RTSPCredential("admin", "admin1234"),
    RTSPCredential("admin", "changeme"),
    RTSPCredential("admin", "password1"),
    RTSPCredential("admin", "football"),
    RTSPCredential("admin", "baseball"),
    RTSPCredential("admin", "secret"),
    RTSPCredential("admin", "secret123"),
    
    # Common pattern variations
    RTSPCredential("admin", "qwerty123"),
    RTSPCredential("admin", "Password1"),
    RTSPCredential("admin", "Password123"),
    RTSPCredential("admin", "Welcome1"),
    RTSPCredential("admin", "Welcome123"),
    RTSPCredential("admin", "abc@123"),
    RTSPCredential("admin", "master123"),
    RTSPCredential("admin", "login123"),
    
    # Special word patterns
    RTSPCredential("admin", "adminadmin"),
    RTSPCredential("admin", "administrator"),
    RTSPCredential("admin", "superadmin"),
    RTSPCredential("admin", "defaultpass"),
    RTSPCredential("admin", "adminpass"),
    RTSPCredential("admin", "pass@word1"),
    RTSPCredential("admin", "p@ssw0rd"),
    RTSPCredential("admin", "passw0rd"),
    
    # Common phrases
    RTSPCredential("admin", "letmein!"),
    RTSPCredential("admin", "trustno1"),
    RTSPCredential("admin", "iloveyou"),
    RTSPCredential("admin", "welcome!"),
    RTSPCredential("admin", "changeme!"),
    
    # Add these patterns for root user too
    RTSPCredential("root", "welcome"),
    RTSPCredential("root", "welcome123"),
    RTSPCredential("root", "letmein"),
    RTSPCredential("root", "changeme"),
    RTSPCredential("root", "password1"),
    RTSPCredential("root", "Password123"),
    RTSPCredential("root", "rootpass"),
    RTSPCredential("root", "root1234"),
    
    # Common pattern passwords
    RTSPCredential("admin", "Admin123"),
    RTSPCredential("admin", "Admin@123"),
    RTSPCredential("admin", "Password123"),
    RTSPCredential("admin", "Pass@123"),
    RTSPCredential("admin", "P@ssw0rd"),
    RTSPCredential("admin", "adm1n"),
    RTSPCredential("admin", "4dm1n"),
    
    # Special character variations
    RTSPCredential("admin", "admin!@#"),
    RTSPCredential("admin", "admin@123"),
    RTSPCredential("admin", "admin#123"),
    RTSPCredential("admin", "admin$123"),
    RTSPCredential("admin", "admin!123"),
    
    # Root user variations
    RTSPCredential("root", "root"),
    RTSPCredential("root", "root123"),
    RTSPCredential("root", "toor"),
    RTSPCredential("root", "Root@123"),
    RTSPCredential("root", "!@#$%^"),
    
    # Year-based passwords
    *[RTSPCredential("admin", f"admin{year}") for year in range(2020, 2025)],
    *[RTSPCredential("root", f"root{year}") for year in range(2020, 2025)],
    
    # Common user variations
    RTSPCredential("user", "user"),
    RTSPCredential("user", "user123"),
    RTSPCredential("user", "User@123"),
    RTSPCredential("guest", "guest"),
    RTSPCredential("guest", "guest123"),
    RTSPCredential("guest", "Guest@123"),
    
    # Camera brand defaults
    RTSPCredential("hikvision", "hikvision"),
    RTSPCredential("hikvision", "hik12345"),
    RTSPCredential("hikvision", "Hik@12345"),
    RTSPCredential("dahua", "dahua"),
    RTSPCredential("dahua", "dh123456"),
    RTSPCredential("dahua", "Dahua@123"),
    RTSPCredential("axis", "axis"),
    RTSPCredential("axis", "axis123"),
    RTSPCredential("axis", "Axis@123"),  # Fixed credential with both username and password
    RTSPCredential("samsung", "samsung"),
    RTSPCredential("samsung", "samsung123"),
    RTSPCredential("samsung", "Samsung@123"),
    RTSPCredential("sony", "sony"),
    RTSPCredential("sony", "sony123"),
    RTSPCredential("sony", "Sony@123"),
    
    # System default passwords
    RTSPCredential("system", "system"),
    RTSPCredential("supervisor", "supervisor"),
    RTSPCredential("service", "service"),
    RTSPCredential("support", "support"),
    RTSPCredential("tech", "tech"),
    
    # Common number patterns
    *[RTSPCredential("admin", str(i)) for i in range(1000, 10000)],  # 4 digit pins
    *[RTSPCredential("root", str(i)) for i in range(1000, 10000)],   # 4 digit pins
    
    # Special number combinations
    RTSPCredential("admin", "11111111"),
    RTSPCredential("admin", "12121212"),
    RTSPCredential("admin", "123123123"),
    RTSPCredential("admin", "88888888"),
    RTSPCredential("admin", "1234qwer"),
    RTSPCredential("admin", "qwer1234"),
    
    # Manufacturer defaults
    RTSPCredential("admin1", "admin1"),
    RTSPCredential("admin2", "admin2"),
    RTSPCredential("administrator", "administrator"),
    RTSPCredential("Administrator", "Administrator"),
    RTSPCredential("666666", "666666"),
    RTSPCredential("888888", "888888"),
    RTSPCredential("123456789", "123456789"),
]

# Add device-specific patterns
DEFAULT_CREDENTIALS.extend([
    # DVR/NVR specific
    RTSPCredential("dvr", "dvr"),
    RTSPCredential("nvr", "nvr"),
    RTSPCredential("ipcam", "ipcam"),
    RTSPCredential("camera", "camera"),
    
    # Common combo variations
    *[RTSPCredential(f"admin{i}", f"admin{i}") for i in range(10)],
    *[RTSPCredential(f"user{i}", f"pass{i}") for i in range(10)],
    
    # Additional password patterns
    *[RTSPCredential("admin", f"pass{i:04d}") for i in range(100)],
    *[RTSPCredential("root", f"root{i:04d}") for i in range(100)],
])

# Add month/year combinations
for month in range(1, 13):
    for year in range(20, 25):
        DEFAULT_CREDENTIALS.extend([
            RTSPCredential("admin", f"{month:02d}{year:02d}"),
            RTSPCredential("root", f"{month:02d}{year:02d}"),
        ])

# RTSP paths sorted by commonality
RTSP_PATHS = [
    # Common paths (Priority 1)
    RTSPPath("/", "Root path", 1),
    RTSPPath("/live", "Live stream", 1),
    RTSPPath("/stream", "Main stream", 1),
    RTSPPath("/live/ch0", "Channel 0", 1),
    RTSPPath("/live/ch1", "Channel 1", 1),
    RTSPPath("/cam/realmonitor", "Camera monitor", 1),
    RTSPPath("/videoMain", "Main video", 1),
    
    # Standard paths (Priority 2)
    RTSPPath("/live/main", "Main stream", 2),
    RTSPPath("/live/sub", "Sub stream", 2),
    RTSPPath("/axis-media/media.amp", "Axis camera", 2),
    RTSPPath("/mpeg4/media.amp", "MPEG4 stream", 2),
    RTSPPath("/img/media.sav", "Media save", 2),
    RTSPPath("/media/video1", "Video channel 1", 2),
    
    # Rare or device-specific paths (Priority 3)
    RTSPPath("/h264/ch1/main/av_stream", "H264 main stream", 3),
    RTSPPath("/h264/ch1/sub/av_stream", "H264 sub stream", 3),
    RTSPPath("/cam/realmonitor?channel=1&subtype=0", "Detailed monitor", 3),
    RTSPPath("/streaming/channels/1", "Channel streaming", 3),
    RTSPPath("/onvif1", "ONVIF stream", 3),
    RTSPPath("/video1", "Video 1", 3),
]

# Add more RTSP paths
RTSP_PATHS.extend([
    # Additional common paths
    RTSPPath("/Streaming/Channels/1", "Main Stream Channel 1", 1),
    RTSPPath("/Streaming/Channels/2", "Main Stream Channel 2", 1),
    RTSPPath("/live/stream1", "Stream 1", 1),
    RTSPPath("/live/stream2", "Stream 2", 1),
    # Manufacturer-specific paths
    RTSPPath("/axis-media/media.amp?videocodec=h264", "Axis H264", 2),
    RTSPPath("/cam/realmonitor?channel=1&subtype=1", "Dahua Main", 2),
    RTSPPath("/h264/ch01/main/av_stream", "Hikvision Main", 2),
    RTSPPath("/h264/ch01/sub/av_stream", "Hikvision Sub", 2),
    RTSPPath("/live/ch00_0", "Samsung Main", 2),
    RTSPPath("/live/ch00_1", "Samsung Sub", 2),
    # Additional paths
    RTSPPath("/11", "Channel 11", 3),
    RTSPPath("/12", "Channel 12", 3),
    RTSPPath("/media/stream1", "Media Stream 1", 3),
    RTSPPath("/media/stream2", "Media Stream 2", 3),
])

# Extend RTSP_PATHS with many more paths
RTSP_PATHS.extend([
    # Hikvision Paths
    RTSPPath("/h264/ch1/main/av_stream", "Hikvision Main Stream", 1),
    RTSPPath("/h264/ch1/sub/av_stream", "Hikvision Sub Stream", 1),
    RTSPPath("/ISAPI/streaming/channels/101", "Hikvision ISAPI 101", 1),
    RTSPPath("/ISAPI/streaming/channels/102", "Hikvision ISAPI 102", 1),
    RTSPPath("/Streaming/Channels/101", "Hikvision Channel 101", 1),
    RTSPPath("/Streaming/Channels/102", "Hikvision Channel 102", 1),
    
    # Dahua Paths
    RTSPPath("/cam/realmonitor?channel=1&subtype=0", "Dahua Main Stream", 1),
    RTSPPath("/cam/realmonitor?channel=1&subtype=1", "Dahua Sub Stream", 1),
    RTSPPath("/cam/playback?channel=1", "Dahua Playback", 2),
    RTSPPath("/cam/realmonitor?channel=2&subtype=0", "Dahua Channel 2 Main", 2),
    RTSPPath("/cam/realmonitor?channel=2&subtype=1", "Dahua Channel 2 Sub", 2),
    
    # Axis Paths
    RTSPPath("/axis-media/media.amp", "Axis Media", 1),
    RTSPPath("/mpeg4/media.amp", "Axis MPEG4", 1),
    RTSPPath("/axis-media/media.3gp", "Axis 3GP", 2),
    RTSPPath("/view/viewer_index.shtml", "Axis Viewer", 2),
    RTSPPath("/onvif-media/media.amp", "Axis ONVIF", 2),
    
    # Bosch Paths
    RTSPPath("/rtsp_tunnel", "Bosch RTSP Tunnel", 2),
    RTSPPath("/video1", "Bosch Video 1", 1),
    RTSPPath("/video2", "Bosch Video 2", 1),
    RTSPPath("/record", "Bosch Recording", 2),
    
    # Sony Paths
    RTSPPath("/video1", "Sony Primary", 1),
    RTSPPath("/video2", "Sony Secondary", 1),
    RTSPPath("/media/video1", "Sony Media 1", 2),
    RTSPPath("/media/video2", "Sony Media 2", 2),
    
    # Panasonic Paths
    RTSPPath("/MediaInput/h264", "Panasonic H264", 1),
    RTSPPath("/MediaInput/mpeg4", "Panasonic MPEG4", 1),
    RTSPPath("/nphMpeg4/g726-640x480", "Panasonic MPEG4 Audio", 2),
    RTSPPath("/nphMpeg4/nil-640x480", "Panasonic MPEG4 Video", 2),
    
    # Samsung/Hanwha Paths
    RTSPPath("/live.sdp", "Samsung Live", 1),
    RTSPPath("/profile1/media.smp", "Samsung Profile 1", 1),
    RTSPPath("/profile2/media.smp", "Samsung Profile 2", 1),
    RTSPPath("/profile3/media.smp", "Samsung Profile 3", 2),
    RTSPPath("/profile4/media.smp", "Samsung Profile 4", 2),
    
    # Vivotek Paths
    RTSPPath("/live.sdp", "Vivotek Live", 1),
    RTSPPath("/video.3gp", "Vivotek 3GP", 2),
    RTSPPath("/video.mp4", "Vivotek MP4", 2),
    RTSPPath("/media/video1", "Vivotek Media 1", 2),
    
    # ONVIF Standard Paths
    RTSPPath("/onvif/device_service", "ONVIF Device", 1),
    RTSPPath("/onvif/media_service", "ONVIF Media", 1),
    RTSPPath("/onvif/streaming/1", "ONVIF Stream 1", 1),
    RTSPPath("/onvif/streaming/2", "ONVIF Stream 2", 1),
    RTSPPath("/onvif/profile1/media.smp", "ONVIF Profile 1", 2),
    
    # Generic Paths
    RTSPPath("/ch01.264", "Channel 1 H264", 1),
    RTSPPath("/ch02.264", "Channel 2 H264", 1),
    RTSPPath("/ch03.264", "Channel 3 H264", 2),
    RTSPPath("/ch04.264", "Channel 4 H264", 2),
    RTSPPath("/1", "Stream 1", 1),
    RTSPPath("/2", "Stream 2", 1),
    RTSPPath("/stream1", "Generic Stream 1", 1),
    RTSPPath("/stream2", "Generic Stream 2", 1),
    RTSPPath("/live/1", "Live 1", 1),
    RTSPPath("/live/2", "Live 2", 1),
    
    # Multi-Channel Paths
    *[RTSPPath(f"/channel{i}", f"Channel {i}", 2) for i in range(1, 17)],
    *[RTSPPath(f"/cam{i}", f"Camera {i}", 2) for i in range(1, 17)],
    *[RTSPPath(f"/stream{i}", f"Stream {i}", 2) for i in range(1, 17)],
    *[RTSPPath(f"/ch{i:02d}", f"CH {i}", 2) for i in range(1, 17)],
    
    # Additional Manufacturer Paths
    RTSPPath("/live/main", "Main Stream", 1),
    RTSPPath("/live/sub", "Sub Stream", 1),
    RTSPPath("/live/mobile", "Mobile Stream", 2),
    RTSPPath("/av0_0", "AV Stream 0", 2),
    RTSPPath("/av0_1", "AV Stream 1", 2),
    RTSPPath("/primary", "Primary Stream", 1),
    RTSPPath("/secondary", "Secondary Stream", 1),
    RTSPPath("/tertiary", "Tertiary Stream", 2),
    
    # Protocol Variations
    RTSPPath("/h264", "H264 Default", 1),
    RTSPPath("/h265", "H265 Default", 1),
    RTSPPath("/mpeg4", "MPEG4 Default", 2),
    RTSPPath("/mjpeg", "MJPEG Default", 2),
    RTSPPath("/av_stream/ch0", "AV Ch0", 2),
    RTSPPath("/av_stream/ch1", "AV Ch1", 2),
    
    # Special Cases
    RTSPPath("/", "Root", 1),
    RTSPPath("/11", "Special Stream 1", 3),
    RTSPPath("/12", "Special Stream 2", 3),
    RTSPPath("/0", "Zero Stream", 3),
    RTSPPath("/main", "Main Only", 1),
    RTSPPath("/sub", "Sub Only", 1),
    
    # Additional Variations
    *[RTSPPath(f"/live/ch{i}", f"Live Channel {i}", 3) for i in range(1, 9)],
    *[RTSPPath(f"/live/stream{i}", f"Live Stream {i}", 3) for i in range(1, 9)],
    *[RTSPPath(f"/h264/ch{i:02d}/main/av_stream", f"H264 Main Ch{i}", 3) for i in range(1, 9)],
    *[RTSPPath(f"/h264/ch{i:02d}/sub/av_stream", f"H264 Sub Ch{i}", 3) for i in range(1, 9)],
])

# Add comprehensive CCTV paths
RTSP_PATHS.extend([
    # DVR/NVR channel patterns
    *[RTSPPath(f"/cam/realmonitor?channel={i}&subtype=0", f"DVR Channel {i} Main", 1) for i in range(1, 33)],
    *[RTSPPath(f"/cam/realmonitor?channel={i}&subtype=1", f"DVR Channel {i} Sub", 1) for i in range(1, 33)],
    *[RTSPPath(f"/h264/ch{i:02d}/main/av_stream", f"Channel {i} Main H264", 1) for i in range(1, 33)],
    *[RTSPPath(f"/h264/ch{i:02d}/sub/av_stream", f"Channel {i} Sub H264", 1) for i in range(1, 33)],
    
    # Multi-channel variations
    *[RTSPPath(f"/Streaming/Channels/{i:02d}", f"Stream Channel {i}", 1) for i in range(1, 33)],
    *[RTSPPath(f"/live/ch{i:02d}", f"Live Channel {i}", 1) for i in range(0, 33)],
    
    # Additional CCTV manufacturers
    *[RTSPPath(f"/ch{i}/main/av_stream", f"Main Stream {i}", 1) for i in range(1, 33)],
    *[RTSPPath(f"/ch{i}/sub/av_stream", f"Sub Stream {i}", 1) for i in range(1, 33)],
    
    # Common CCTV path patterns
    RTSPPath("/live", "Main Stream", 1),
    RTSPPath("/live/main", "Main Stream", 1),
    RTSPPath("/live/ch00_0", "Channel 1 High", 1),
    RTSPPath("/live/ch01_0", "Channel 1 High", 1),
    RTSPPath("/live/ch00_1", "Channel 1 Low", 1),
    RTSPPath("/live/ch01_1", "Channel 1 Low", 1),
    RTSPPath("/live/0/main", "Main Stream", 1),
    RTSPPath("/live/1/main", "Main Stream", 1),
    
    # Extended channel formats
    *[RTSPPath(f"/live/{i}/main", f"Live Main {i}", 2) for i in range(64)],
    *[RTSPPath(f"/live/{i}/sub", f"Live Sub {i}", 2) for i in range(64)],
])

class RTSPScanner:
    def __init__(self, host: str, port: int = 554, timeout: int = 5):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.results: List[Dict] = []
        self.stop_scan = False
        self.successful_auths: Set[Tuple[str, str]] = set()
        self.successful_paths: Set[str] = set()
        self.channel_map = {}
        self.path_queue = Queue()
        self.max_workers = min(50, len(RTSP_PATHS))  # Increased max workers
        self.connection_cache = {}  # Cache for connection results
        self.auth_cache = {}  # Cache for authentication results
        self.scan_start_time = None
        self.last_activity = None
        self.requests_sent = 0
        self.responses_received = 0
        self.connection_pool = []
        self.connection_semaphore = asyncio.Semaphore(50)  # Connection pool limit

    @lru_cache(maxsize=1024)
    def _create_rtsp_request(self, path: str, credential: Optional[RTSPCredential] = None) -> str:
        """Cached RTSP request creation"""
        request = f"OPTIONS rtsp://"
        
        if credential:
            request += f"{credential.username}:{credential.password}@"
            
        request += f"{self.host}:{self.port}{path} RTSP/1.0\r\n"
        request += "CSeq: 1\r\n"
        request += "User-Agent: NEScan RTSP Scanner\r\n"
        request += "\r\n"
        return request

    def _test_connection(self) -> bool:
        """Test basic connection to host before scanning"""
        try:
            with socket.create_connection((self.host, self.port), 2):
                return True
        except:
            return False

    async def _get_connection(self):
        """Get connection from pool or create new one"""
        async with self.connection_semaphore:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.host, self.port),
                    timeout=self.timeout
                )
                return reader, writer
            except Exception as e:
                logging.debug(f"Connection error: {str(e)}")
                return None, None

    async def _async_test_rtsp_path(self, path: RTSPPath, credential: Optional[RTSPCredential] = None) -> Optional[Dict]:
        """Optimized RTSP path testing"""
        try:
            self.requests_sent += 1
            
            # Use cached result if available
            cache_key = (path.path, credential.username if credential else None, 
                        credential.password if credential else None)
            if cache_key in self.connection_cache:
                return self.connection_cache[cache_key]

            reader, writer = await self._get_connection()
            if not reader or not writer:
                return None

            try:
                request = self._create_rtsp_request(path.path, credential)
                writer.write(request.encode())
                await writer.drain()
                
                response = await asyncio.wait_for(
                    reader.read(1024),
                    timeout=self.timeout
                )
                
                response_str = response.decode('utf-8', errors='ignore')
                result = self._process_response(path, credential, response_str)
                
                if result:
                    self.connection_cache[cache_key] = result
                    self.responses_received += 1
                
                return result

            finally:
                writer.close()
                await writer.wait_closed()

        except Exception as e:
            logging.debug(f"Error testing {path.path}: {str(e)}")
            return None

    async def _scan_batch(self, paths: List[RTSPPath], credentials: List[RTSPCredential], auth_mode: bool = False) -> List[Dict]:
        """Scan a batch of paths with separate auth handling"""
        tasks = []
        results = []
        
        if not auth_mode:
            # Regular path scanning without auth
            for path in paths:
                clean_path = path.path.rstrip('/')
                current_url = f"rtsp://{self.host}:{self.port}{clean_path}"
                print(f"\r{Fore.CYAN}[*] Checking: {current_url:<70}{Style.RESET_ALL}", end='', flush=True)
                tasks.append(self._async_test_rtsp_path(path))

            # Wait for results
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in batch_results:
                if isinstance(result, dict):
                    if result['response_code'] == "200 OK":
                        rtsp_url = f"rtsp://{self.host}:{self.port}{result['path'].rstrip('/')}"
                        print(f"\n{Fore.GREEN}[✓] Found: {rtsp_url}{Style.RESET_ALL}")
                        results.append(result)
                    elif result['response_code'] == "401 Unauthorized":
                        results.append(result)
        else:
            # Auth scanning mode
            for path in paths:
                if path.path not in self.successful_paths:  # Skip already successful paths
                    for cred in credentials:
                        auth_url = f"rtsp://{cred.username}:{cred.password}@{self.host}:{self.port}{path.path.rstrip('/')}"
                        print(f"\r{Fore.BLUE}[*] Trying: {auth_url:<70}{Style.RESET_ALL}", end='', flush=True)
                        auth_result = await self._async_test_rtsp_path(path, cred)
                        if auth_result and auth_result['response_code'] == "200 OK":
                            print(f"\n{Fore.GREEN}[✓] Found: {auth_url}{Style.RESET_ALL}")
                            results.append(auth_result)
                            break  # Found working credentials, move to next path

        return results

    def scan(self, use_auth: bool = True, priority_level: int = 3) -> List[Dict]:
        """Enhanced scanning with separate auth phase"""
        if not self._test_connection():
            logging.error(f"Cannot connect to {self.host}:{self.port}")
            print(f"\n{Fore.RED}[!] No Found - Cannot connect to {self.host}:{self.port}{Style.RESET_ALL}")
            return []

        self.scan_start_time = time.time()
        self.last_activity = time.time()
        self.requests_sent = 0
        self.responses_received = 0
        self.results = []

        paths_to_scan = [p for p in RTSP_PATHS if p.priority <= priority_level]
        priority_groups = {i: [p for p in paths_to_scan if p.priority == i] for i in range(1, 4)}
        credentials = DEFAULT_CREDENTIALS if use_auth else []

        print(f"\n{Fore.BLUE}[*] Starting RTSP scan on {self.host}:{self.port}")
        print(f"[*] Testing {len(paths_to_scan)} paths{' with authentication' if use_auth else ''}")
        print(f"[*] Using {len(credentials)} credential sets" if use_auth else "")

        async def run_scan():
            # Phase 1: Scan without auth
            for priority in sorted(priority_groups.keys()):
                paths = priority_groups[priority]
                if not paths:
                    continue

                print(f"\n{Fore.CYAN}[*] Scanning priority {priority} paths...{Style.RESET_ALL}")
                batch_size = 10
                with tqdm(total=len(paths), desc=f"Priority {priority}", unit="path") as pbar:
                    for i in range(0, len(paths), batch_size):
                        if self.stop_scan:
                            break
                        batch = paths[i:i + batch_size]
                        batch_results = await self._scan_batch(batch, credentials, auth_mode=False)
                        self.results.extend(batch_results)
                        pbar.update(len(batch))

            # Phase 2: Auth scanning for paths that returned 401 or weren't accessible
            if use_auth and credentials:
                auth_required = [r['path'] for r in self.results if r['response_code'] == "401 Unauthorized"]
                if auth_required:
                    print(f"\n{Fore.YELLOW}[*] Starting authentication scan for {len(auth_required)} paths...{Style.RESET_ALL}")
                    auth_paths = [RTSPPath(p, "", 1) for p in auth_required]
                    batch_size = 5
                    with tqdm(total=len(auth_paths), desc="Auth scan", unit="path") as pbar:
                        for i in range(0, len(auth_paths), batch_size):
                            if self.stop_scan:
                                break
                            batch = auth_paths[i:i + batch_size]
                            batch_results = await self._scan_batch(batch, credentials, auth_mode=True)
                            self.results.extend(batch_results)
                            pbar.update(len(batch))

                # Try auth on all paths as fallback
                print(f"\n{Fore.YELLOW}[*] Trying authentication on all paths...{Style.RESET_ALL}")
                all_paths = [p for p in paths_to_scan if p.path not in self.successful_paths]
                for priority in sorted(priority_groups.keys()):
                    priority_paths = [p for p in all_paths if p.priority == priority]
                    if priority_paths:
                        print(f"{Fore.CYAN}[*] Trying auth on priority {priority} paths...{Style.RESET_ALL}")
                        with tqdm(total=len(priority_paths), desc=f"Auth priority {priority}", unit="path") as pbar:
                            for i in range(0, len(priority_paths), batch_size):
                                if self.stop_scan:
                                    break
                                batch = priority_paths[i:i + batch_size]
                                batch_results = await self._scan_batch(batch, credentials[:100], auth_mode=True)  # Try top 100 credentials
                                self.results.extend(batch_results)
                                pbar.update(len(batch))

            # Show final statistics
            scan_duration = time.time() - self.scan_start_time
            success_rate = (self.responses_received / self.requests_sent * 100) if self.requests_sent > 0 else 0
            print(f"\n{Fore.BLUE}[*] Scan Statistics:{Style.RESET_ALL}")
            print(f"[*] Duration: {scan_duration:.1f} seconds")
            print(f"[*] Requests Sent: {self.requests_sent}")
            print(f"[*] Responses Received: {self.responses_received}")
            print(f"[*] Success Rate: {success_rate:.1f}%")

        try:
            asyncio.run(run_scan())
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
            self.stop_scan = True

        successful = len([r for r in self.results if r['response_code'] == "200 OK"])
        if successful:
            print(f"\n{Fore.GREEN}[✓] Found {successful} accessible RTSP streams{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.RED}[!] No Found - No accessible RTSP streams found{Style.RESET_ALL}")

        return self.results

    def _optimize_paths(self, paths: List[RTSPPath]) -> List[RTSPPath]:
        """Optimize path scanning order based on previous results"""
        if not self.successful_paths:
            return paths
            
        def similarity_score(path: RTSPPath) -> float:
            base_score = max(len(os.path.commonprefix([path.path, sp])) for sp in self.successful_paths)
            # Prioritize same-priority paths
            if any(sp.endswith(path.path.split('/')[-1]) for sp in self.successful_paths):
                base_score += 10
            return base_score

        return sorted(paths, key=lambda p: similarity_score(p), reverse=True)

    def _process_response(self, path: RTSPPath, credential: Optional[RTSPCredential], response: str) -> Optional[Dict]:
        """Process RTSP response and extract information"""
        if "200 OK" in response or "401 Unauthorized" in response:
            is_success = "200 OK" in response
            
            if is_success:
                self.successful_paths.add(path.path)
                if credential:
                    self.successful_auths.add((credential.username, credential.password))
                
                # Cache successful auth for this path
                if credential:
                    self.auth_cache[path.path] = (credential.username, credential.password)

            result = {
                "path": path.path,
                "description": path.description,
                "priority": path.priority,
                "response_code": "200 OK" if is_success else "401 Unauthorized",
                "authenticated": credential is not None,
                "port": self.port,
            }
            
            if credential:
                result.update({
                    "username": credential.username,
                    "password": credential.password,
                })
            
            if is_success:
                channel_info = self._detect_channel_info(path.path)
                if channel_info:
                    result.update(channel_info)
            
            return result
        return None

    def _print_channel_mapping(self) -> None:
        """Print discovered channel mapping"""
        print(f"\n{Fore.CYAN}[*] Channel Mapping:{Style.RESET_ALL}")
        for channel, path in sorted(self.channel_map.items()):
            print(f"  Channel {channel}: {path}")

    def stop(self):
        """Stop the ongoing scan"""
        self.stop_scan = True

def format_rtsp_results(results: List[Dict]) -> str:
    """Enhanced results formatting with more details"""
    from colorama import Fore, Style
    
    if not results:
        return f"\n{Fore.RED}[!] No Found - No RTSP streams were discovered{Style.RESET_ALL}"
    
    output = []
    output.append(f"\n{Fore.CYAN}[*] RTSP Scan Results:{Style.RESET_ALL}")
    output.append(f"{Fore.BLUE}{'═' * 60}{Style.RESET_ALL}")
    
    # Track streams by status
    connected_streams = []
    auth_required_streams = []
    auth_successful_streams = []
    
    # Process results
    credentials_found = set()
    for result in results:
        if result['response_code'] == '200 OK':
            stream_url = f"rtsp://"
            if result.get('authenticated'):
                stream_url += f"{result['username']}:{result['password']}@"
                credentials_found.add((result['username'], result['password']))
                auth_successful_streams.append(result)
            else:
                connected_streams.append(result)
            stream_url += f"<TARGET-IP>:{result['port']}{result['path']}"
            result['url'] = stream_url
        elif result['response_code'] == '401 Unauthorized':
            auth_required_streams.append(result)
    
    # Show successful connections
    if connected_streams or auth_successful_streams:
        output.append(f"\n{Fore.GREEN}[✓] Successfully Connected Streams:{Style.RESET_ALL}")
        
        if connected_streams:
            output.append(f"\n{Fore.GREEN}No Authentication Required:{Style.RESET_ALL}")
            for stream in connected_streams:
                output.append(f"\n{Fore.GREEN}▶ Stream Found:{Style.RESET_ALL}")
                output.append(f"  • Description: {stream['description']}")
                output.append(f"  • URL: {stream['url']}")
                output.append(f"  • Path: {stream['path']}")
        
        if auth_successful_streams:
            output.append(f"\n{Fore.GREEN}Authentication Successful:{Style.RESET_ALL}")
            for stream in auth_successful_streams:
                output.append(f"\n{Fore.GREEN}▶ Stream Found:{Style.RESET_ALL}")
                output.append(f"  • Description: {stream['description']}")
                output.append(f"  • URL: {stream['url']}")
                output.append(f"  • Credentials: {stream['username']}:{stream['password']}")
    else:
        output.append(f"\n{Fore.YELLOW}[!] No accessible RTSP streams found. Get lucky next time!{Style.RESET_ALL}")
    
    # Show authentication summary
    if credentials_found:
        output.append(f"\n{Fore.CYAN}[*] Working Credentials Found:{Style.RESET_ALL}")
        for username, password in credentials_found:
            output.append(f"  • {username}:{password}")
    
    # Show streams requiring authentication
    if auth_required_streams:
        output.append(f"\n{Fore.YELLOW}[!] Streams Requiring Authentication:{Style.RESET_ALL}")
        for stream in auth_required_streams:
            output.append(f"  • {stream['path']} ({stream['description']})")
    
    # Show scan statistics
    output.append(f"\n{Fore.BLUE}{'─' * 60}{Style.RESET_ALL}")
    output.append(f"{Fore.CYAN}Scan Statistics:{Style.RESET_ALL}")
    output.append(f"• Total Streams Found: {len(results)}")
    output.append(f"• Open Streams: {len(connected_streams)}")
    output.append(f"• Auth Success: {len(auth_successful_streams)}")
    output.append(f"• Auth Required: {len(auth_required_streams)}")
    output.append(f"• Working Credentials: {len(credentials_found)}")
    output.append(f"{Fore.BLUE}{'─' * 60}{Style.RESET_ALL}")
    
    # Add channel mapping section
    if any('channel_number' in r for r in results):
        output.append(f"\n{Fore.CYAN}[*] Available Channels:{Style.RESET_ALL}")
        channels = {}
        for result in results:
            if 'channel_number' in result:
                channel = result['channel_number']
                stream_type = result.get('stream_type', 'unknown')
                if channel not in channels:
                    channels[channel] = {}
                channels[channel][stream_type] = result['url']
        
        for channel, streams in sorted(channels.items()):
            output.append(f"\n{Fore.GREEN}Channel {channel}:{Style.RESET_ALL}")
            for stream_type, url in streams.items():
                output.append(f"  • {stream_type.title()}: {url}")
    
    # Show final status if no successful connections
    if not (connected_streams or auth_successful_streams):
        output = [f"\n{Fore.RED}[!] No Found - No accessible RTSP streams were discovered{Style.RESET_ALL}"]
    
    return '\n'.join(output)
