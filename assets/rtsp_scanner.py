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
    RTSPCredential("admin", "admin"),
    RTSPCredential("admin", "12345"),
    RTSPCredential("admin", ""),
    RTSPCredential("root", "root"),
    RTSPCredential("admin", "password"),
    # Add more common credentials
    RTSPCredential("admin", "123456"),
    RTSPCredential("admin", "admin123"),
    RTSPCredential("admin", "pass123"),
    RTSPCredential("root", "123456"),
    RTSPCredential("root", "password"),
    RTSPCredential("user", "user"),
    RTSPCredential("user", "password"),
    RTSPCredential("guest", "guest"),
    RTSPCredential("operator", "operator"),
    RTSPCredential("supervisor", "supervisor"),
    # Camera-specific credentials
    RTSPCredential("hikvision", "hikvision"),
    RTSPCredential("dahua", "dahua"),
    RTSPCredential("axis", "axis"),
    RTSPCredential("samsung", "samsung"),
    RTSPCredential("sony", "sony"),
    # Default camera passwords
    RTSPCredential("admin", "4321"),
    RTSPCredential("admin", "1234"),
    RTSPCredential("admin", "12345678"),
    RTSPCredential("admin", "123456789"),
    RTSPCredential("admin", "administrator"),
]

# Add CCTV-specific credentials
DEFAULT_CREDENTIALS.extend([
    # Commonly used DVR/NVR credentials
    RTSPCredential("admin", ""),
    RTSPCredential("admin", "admin"),
    RTSPCredential("666666", "666666"),
    RTSPCredential("888888", "888888"),
    RTSPCredential("admin", "9999"),
    RTSPCredential("admin", "12345"),
    # DVR manufacturer defaults
    RTSPCredential("dvr", "dvr"),
    RTSPCredential("service", "service"),
    RTSPCredential("supervisor", "supervisor"),
    RTSPCredential("admin1", "admin1"),
    # More camera credentials
    *[RTSPCredential("admin", str(i)) for i in range(1234, 12345)],  # Common numeric passwords
    *[RTSPCredential("root", str(i)) for i in range(1234, 12345)],
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
        self.max_workers = min(32, len(RTSP_PATHS))  # Limit max threads
        self.connection_cache = {}  # Cache for connection results
        self.auth_cache = {}  # Cache for authentication results

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

    async def _async_test_rtsp_path(self, path: RTSPPath, credential: Optional[RTSPCredential] = None) -> Optional[Dict]:
        """Asynchronous RTSP path testing"""
        try:
            # Check cache first
            cache_key = (path.path, credential.username if credential else None, 
                        credential.password if credential else None)
            if cache_key in self.connection_cache:
                return self.connection_cache[cache_key]

            reader, writer = await asyncio.open_connection(self.host, self.port)
            request = self._create_rtsp_request(path.path, credential)
            
            writer.write(request.encode())
            await writer.drain()
            
            response = await reader.read(1024)
            writer.close()
            await writer.wait_closed()
            
            response_str = response.decode('utf-8', errors='ignore')
            
            result = self._process_response(path, credential, response_str)
            self.connection_cache[cache_key] = result
            return result

        except Exception as e:
            logging.debug(f"Error testing RTSP path {path.path}: {str(e)}")
            return None

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

    async def _scan_batch(self, paths: List[RTSPPath], credentials: List[RTSPCredential]) -> List[Dict]:
        """Scan a batch of paths concurrently"""
        tasks = []
        for path in paths:
            # Try without auth first
            tasks.append(self._async_test_rtsp_path(path))
            
            # Try with credentials
            for cred in credentials:
                if not self.stop_scan:
                    tasks.append(self._async_test_rtsp_path(path, cred))
        
        results = []
        for coro in asyncio.as_completed(tasks):
            if self.stop_scan:
                break
            try:
                result = await coro
                if result:
                    results.append(result)
            except Exception as e:
                logging.debug(f"Error in scan batch: {e}")
        
        return results

    def scan(self, use_auth: bool = True, priority_level: int = 3) -> List[Dict]:
        """Enhanced scanning with optimizations"""
        if not self._test_connection():
            logging.error(f"Cannot connect to {self.host}:{self.port}")
            return []

        self.results = []
        paths_to_scan = [p for p in RTSP_PATHS if p.priority <= priority_level]
        
        # Group paths by priority for better efficiency
        priority_groups = {
            1: [p for p in paths_to_scan if p.priority == 1],
            2: [p for p in paths_to_scan if p.priority == 2],
            3: [p for p in paths_to_scan if p.priority == 3]
        }

        credentials = DEFAULT_CREDENTIALS if use_auth else []
        
        # Calculate total operations for progress bar
        total_ops = sum(len(paths) * (len(credentials) + 1) for paths in priority_groups.values())
        
        async def run_scan():
            with tqdm(total=total_ops, desc="Scanning RTSP paths", unit="path") as pbar:
                # Scan high priority paths first
                for priority in sorted(priority_groups.keys()):
                    paths = priority_groups[priority]
                    if not paths:
                        continue

                    # Split paths into smaller batches for better control
                    batch_size = 10
                    for i in range(0, len(paths), batch_size):
                        batch = paths[i:i + batch_size]
                        batch_results = await self._scan_batch(batch, credentials)
                        self.results.extend(batch_results)
                        pbar.update(len(batch) * (len(credentials) + 1))

                        # If we found working paths/credentials, prioritize similar patterns
                        if self.successful_paths:
                            self._prioritize_similar_paths(paths[i + batch_size:])

                        if self.stop_scan:
                            break

        # Run the async scan
        asyncio.run(run_scan())
        
        # Show channel mapping
        if self.channel_map:
            self._print_channel_mapping()

        return self.results

    def _prioritize_similar_paths(self, remaining_paths: List[RTSPPath]) -> None:
        """Reorder remaining paths based on successful patterns"""
        if not self.successful_paths:
            return

        def similarity_score(path: str) -> int:
            return max(len(os.path.commonprefix([path, sp])) for sp in self.successful_paths)

        remaining_paths.sort(key=lambda p: similarity_score(p.path), reverse=True)

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
        return f"{Fore.YELLOW}No RTSP streams found. Get lucky next time!{Style.RESET_ALL}"
    
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
    
    return '\n'.join(output)
