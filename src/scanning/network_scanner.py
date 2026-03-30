"""
Network Scanner Module

Network discovery and port scanning with configurable rate limiting.
Integrates python-nmap for advanced scanning when available.
"""

import ipaddress
import logging
import os
import socket
import subprocess
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


class NetworkScanner:
    """
    Network scanner for host discovery and port scanning.

    Rate limiting is built in to avoid triggering IDS/IPS or flooding
    the network. Default: 50 threads, 0.05 s inter-scan delay.
    """

    def __init__(
        self,
        target: str = '192.168.1.0/24',
        max_threads: int = 50,
        scan_delay: float = 0.05,
    ):
        """
        Args:
            target:      Target network CIDR or single host.
            max_threads: Thread pool size for concurrent scanning.
            scan_delay:  Seconds to sleep between each port probe (rate limit).
        """
        self.target      = target
        self.max_threads = max_threads
        self.scan_delay  = scan_delay
        self.scan_results: Dict[str, Any] = {}

    # ------------------------------------------------------------------
    # Host discovery
    # ------------------------------------------------------------------

    def ping_host(self, host: str, timeout: int = 2) -> bool:
        """Send a single ICMP ping. Returns True if host responds."""
        try:
            result = subprocess.run(
                ['ping', '-c', '1', '-W', str(timeout * 1000), host],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=timeout + 1,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return False

    def scan_network(self) -> List[Dict[str, Any]]:
        """
        Discover active hosts on self.target via ICMP ping.
        Returns a list of host info dicts.
        """
        active_hosts: List[Dict[str, Any]] = []

        try:
            network = ipaddress.ip_network(self.target, strict=False)
            hosts   = list(network.hosts())
        except ValueError:
            # Single host / hostname
            if self.ping_host(self.target):
                active_hosts.append(self._build_host_info(self.target))
            return active_hosts

        logger.info(f"Ping-scanning {self.target} ({len(hosts)} hosts) "
                    f"with {self.max_threads} threads …")

        with ThreadPoolExecutor(max_workers=self.max_threads) as pool:
            futures = {pool.submit(self.ping_host, str(h)): str(h) for h in hosts}
            for future in as_completed(futures):
                host = futures[future]
                try:
                    if future.result():
                        active_hosts.append(self._build_host_info(host))
                        logger.info(f"Host alive: {host}")
                except Exception as e:
                    logger.debug(f"Ping error for {host}: {e}")

        return active_hosts

    def _build_host_info(self, ip: str) -> Dict[str, Any]:
        return {
            'ip':       ip,
            'hostname': self.resolve_hostname(ip),
            'mac':      self.get_mac_address(ip),
            'vendor':   None,
        }

    # ------------------------------------------------------------------
    # Port scanning
    # ------------------------------------------------------------------

    def scan_port(self, host: str, port: int, timeout: float = 1.0) -> bool:
        """Return True if TCP port is open on host."""
        if self.scan_delay > 0:
            time.sleep(self.scan_delay)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                return sock.connect_ex((host, port)) == 0
        except (socket.error, OSError):
            return False

    def scan_host_ports(
        self,
        host: str,
        ports: List[int],
    ) -> Dict[int, bool]:
        """Scan multiple ports on host. Returns {port: is_open}."""
        results: Dict[int, bool] = {}

        with ThreadPoolExecutor(max_workers=self.max_threads) as pool:
            futures = {pool.submit(self.scan_port, host, port): port for port in ports}
            for future in as_completed(futures):
                port = futures[future]
                try:
                    is_open = future.result()
                    results[port] = is_open
                    if is_open:
                        logger.info(f"  {host}:{port} OPEN")
                except Exception as e:
                    logger.debug(f"Port scan error {host}:{port}: {e}")
                    results[port] = False

        return results

    @staticmethod
    def get_common_ports() -> List[int]:
        return [
            20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
            443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900,
            8080, 8443, 8888, 9090, 10000,
        ]

    # ------------------------------------------------------------------
    # Comprehensive host scan
    # ------------------------------------------------------------------

    def comprehensive_scan(
        self,
        target_host: str,
        port_range: Optional[Tuple[int, int]] = None,
        use_nmap: bool = True,
    ) -> Dict[str, Any]:
        """
        Full scan of a single host: ping, ports, services, OS detection.

        If python-nmap is available and use_nmap=True, delegates to nmap
        for richer results (version detection, OS fingerprinting).
        """
        logger.info(f"Comprehensive scan: {target_host}")

        # Try nmap first if available
        if use_nmap and NMAP_AVAILABLE:
            nmap_result = self._nmap_comprehensive(target_host, port_range)
            if nmap_result:
                return nmap_result

        # Fallback: custom implementation
        if not self.ping_host(target_host):
            return {'host': target_host, 'alive': False,
                    'error': 'Host not responding to ping'}

        result: Dict[str, Any] = {
            'host':         target_host,
            'alive':        True,
            'hostname':     self.resolve_hostname(target_host),
            'mac':          self.get_mac_address(target_host),
            'open_ports':   {},
            'services':     {},
            'os_detection': self.detect_os(target_host),
            'scan_method':  'custom',
        }

        ports = (
            list(range(port_range[0], port_range[1] + 1))
            if port_range else self.get_common_ports()
        )
        logger.info(f"Scanning {len(ports)} ports on {target_host} …")

        port_results = self.scan_host_ports(target_host, ports)
        open_ports   = {p: True for p, up in port_results.items() if up}
        result['open_ports'] = open_ports

        if open_ports:
            result['services'] = self.detect_services(target_host, list(open_ports))

        return result

    # ------------------------------------------------------------------
    # Nmap integration (enhanced)
    # ------------------------------------------------------------------

    def nmap_scan(
        self,
        scan_type: str = 'syn',
        port_range: Optional[str] = None,
        service_detection: bool = True,
        os_detection: bool = False,
    ) -> Optional[Dict[str, Any]]:
        """
        Run an Nmap scan and return structured results.

        Args:
            scan_type:          'syn' | 'tcp' | 'udp' | 'ping' | 'version'
            port_range:         Port range string e.g. '1-1024' or '22,80,443'
            service_detection:  Add -sV flag for version detection
            os_detection:       Add -O flag (requires root)
        """
        if not NMAP_AVAILABLE:
            logger.warning("python-nmap not installed. Install with: pip install python-nmap")
            return None

        scan_args_map = {
            'syn':     '-sS',
            'tcp':     '-sT',
            'udp':     '-sU',
            'ping':    '-sn',
            'version': '-sV',
        }
        args = scan_args_map.get(scan_type, '-sT')

        if service_detection and scan_type not in ('ping', 'udp'):
            args += ' -sV'
        if os_detection:
            args += ' -O'
        if port_range:
            args += f' -p {port_range}'

        try:
            nm = nmap.PortScanner()
            logger.info(f"Running nmap {args} on {self.target} …")
            nm.scan(self.target, arguments=args)
            return self._parse_nmap_results(nm)
        except nmap.PortScannerError as e:
            logger.error(f"Nmap error: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected nmap error: {e}")
            return None

    def _nmap_comprehensive(
        self,
        host: str,
        port_range: Optional[Tuple[int, int]],
    ) -> Optional[Dict[str, Any]]:
        """Run a targeted nmap comprehensive scan on a single host."""
        if not NMAP_AVAILABLE:
            return None

        port_arg = (
            f'-p {port_range[0]}-{port_range[1]}'
            if port_range
            else '-p 1-1024'
        )
        args = f'-sT -sV {port_arg}'

        try:
            nm = nmap.PortScanner()
            nm.scan(host, arguments=args)
            parsed = self._parse_nmap_results(nm)

            if parsed and host in parsed:
                host_data = parsed[host]
                result: Dict[str, Any] = {
                    'host':        host,
                    'alive':       True,
                    'hostname':    host_data.get('hostname', self.resolve_hostname(host)),
                    'open_ports':  {},
                    'services':    {},
                    'os_detection': host_data.get('os', None),
                    'scan_method': 'nmap',
                    'mac':         self.get_mac_address(host),
                }
                for port_info in host_data.get('ports', []):
                    port = port_info['port']
                    if port_info.get('state') == 'open':
                        result['open_ports'][port] = True
                        result['services'][port] = {
                            'service': port_info.get('name', 'unknown'),
                            'version': port_info.get('version', ''),
                            'banner':  port_info.get('product', ''),
                        }
                return result
        except Exception as e:
            logger.debug(f"Nmap comprehensive scan error: {e}")

        return None

    def _parse_nmap_results(self, nm: 'nmap.PortScanner') -> Dict[str, Any]:
        """Convert raw nmap PortScanner output to a clean structured dict."""
        results: Dict[str, Any] = {}

        for host in nm.all_hosts():
            host_info: Dict[str, Any] = {
                'hostname': nm[host].hostname(),
                'state':    nm[host].state(),
                'ports':    [],
                'os':       None,
            }

            # OS detection (if data present)
            osmatch = nm[host].get('osmatch', [])
            if osmatch:
                host_info['os'] = {
                    'name':     osmatch[0].get('name', ''),
                    'accuracy': osmatch[0].get('accuracy', ''),
                }

            # Ports
            for proto in nm[host].all_protocols():
                for port in sorted(nm[host][proto]):
                    port_data = nm[host][proto][port]
                    host_info['ports'].append({
                        'port':    port,
                        'proto':   proto,
                        'state':   port_data.get('state', ''),
                        'name':    port_data.get('name', ''),
                        'product': port_data.get('product', ''),
                        'version': port_data.get('version', ''),
                        'extrainfo': port_data.get('extrainfo', ''),
                    })

            results[host] = host_info

        return results

    # ------------------------------------------------------------------
    # Service / OS detection helpers
    # ------------------------------------------------------------------

    _COMMON_SERVICES: Dict[int, str] = {
        20: 'FTP Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet',
        25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
        143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 993: 'IMAPS',
        995: 'POP3S', 1433: 'MSSQL', 1521: 'Oracle',
        3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC',
        6379: 'Redis', 8080: 'HTTP-Alt', 27017: 'MongoDB',
    }

    def detect_services(
        self, host: str, ports: List[int]
    ) -> Dict[int, Dict[str, str]]:
        """Map open ports to service names and grab banners."""
        return {
            port: {
                'service': self._COMMON_SERVICES.get(port, 'Unknown'),
                'banner':  self.grab_banner(host, port) or '',
            }
            for port in ports
        }

    def grab_banner(self, host: str, port: int, timeout: float = 3.0) -> Optional[str]:
        """Attempt to read a service banner from host:port."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect((host, port))
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                return banner or None
        except (socket.error, OSError):
            return None

    def detect_os(self, host: str) -> Optional[str]:
        """
        Heuristic OS detection via ICMP TTL value.
        ≤64 → Linux/Unix, ≤128 → Windows, ≤255 → Network device.
        """
        try:
            result = subprocess.run(
                ['ping', '-c', '1', host],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                match = re.search(r'ttl=(\d+)', result.stdout, re.IGNORECASE)
                if match:
                    ttl = int(match.group(1))
                    if ttl <= 64:
                        return 'Linux/Unix'
                    if ttl <= 128:
                        return 'Windows'
                    return 'Network Device / BSD'
        except (subprocess.TimeoutExpired, OSError, ValueError):
            pass
        return None

    # ------------------------------------------------------------------
    # Hostname / MAC resolution
    # ------------------------------------------------------------------

    def resolve_hostname(self, ip: str) -> Optional[str]:
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror):
            return None

    def get_mac_address(self, ip: str) -> Optional[str]:
        try:
            result = subprocess.run(
                ['arp', '-n', ip],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if ip in line:
                        for part in line.split():
                            if re.fullmatch(r'([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}', part):
                                return part
        except (subprocess.TimeoutExpired, OSError):
            pass
        return None

    # ------------------------------------------------------------------
    # Interface enumeration
    # ------------------------------------------------------------------

    def get_network_interfaces(self) -> List[Dict[str, Any]]:
        """Return a list of network interface details."""
        if PSUTIL_AVAILABLE:
            interfaces = []
            for name, addrs in psutil.net_if_addrs().items():
                interfaces.append({
                    'name': name,
                    'addresses': [
                        {
                            'family':    str(a.family),
                            'address':   a.address,
                            'netmask':   a.netmask,
                            'broadcast': a.broadcast,
                        }
                        for a in addrs
                    ],
                })
            return interfaces

        # Fallback: parse ifconfig
        interfaces: List[Dict[str, Any]] = []
        try:
            result = subprocess.run(['ifconfig'], capture_output=True, text=True)
            current: Optional[Dict[str, Any]] = None
            for line in result.stdout.splitlines():
                if line and not line.startswith((' ', '\t')):
                    if ':' in line:
                        if current:
                            interfaces.append(current)
                        current = {'name': line.split(':')[0], 'addresses': []}
                elif current and 'inet ' in line:
                    parts = line.split()
                    for i, p in enumerate(parts):
                        if p == 'inet' and i + 1 < len(parts):
                            current['addresses'].append({'address': parts[i + 1]})
            if current:
                interfaces.append(current)
        except Exception as e:
            logger.debug(f"ifconfig parse error: {e}")

        return interfaces


def main():
    import argparse

    parser = argparse.ArgumentParser(description='Network Scanner')
    parser.add_argument('target', help='Target network or host')
    parser.add_argument('-p', '--ports',  help='Port range e.g. 1-1000')
    parser.add_argument('--scan-delay',   type=float, default=0.05,
                        help='Seconds between port probes (rate limit)')
    parser.add_argument('--max-threads',  type=int, default=50)
    parser.add_argument('--type',         choices=['ping', 'comprehensive', 'nmap'],
                        default='comprehensive')
    parser.add_argument('--nmap-type',    choices=['syn','tcp','udp','ping','version'],
                        default='tcp')
    parser.add_argument('--interfaces',   action='store_true')
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    scanner = NetworkScanner(args.target, args.max_threads, args.scan_delay)

    if args.interfaces:
        for iface in scanner.get_network_interfaces():
            print(f"  {iface['name']}: "
                  f"{[a.get('address') for a in iface.get('addresses', [])]}")
        return

    if args.type == 'ping':
        hosts = scanner.scan_network()
        print(f"\nFound {len(hosts)} active host(s):")
        for h in hosts:
            print(f"  {h['ip']:<18} {h.get('hostname') or 'Unknown'}")

    elif args.type == 'nmap':
        pr = args.ports if args.ports else None
        results = scanner.nmap_scan(args.nmap_type, port_range=pr)
        if results:
            for host, info in results.items():
                print(f"\n{host} ({info.get('hostname', '')})")
                for p in info.get('ports', []):
                    if p['state'] == 'open':
                        svc = f"{p['name']} {p.get('version', '')}".strip()
                        print(f"  {p['port']:>5}/{p['proto']}  {svc}")

    else:
        port_range = None
        if args.ports:
            try:
                start, end = map(int, args.ports.split('-'))
                port_range = (start, end)
            except ValueError:
                print("Invalid port range. Use start-end (e.g. 1-1000)")
                return

        result = scanner.comprehensive_scan(args.target, port_range)
        print(f"\nHost: {args.target}")
        print(f"Alive: {result['alive']}")
        if result.get('alive'):
            if result.get('hostname'):
                print(f"Hostname: {result['hostname']}")
            if result.get('os_detection'):
                print(f"OS: {result['os_detection']}")
            if result.get('scan_method'):
                print(f"Scan method: {result['scan_method']}")
            open_ports = result.get('open_ports', {})
            if open_ports:
                print(f"\nOpen ports ({len(open_ports)}):")
                for port in sorted(open_ports):
                    svc = result.get('services', {}).get(port, {})
                    name = svc.get('service', 'Unknown')
                    ver  = svc.get('version', '') or svc.get('banner', '')
                    ver_str = f" — {ver[:60]}" if ver else ''
                    print(f"  {port:>5}/tcp  {name}{ver_str}")


if __name__ == '__main__':
    main()
