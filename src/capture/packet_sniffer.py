"""
Packet Sniffer Module

Real-time network packet capture and monitoring with IPv4 and IPv6 support.
"""

import logging
import queue
import threading
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

try:
    from scapy.all import sniff, wrpcap, get_if_list, conf
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
    from scapy.layers.http import HTTPRequest, HTTPResponse
    from scapy.layers.dns import DNS
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("Scapy not available — packet capture features limited.")


class PacketSniffer:
    """
    Advanced packet sniffer for real-time network traffic monitoring.

    Supports IPv4, IPv6, TCP, UDP, HTTP, DNS, and ICMP.
    """

    def __init__(self, interface: Optional[str] = None, filter_expr: str = ''):
        self.interface    = interface or self._get_default_interface()
        self.filter_expr  = filter_expr
        self.captured_packets: List[Dict[str, Any]] = []
        self.is_capturing = False
        self.packet_queue: queue.Queue = queue.Queue()

    # ------------------------------------------------------------------
    # Interface helpers
    # ------------------------------------------------------------------

    def _get_default_interface(self) -> str:
        if SCAPY_AVAILABLE:
            interfaces = get_if_list()
            for iface in interfaces:
                if any(p in iface for p in ('en', 'eth', 'wlan', 'ens', 'enp')):
                    return iface
            return interfaces[0] if interfaces else 'en0'
        return 'en0'

    def list_interfaces(self) -> List[str]:
        """Return available network interfaces."""
        if SCAPY_AVAILABLE:
            return get_if_list()
        import subprocess
        try:
            result = subprocess.run(['ifconfig'], capture_output=True, text=True)
            return [
                line.split(':')[0]
                for line in result.stdout.split('\n')
                if ':' in line and not line.startswith(('\t', ' '))
            ]
        except Exception:
            return ['en0', 'en1', 'lo0']

    # ------------------------------------------------------------------
    # Packet handler
    # ------------------------------------------------------------------

    def packet_handler(self, packet):
        """Callback invoked for each captured packet."""
        info: Dict[str, Any] = {
            'timestamp': datetime.now(),
            'summary':   str(packet.summary()) if hasattr(packet, 'summary') else str(packet),
        }

        if not (SCAPY_AVAILABLE and hasattr(packet, 'haslayer')):
            self._store(info)
            return

        # ---- IPv4 ----
        if packet.haslayer(IP):
            ip = packet[IP]
            info.update({
                'src_ip':   ip.src,
                'dst_ip':   ip.dst,
                'protocol': ip.proto,
                'length':   ip.len,
                'ip_ver':   4,
            })
            self._extract_transport(packet, info)
            self._extract_app_layer(packet, info)

        # ---- IPv6 ----
        elif packet.haslayer(IPv6):
            ip6 = packet[IPv6]
            info.update({
                'src_ip':   ip6.src,
                'dst_ip':   ip6.dst,
                'protocol': ip6.nh,   # next header
                'length':   ip6.plen,
                'ip_ver':   6,
            })
            self._extract_transport(packet, info)
            self._extract_app_layer(packet, info)

        self._store(info)

    def _extract_transport(self, packet, info: Dict[str, Any]):
        """Extract TCP/UDP/ICMP fields into *info*."""
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            info.update({
                'src_port':  tcp.sport,
                'dst_port':  tcp.dport,
                'tcp_flags': str(tcp.flags),
            })
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            info.update({
                'src_port': udp.sport,
                'dst_port': udp.dport,
            })
        elif packet.haslayer(ICMP):
            icmp = packet[ICMP]
            info['icmp_type'] = icmp.type

    def _extract_app_layer(self, packet, info: Dict[str, Any]):
        """Extract HTTP / DNS application-layer fields into *info*."""
        if packet.haslayer(HTTPRequest):
            h = packet[HTTPRequest]
            info.update({
                'http_method': h.Method.decode('utf-8', errors='ignore') if h.Method else '',
                'http_host':   h.Host.decode('utf-8', errors='ignore')   if h.Host   else '',
                'http_path':   h.Path.decode('utf-8', errors='ignore')   if h.Path   else '',
            })
        elif packet.haslayer(HTTPResponse):
            h = packet[HTTPResponse]
            info['http_status'] = (
                h.Status_Code.decode('utf-8', errors='ignore') if h.Status_Code else ''
            )

        if packet.haslayer(DNS):
            dns = packet[DNS]
            if dns.qd:
                info['dns_query'] = dns.qd.qname.decode('utf-8', errors='ignore')

    def _store(self, info: Dict[str, Any]):
        """Store packet info and print a summary line."""
        self.captured_packets.append(info)
        self.packet_queue.put(info)

        ts = info['timestamp'].strftime('%H:%M:%S.%f')[:-3]
        if 'src_ip' in info:
            src = f"{info['src_ip']}:{info.get('src_port', '')}"
            dst = f"{info['dst_ip']}:{info.get('dst_port', '')}"
            ver = f"IPv{info.get('ip_ver', '?')}"
            proto = info.get('protocol', '?')
            logger.debug(f"[{ts}] {ver} {src} -> {dst} (proto={proto})")
        else:
            logger.debug(f"[{ts}] {info['summary']}")

    # ------------------------------------------------------------------
    # Capture control
    # ------------------------------------------------------------------

    def start_capture(
        self,
        count: int = 0,
        timeout: Optional[int] = None,
        save_to_file: Optional[str] = None,
    ):
        """
        Start live packet capture.

        Args:
            count:        Packets to capture; 0 = unlimited.
            timeout:      Stop after N seconds.
            save_to_file: Write captured packets to this PCAP path.
        """
        if not SCAPY_AVAILABLE:
            logger.error("Scapy is required for packet capture.")
            return

        logger.info(f"Starting capture on {self.interface!r}, filter={self.filter_expr!r}")
        print(f"Capturing on {self.interface} — press Ctrl+C to stop.")

        self.is_capturing = True
        self.captured_packets.clear()

        try:
            packets = sniff(
                iface=self.interface,
                filter=self.filter_expr,
                prn=self.packet_handler,
                count=count,
                timeout=timeout,
                stop_filter=lambda _: not self.is_capturing,
            )

            if save_to_file:
                wrpcap(save_to_file, packets)
                logger.info(f"Packets saved to {save_to_file}")

        except KeyboardInterrupt:
            print('\nCapture stopped.')
        except Exception as e:
            logger.error(f"Capture error: {e}")
        finally:
            self.is_capturing = False

    def stop_capture(self):
        self.is_capturing = False

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def get_capture_statistics(self) -> Dict[str, Any]:
        if not self.captured_packets:
            return {}

        stats: Dict[str, Any] = {
            'total_packets':      len(self.captured_packets),
            'protocols':          {},
            'top_sources':        {},
            'top_destinations':   {},
            'ipv4_packets':       0,
            'ipv6_packets':       0,
            'capture_duration':   0.0,
        }

        for pkt in self.captured_packets:
            proto = pkt.get('protocol', 'Unknown')
            stats['protocols'][proto] = stats['protocols'].get(proto, 0) + 1

            if pkt.get('ip_ver') == 4:
                stats['ipv4_packets'] += 1
            elif pkt.get('ip_ver') == 6:
                stats['ipv6_packets'] += 1

            src = pkt.get('src_ip')
            if src:
                stats['top_sources'][src] = stats['top_sources'].get(src, 0) + 1

            dst = pkt.get('dst_ip')
            if dst:
                stats['top_destinations'][dst] = stats['top_destinations'].get(dst, 0) + 1

        if len(self.captured_packets) >= 2:
            t0 = self.captured_packets[0]['timestamp']
            t1 = self.captured_packets[-1]['timestamp']
            stats['capture_duration'] = (t1 - t0).total_seconds()

        return stats

    def print_statistics(self):
        stats = self.get_capture_statistics()
        if not stats:
            print("No statistics available.")
            return

        print('\n' + '=' * 50)
        print('PACKET CAPTURE STATISTICS')
        print('=' * 50)
        print(f"Total Packets:    {stats['total_packets']}")
        print(f"IPv4 Packets:     {stats['ipv4_packets']}")
        print(f"IPv6 Packets:     {stats['ipv6_packets']}")
        print(f"Duration:         {stats['capture_duration']:.2f}s")

        print('\nProtocol Distribution:')
        total = stats['total_packets']
        for proto, count in sorted(stats['protocols'].items(), key=lambda x: x[1], reverse=True):
            print(f"  {proto}: {count} ({count/total*100:.1f}%)")

        print('\nTop 5 Source IPs:')
        for ip, count in sorted(stats['top_sources'].items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {ip}: {count}")

        print('\nTop 5 Destination IPs:')
        for ip, count in sorted(stats['top_destinations'].items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {ip}: {count}")


def main():
    import argparse

    parser = argparse.ArgumentParser(description='Network Packet Sniffer')
    parser.add_argument('-i', '--interface',        help='Network interface')
    parser.add_argument('-f', '--filter', default='', help='BPF filter')
    parser.add_argument('-c', '--count',  type=int, default=0, help='Packet count (0=∞)')
    parser.add_argument('-t', '--timeout', type=int, help='Capture timeout (seconds)')
    parser.add_argument('-o', '--output',           help='Output PCAP file')
    parser.add_argument('--list-interfaces', action='store_true')
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    sniffer = PacketSniffer(interface=args.interface, filter_expr=args.filter)

    if args.list_interfaces:
        for iface in sniffer.list_interfaces():
            print(f"  {iface}")
        return

    try:
        sniffer.start_capture(count=args.count, timeout=args.timeout, save_to_file=args.output)
    finally:
        sniffer.print_statistics()


if __name__ == '__main__':
    main()
