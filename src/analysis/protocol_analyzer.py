"""
Protocol Analyzer Module

Deep packet inspection and protocol analysis for IPv4, IPv6, TCP, UDP,
HTTP, DNS, ARP, and more.  Supports both Scapy and PyShark backends.
"""

import json
import logging
import re
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

try:
    import pyshark
    PYSHARK_AVAILABLE = True
except ImportError:
    PYSHARK_AVAILABLE = False

try:
    from scapy.all import rdpcap
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6ND_NS
    from scapy.layers.dns import DNS
    from scapy.layers.l2 import ARP
    from scapy.layers.http import HTTPRequest, HTTPResponse
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# ---------------------------------------------------------------------------
# Suspicious TLDs / patterns
# ---------------------------------------------------------------------------

_SUSPICIOUS_TLDS = {'.tk', '.ml', '.ga', '.cf', '.pw', '.xyz', '.top', '.click'}
_IP_AS_HOST_RE   = re.compile(r'^\d{1,3}(\.\d{1,3}){3}')


def _fresh_analysis() -> Dict[str, Any]:
    """Return a clean analysis dict."""
    return {
        'total_packets':   0,
        'protocols':       Counter(),
        'ip_conversations': defaultdict(int),
        'port_analysis':   defaultdict(int),
        'http_analysis': {
            'requests':     [],
            'responses':    [],
            'hosts':        Counter(),
            'user_agents':  Counter(),
            'status_codes': Counter(),
        },
        'dns_analysis': {
            'queries':   [],
            'responses': [],
            'domains':   Counter(),
        },
        'tcp_analysis': {
            'connections': [],
            'flags':       Counter(),
            'ports':       Counter(),
        },
        'ipv6_analysis': {
            'src_addresses':  Counter(),
            'dst_addresses':  Counter(),
            'next_headers':   Counter(),
        },
        'suspicious_patterns': [],
    }


class ProtocolAnalyzer:
    """
    Analyse network traffic from PCAP files or live capture data.

    Backends (in preference order): Scapy → PyShark.
    """

    def __init__(self, pcap_file: Optional[str] = None):
        self.pcap_file       = pcap_file
        self.packets: List   = []
        self.analysis_results: Dict[str, Any] = {}

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def load_pcap(self, pcap_file: str):
        """Load packets from a PCAP file."""
        self.pcap_file = pcap_file
        self.packets   = []

        if SCAPY_AVAILABLE:
            try:
                self.packets = list(rdpcap(pcap_file))
                logger.info(f"Loaded {len(self.packets)} packets (Scapy) from {pcap_file}")
                return
            except Exception as e:
                logger.warning(f"Scapy failed to read {pcap_file}: {e}")

        if PYSHARK_AVAILABLE:
            try:
                cap = pyshark.FileCapture(pcap_file)
                self.packets = list(cap)
                cap.close()
                logger.info(f"Loaded {len(self.packets)} packets (PyShark) from {pcap_file}")
                return
            except Exception as e:
                logger.warning(f"PyShark failed to read {pcap_file}: {e}")

        logger.error("Neither Scapy nor PyShark available — cannot load PCAP.")

    def load_live_packets(self, packets: List):
        """Accept a list of already-captured Scapy packets."""
        self.packets = packets

    # ------------------------------------------------------------------
    # Analysis entry point
    # ------------------------------------------------------------------

    def analyze_protocols(self) -> Dict[str, Any]:
        """
        Analyse all loaded packets and populate self.analysis_results.
        """
        if not self.packets:
            logger.warning("No packets loaded. Call load_pcap() first.")
            return {}

        analysis = _fresh_analysis()
        analysis['total_packets'] = len(self.packets)

        for i, packet in enumerate(self.packets):
            try:
                if SCAPY_AVAILABLE and hasattr(packet, 'haslayer'):
                    self._analyze_scapy_packet(packet, analysis)
                elif PYSHARK_AVAILABLE:
                    self._analyze_pyshark_packet(packet, analysis)
            except Exception as e:
                logger.debug(f"Packet {i} analysis error: {e}")

        self.analysis_results = analysis
        return analysis

    # ------------------------------------------------------------------
    # Scapy backend
    # ------------------------------------------------------------------

    def _analyze_scapy_packet(self, packet, analysis: Dict[str, Any]):
        """Analyse a single Scapy packet."""

        # ---- IPv4 ----
        if packet.haslayer(IP):
            analysis['protocols']['IPv4'] += 1
            ip = packet[IP]
            conv_key = f"{ip.src} -> {ip.dst}"
            analysis['ip_conversations'][conv_key] += 1
            self._scapy_transport(packet, ip.src, ip.dst, analysis)

        # ---- IPv6 ----
        elif packet.haslayer(IPv6):
            analysis['protocols']['IPv6'] += 1
            ip6 = packet[IPv6]
            conv_key = f"{ip6.src} -> {ip6.dst}"
            analysis['ip_conversations'][conv_key] += 1
            analysis['ipv6_analysis']['src_addresses'][ip6.src] += 1
            analysis['ipv6_analysis']['dst_addresses'][ip6.dst] += 1
            analysis['ipv6_analysis']['next_headers'][ip6.nh]   += 1
            self._scapy_transport(packet, ip6.src, ip6.dst, analysis)

        # ---- ARP ----
        if packet.haslayer(ARP):
            analysis['protocols']['ARP'] += 1

        # ---- DNS (can appear without IP in some captures) ----
        if packet.haslayer(DNS):
            self._scapy_dns(packet[DNS], analysis)

        # ---- ICMP ----
        if packet.haslayer(ICMP):
            analysis['protocols']['ICMP'] += 1

    def _scapy_transport(self, packet, src_ip: str, dst_ip: str,
                         analysis: Dict[str, Any]):
        """Extract TCP/UDP/HTTP sub-analysis."""
        if packet.haslayer(TCP):
            analysis['protocols']['TCP'] += 1
            tcp = packet[TCP]
            analysis['port_analysis'][tcp.sport] += 1
            analysis['port_analysis'][tcp.dport] += 1
            analysis['tcp_analysis']['ports'][tcp.dport] += 1

            flags = []
            flag_map = [(0x01,'FIN'),(0x02,'SYN'),(0x04,'RST'),
                        (0x08,'PSH'),(0x10,'ACK'),(0x20,'URG')]
            for bit, name in flag_map:
                if tcp.flags & bit:
                    flags.append(name)
                    analysis['tcp_analysis']['flags'][name] += 1

            analysis['tcp_analysis']['connections'].append({
                'src':   f"{src_ip}:{tcp.sport}",
                'dst':   f"{dst_ip}:{tcp.dport}",
                'flags': flags,
            })

            # HTTP on top of TCP
            if packet.haslayer(HTTPRequest):
                self._scapy_http_request(packet[HTTPRequest], analysis)
            elif packet.haslayer(HTTPResponse):
                self._scapy_http_response(packet[HTTPResponse], analysis)

        elif packet.haslayer(UDP):
            analysis['protocols']['UDP'] += 1
            udp = packet[UDP]
            analysis['port_analysis'][udp.sport] += 1
            analysis['port_analysis'][udp.dport] += 1

    def _scapy_http_request(self, h, analysis: Dict[str, Any]):
        analysis['protocols']['HTTP'] += 1

        def _dec(field) -> str:
            return field.decode('utf-8', errors='ignore') if field else ''

        req = {
            'method':     _dec(h.Method),
            'host':       _dec(h.Host),
            'path':       _dec(h.Path),
            'user_agent': _dec(h.User_Agent) if hasattr(h, 'User_Agent') else '',
        }
        analysis['http_analysis']['requests'].append(req)
        if req['host']:
            analysis['http_analysis']['hosts'][req['host']] += 1
        if req['user_agent']:
            analysis['http_analysis']['user_agents'][req['user_agent']] += 1

    def _scapy_http_response(self, h, analysis: Dict[str, Any]):
        def _dec(field) -> str:
            return field.decode('utf-8', errors='ignore') if field else ''
        resp = {
            'status_code':  _dec(h.Status_Code),
            'content_type': _dec(h.Content_Type) if hasattr(h, 'Content_Type') else '',
        }
        analysis['http_analysis']['responses'].append(resp)
        if resp['status_code']:
            analysis['http_analysis']['status_codes'][resp['status_code']] += 1

    def _scapy_dns(self, dns, analysis: Dict[str, Any]):
        analysis['protocols']['DNS'] += 1
        if dns.qr == 0 and dns.qd:
            domain = dns.qd.qname.decode('utf-8', errors='ignore')
            analysis['dns_analysis']['queries'].append({'domain': domain, 'type': dns.qd.qtype})
            analysis['dns_analysis']['domains'][domain] += 1
        elif dns.qr == 1:
            domain = dns.qd.qname.decode('utf-8', errors='ignore') if dns.qd else ''
            answers = []
            if dns.an:
                for ans in dns.an:
                    if hasattr(ans, 'rdata'):
                        answers.append(str(ans.rdata))
            analysis['dns_analysis']['responses'].append({'domain': domain, 'answers': answers})

    # ------------------------------------------------------------------
    # PyShark backend (expanded coverage)
    # ------------------------------------------------------------------

    def _analyze_pyshark_packet(self, packet, analysis: Dict[str, Any]):
        """Analyse a single PyShark packet — broader protocol coverage."""
        try:
            highest = packet.highest_layer
            analysis['protocols'][highest] += 1

            # IP layer
            for ip_attr in ('ip', 'ipv6'):
                if hasattr(packet, ip_attr):
                    ip_layer = getattr(packet, ip_attr)
                    src = getattr(ip_layer, 'src', '')
                    dst = getattr(ip_layer, 'dst', '')
                    if src and dst:
                        analysis['ip_conversations'][f"{src} -> {dst}"] += 1

                    if ip_attr == 'ipv6':
                        analysis['protocols']['IPv6'] += 1
                        analysis['ipv6_analysis']['src_addresses'][src] += 1
                        analysis['ipv6_analysis']['dst_addresses'][dst] += 1
                    break

            # TCP
            if hasattr(packet, 'tcp'):
                tcp = packet.tcp
                sport = int(getattr(tcp, 'srcport', 0) or 0)
                dport = int(getattr(tcp, 'dstport', 0) or 0)
                analysis['port_analysis'][sport] += 1
                analysis['port_analysis'][dport]  += 1
                analysis['tcp_analysis']['ports'][dport] += 1
                analysis['protocols']['TCP'] += 1

                # TCP flags via PyShark
                for flag_name in ('syn', 'ack', 'fin', 'rst', 'psh', 'urg'):
                    if getattr(tcp, f'flags_{flag_name}', '0') == '1':
                        analysis['tcp_analysis']['flags'][flag_name.upper()] += 1

            # UDP
            if hasattr(packet, 'udp'):
                udp = packet.udp
                sport = int(getattr(udp, 'srcport', 0) or 0)
                dport = int(getattr(udp, 'dstport', 0) or 0)
                analysis['port_analysis'][sport] += 1
                analysis['port_analysis'][dport]  += 1
                analysis['protocols']['UDP'] += 1

            # HTTP
            if hasattr(packet, 'http'):
                http = packet.http
                analysis['protocols']['HTTP'] += 1
                if hasattr(http, 'request_method'):
                    host = getattr(http, 'host', '')
                    ua   = getattr(http, 'user_agent', '')
                    req  = {
                        'method':     http.request_method,
                        'host':       host,
                        'path':       getattr(http, 'request_uri', ''),
                        'user_agent': ua,
                    }
                    analysis['http_analysis']['requests'].append(req)
                    if host:
                        analysis['http_analysis']['hosts'][host] += 1
                    if ua:
                        analysis['http_analysis']['user_agents'][ua] += 1
                if hasattr(http, 'response_code'):
                    code = str(http.response_code)
                    analysis['http_analysis']['status_codes'][code] += 1

            # DNS
            if hasattr(packet, 'dns'):
                dns = packet.dns
                analysis['protocols']['DNS'] += 1
                qname = getattr(dns, 'qry_name', '')
                if qname:
                    analysis['dns_analysis']['domains'][qname] += 1
                    analysis['dns_analysis']['queries'].append({'domain': qname, 'type': None})

            # TLS/SSL
            if hasattr(packet, 'tls'):
                analysis['protocols']['TLS'] += 1
                sni = getattr(packet.tls, 'handshake_extensions_server_name', None)
                if sni:
                    analysis['dns_analysis']['domains'][sni] += 1

            # QUIC
            if hasattr(packet, 'quic'):
                analysis['protocols']['QUIC'] += 1

            # DHCP / DHCPv6
            if hasattr(packet, 'dhcp'):
                analysis['protocols']['DHCP'] += 1
            if hasattr(packet, 'dhcpv6'):
                analysis['protocols']['DHCPv6'] += 1

            # ICMP / ICMPv6
            if hasattr(packet, 'icmp'):
                analysis['protocols']['ICMP'] += 1
            if hasattr(packet, 'icmpv6'):
                analysis['protocols']['ICMPv6'] += 1

            # ARP
            if hasattr(packet, 'arp'):
                analysis['protocols']['ARP'] += 1

            # SMTP / IMAP / POP3
            for proto in ('smtp', 'imap', 'pop'):
                if hasattr(packet, proto):
                    analysis['protocols'][proto.upper()] += 1

            # FTP
            if hasattr(packet, 'ftp'):
                analysis['protocols']['FTP'] += 1

            # SSH
            if hasattr(packet, 'ssh'):
                analysis['protocols']['SSH'] += 1

        except Exception as e:
            logger.debug(f"PyShark packet analysis error: {e}")

    # ------------------------------------------------------------------
    # Anomaly / suspicious pattern detection
    # ------------------------------------------------------------------

    def detect_suspicious_patterns(self) -> List[Dict[str, Any]]:
        """Return list of suspicious patterns found in current analysis_results."""
        suspicious = []
        if not self.analysis_results:
            return suspicious

        # Port scanning: many distinct destination ports seen
        ports = self.analysis_results.get('tcp_analysis', {}).get('ports', {})
        if len(ports) > 50:
            suspicious.append({
                'type':        'potential_port_scan',
                'description': f'High port diversity: {len(ports)} unique destination ports',
                'details':     {'unique_ports': len(ports)},
            })

        # Excessive DNS queries to specific domains
        dns_domains = self.analysis_results.get('dns_analysis', {}).get('domains', {})
        hot_domains = {d: c for d, c in dns_domains.items() if c > 20}
        if hot_domains:
            suspicious.append({
                'type':        'excessive_dns_queries',
                'description': f'High DNS query rate to {len(hot_domains)} domain(s)',
                'details':     dict(list(hot_domains.items())[:10]),
            })

        # Suspicious domain TLDs
        flagged_domains = [
            d for d in dns_domains
            if any(d.lower().endswith(t) for t in _SUSPICIOUS_TLDS)
            or _IP_AS_HOST_RE.match(d)
        ]
        if flagged_domains:
            suspicious.append({
                'type':        'suspicious_domains',
                'description': f'Potentially suspicious domains: {len(flagged_domains)}',
                'details':     flagged_domains[:20],
            })

        # SYN flood heuristic
        flags = self.analysis_results.get('tcp_analysis', {}).get('flags', {})
        syn = flags.get('SYN', 0)
        ack = flags.get('ACK', 0)
        if syn > 100 and syn > ack * 5:
            suspicious.append({
                'type':        'potential_syn_flood',
                'description': f'SYN/ACK imbalance: {syn} SYN vs {ack} ACK',
                'details':     {'syn': syn, 'ack': ack},
            })

        # IPv6 scanning indicators
        ipv6 = self.analysis_results.get('ipv6_analysis', {})
        if len(ipv6.get('dst_addresses', {})) > 100:
            suspicious.append({
                'type':        'ipv6_enumeration',
                'description': f"Many unique IPv6 destinations: {len(ipv6['dst_addresses'])}",
                'details':     {'unique_dst': len(ipv6['dst_addresses'])},
            })

        self.analysis_results['suspicious_patterns'] = suspicious
        return suspicious

    # ------------------------------------------------------------------
    # Report generation
    # ------------------------------------------------------------------

    def generate_report(self, output_file: Optional[str] = None) -> str:
        if not self.analysis_results:
            self.analyze_protocols()

        lines = [
            '=' * 60,
            'NETWORK TRAFFIC ANALYSIS REPORT',
            '=' * 60,
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        ]
        if self.pcap_file:
            lines.append(f"Source:    {self.pcap_file}")

        total = self.analysis_results.get('total_packets', 0)
        lines += [f"Total Packets: {total}", '']

        # Protocols
        lines += ['PROTOCOL DISTRIBUTION', '-' * 30]
        protocols = self.analysis_results.get('protocols', Counter())
        proto_total = sum(protocols.values()) or 1
        for proto, count in protocols.most_common():
            pct = count / proto_total * 100
            lines.append(f"{proto:<15} {count:>8} ({pct:>5.1f}%)")
        lines.append('')

        # Top conversations
        lines += ['TOP IP CONVERSATIONS', '-' * 30]
        convs = self.analysis_results.get('ip_conversations', {})
        for conv, count in sorted(convs.items(), key=lambda x: x[1], reverse=True)[:10]:
            lines.append(f"{conv:<45} {count:>6}")
        lines.append('')

        # IPv6 summary
        ipv6 = self.analysis_results.get('ipv6_analysis', {})
        if ipv6.get('src_addresses'):
            lines += ['TOP IPv6 SOURCES', '-' * 30]
            for addr, count in Counter(ipv6['src_addresses']).most_common(5):
                lines.append(f"  {addr}: {count}")
            lines.append('')

        # HTTP
        http = self.analysis_results.get('http_analysis', {})
        if http.get('hosts'):
            lines += ['TOP HTTP HOSTS', '-' * 30]
            for host, count in http['hosts'].most_common(10):
                lines.append(f"{host:<40} {count:>6}")
            lines.append('')

        # DNS
        dns = self.analysis_results.get('dns_analysis', {})
        if dns.get('domains'):
            lines += ['TOP DNS QUERIES', '-' * 30]
            for domain, count in dns['domains'].most_common(10):
                lines.append(f"{domain:<40} {count:>6}")
            lines.append('')

        # Suspicious patterns
        suspicious = self.detect_suspicious_patterns()
        if suspicious:
            lines += ['SUSPICIOUS PATTERNS', '-' * 30]
            for pattern in suspicious:
                lines.append(f"  [{pattern['type']}] {pattern['description']}")
            lines.append('')

        report = '\n'.join(lines)

        if output_file:
            with open(output_file, 'w') as fh:
                fh.write(report)
            logger.info(f"Report saved to {output_file}")

        return report

    def export_to_json(self, output_file: str):
        """Serialise analysis results to a JSON file."""
        if not self.analysis_results:
            self.analyze_protocols()

        def _serialize(obj):
            if isinstance(obj, (Counter, defaultdict, dict)):
                return {str(k): _serialize(v) for k, v in obj.items()}
            if isinstance(obj, list):
                return [_serialize(i) for i in obj]
            return obj

        data = _serialize(self.analysis_results)
        with open(output_file, 'w') as fh:
            json.dump(data, fh, indent=2, default=str)
        logger.info(f"Analysis exported to {output_file}")


def main():
    import argparse

    parser = argparse.ArgumentParser(description='Network Protocol Analyzer')
    parser.add_argument('pcap_file', help='PCAP file to analyse')
    parser.add_argument('-r', '--report', help='Save text report to file')
    parser.add_argument('-j', '--json',   help='Save JSON results to file')
    parser.add_argument('--print-report', action='store_true')
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)

    analyzer = ProtocolAnalyzer(args.pcap_file)
    analyzer.load_pcap(args.pcap_file)
    analyzer.analyze_protocols()

    if args.report or args.print_report:
        report = analyzer.generate_report(args.report)
        if args.print_report:
            print(report)

    if args.json:
        analyzer.export_to_json(args.json)

    suspicious = analyzer.detect_suspicious_patterns()
    for p in suspicious:
        print(f"[!] {p['description']}")


if __name__ == '__main__':
    main()
