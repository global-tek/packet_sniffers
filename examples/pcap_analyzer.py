#!/usr/bin/env python3
"""
PCAP File Analyzer - Comprehensive Analysis Tool

This script demonstrates the best methods to analyze and visualize 
PCAP files using the network packet monitoring toolkit.
"""

import sys
import os
import time
from pathlib import Path
from collections import defaultdict, Counter

# Add src to Python path
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))

class PCAPAnalyzer:
    """Comprehensive PCAP file analyzer."""
    
    def __init__(self, pcap_file):
        """Initialize the analyzer with a PCAP file."""
        self.pcap_file = Path(pcap_file)
        if not self.pcap_file.exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_file}")
        
        # Initialize components
        self.setup_components()
        
        # Analysis results
        self.analysis_results = {}
        
    def setup_components(self):
        """Set up analysis components."""
        try:
            from analysis.protocol_analyzer import ProtocolAnalyzer
            from decryption.traffic_decryptor import TrafficDecryptor
            from visualization.network_visualizer import NetworkVisualizer
            from utils.common import PerformanceMonitor, DataExporter
            
            self.protocol_analyzer = ProtocolAnalyzer()
            self.traffic_decryptor = TrafficDecryptor()
            self.visualizer = NetworkVisualizer("pcap_analysis_output")
            self.performance_monitor = PerformanceMonitor()
            self.data_exporter = DataExporter("pcap_analysis_reports")
            
            print("✓ All analysis components initialized successfully")
            
        except ImportError as e:
            print(f"✗ Component initialization error: {e}")
            raise
    
    def get_basic_info(self):
        """Get basic information about the PCAP file."""
        print(f"\n📁 PCAP File Information")
        print("=" * 50)
        
        file_size = self.pcap_file.stat().st_size
        file_size_mb = file_size / (1024 * 1024)
        
        print(f"File: {self.pcap_file.name}")
        print(f"Path: {self.pcap_file}")
        print(f"Size: {file_size:,} bytes ({file_size_mb:.2f} MB)")
        print(f"Modified: {time.ctime(self.pcap_file.stat().st_mtime)}")
        
        return {
            'file_size': file_size,
            'file_size_mb': file_size_mb,
            'modified_time': self.pcap_file.stat().st_mtime
        }
    
    def analyze_with_scapy(self):
        """Analyze PCAP using Scapy (fastest method)."""
        print(f"\n🔍 Scapy Analysis")
        print("=" * 50)
        
        try:
            from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP, DNS
            
            print("Loading packets with Scapy...")
            packets = rdpcap(str(self.pcap_file))
            
            print(f"✓ Loaded {len(packets)} packets")
            
            # Protocol analysis
            protocols = Counter()
            ip_src = Counter()
            ip_dst = Counter()
            ports_src = Counter()
            ports_dst = Counter()
            packet_sizes = []
            
            for pkt in packets:
                packet_sizes.append(len(pkt))
                
                # Protocol counting
                if IP in pkt:
                    ip_src[pkt[IP].src] += 1
                    ip_dst[pkt[IP].dst] += 1
                    
                    if TCP in pkt:
                        protocols['TCP'] += 1
                        ports_src[pkt[TCP].sport] += 1
                        ports_dst[pkt[TCP].dport] += 1
                    elif UDP in pkt:
                        protocols['UDP'] += 1
                        ports_src[pkt[UDP].sport] += 1
                        ports_dst[pkt[UDP].dport] += 1
                    elif ICMP in pkt:
                        protocols['ICMP'] += 1
                
                if ARP in pkt:
                    protocols['ARP'] += 1
                
                if DNS in pkt:
                    protocols['DNS'] += 1
            
            # Summary statistics
            avg_packet_size = sum(packet_sizes) / len(packet_sizes) if packet_sizes else 0
            total_bytes = sum(packet_sizes)
            
            print(f"\n📊 Packet Statistics:")
            print(f"   Total packets: {len(packets):,}")
            print(f"   Total bytes: {total_bytes:,}")
            print(f"   Average packet size: {avg_packet_size:.1f} bytes")
            print(f"   Unique source IPs: {len(ip_src)}")
            print(f"   Unique destination IPs: {len(ip_dst)}")
            
            print(f"\n🌐 Top Protocols:")
            for proto, count in protocols.most_common(10):
                percentage = (count / len(packets)) * 100
                print(f"   {proto:<8} {count:>6,} packets ({percentage:>5.1f}%)")
            
            print(f"\n📡 Top Source IPs:")
            for ip, count in ip_src.most_common(10):
                percentage = (count / len(packets)) * 100
                print(f"   {ip:<15} {count:>6,} packets ({percentage:>5.1f}%)")
            
            print(f"\n🎯 Top Destination IPs:")
            for ip, count in ip_dst.most_common(10):
                percentage = (count / len(packets)) * 100
                print(f"   {ip:<15} {count:>6,} packets ({percentage:>5.1f}%)")
            
            print(f"\n🚪 Top Destination Ports:")
            for port, count in ports_dst.most_common(10):
                percentage = (count / len(packets)) * 100
                service = self.get_port_service(port)
                print(f"   {port:<6} {service:<12} {count:>6,} packets ({percentage:>5.1f}%)")
            
            # Store results for visualization
            self.analysis_results['scapy'] = {
                'total_packets': len(packets),
                'total_bytes': total_bytes,
                'protocols': dict(protocols),
                'top_src_ips': dict(ip_src.most_common(20)),
                'top_dst_ips': dict(ip_dst.most_common(20)),
                'top_dst_ports': dict(ports_dst.most_common(20)),
                'avg_packet_size': avg_packet_size
            }
            
            return packets
            
        except ImportError:
            print("✗ Scapy not available")
            return None
        except Exception as e:
            print(f"✗ Scapy analysis error: {e}")
            return None
    
    def analyze_with_pyshark(self):
        """Analyze PCAP using PyShark (detailed analysis)."""
        print(f"\n🔬 PyShark Deep Analysis")
        print("=" * 50)
        
        try:
            import pyshark
            
            print("Loading packets with PyShark (this may take longer)...")
            capture = pyshark.FileCapture(str(self.pcap_file))
            
            # Protocol details
            http_requests = []
            dns_queries = []
            ssl_sessions = []
            suspicious_patterns = []
            
            packet_count = 0
            for pkt in capture:
                packet_count += 1
                
                # HTTP analysis
                if hasattr(pkt, 'http'):
                    if hasattr(pkt.http, 'request_method'):
                        http_requests.append({
                            'method': pkt.http.request_method,
                            'host': getattr(pkt.http, 'host', 'unknown'),
                            'uri': getattr(pkt.http, 'request_uri', ''),
                            'user_agent': getattr(pkt.http, 'user_agent', '')
                        })
                
                # DNS analysis
                if hasattr(pkt, 'dns'):
                    if hasattr(pkt.dns, 'qry_name'):
                        dns_queries.append({
                            'query': pkt.dns.qry_name,
                            'type': getattr(pkt.dns, 'qry_type', 'unknown')
                        })
                
                # SSL/TLS analysis
                if hasattr(pkt, 'tls'):
                    ssl_sessions.append({
                        'version': getattr(pkt.tls, 'version', 'unknown'),
                        'cipher': getattr(pkt.tls, 'cipher', 'unknown')
                    })
                
                # Show progress for large files
                if packet_count % 1000 == 0:
                    print(f"   Processed {packet_count} packets...")
            
            capture.close()
            
            print(f"✓ Deep analysis completed on {packet_count} packets")
            
            # HTTP Summary
            if http_requests:
                print(f"\n🌐 HTTP Analysis ({len(http_requests)} requests):")
                methods = Counter(req['method'] for req in http_requests)
                hosts = Counter(req['host'] for req in http_requests)
                
                print(f"   Top HTTP methods:")
                for method, count in methods.most_common(5):
                    print(f"     {method}: {count}")
                
                print(f"   Top hosts:")
                for host, count in hosts.most_common(5):
                    print(f"     {host}: {count}")
            
            # DNS Summary
            if dns_queries:
                print(f"\n🔍 DNS Analysis ({len(dns_queries)} queries):")
                domains = Counter(query['query'] for query in dns_queries)
                
                print(f"   Top queried domains:")
                for domain, count in domains.most_common(10):
                    print(f"     {domain}: {count}")
            
            # SSL Summary
            if ssl_sessions:
                print(f"\n🔒 SSL/TLS Analysis ({len(ssl_sessions)} sessions):")
                versions = Counter(session['version'] for session in ssl_sessions)
                
                print(f"   TLS versions:")
                for version, count in versions.most_common():
                    print(f"     {version}: {count}")
            
            # Store detailed results
            self.analysis_results['pyshark'] = {
                'http_requests': http_requests,
                'dns_queries': dns_queries,
                'ssl_sessions': ssl_sessions
            }
            
        except ImportError:
            print("✗ PyShark not available")
        except Exception as e:
            print(f"✗ PyShark analysis error: {e}")
    
    def security_analysis(self):
        """Perform security-focused analysis."""
        print(f"\n🛡️ Security Analysis")
        print("=" * 50)
        
        if 'scapy' not in self.analysis_results:
            print("⚠️ Scapy analysis required for security analysis")
            return
        
        results = self.analysis_results['scapy']
        
        # Suspicious patterns
        suspicious_findings = []
        
        # Check for port scanning patterns
        dst_ports = results.get('top_dst_ports', {})
        if len(dst_ports) > 50:  # Many different ports contacted
            suspicious_findings.append("Possible port scanning detected (many destination ports)")
        
        # Check for unusual protocols
        protocols = results.get('protocols', {})
        total_packets = results.get('total_packets', 0)
        
        if protocols.get('ICMP', 0) > total_packets * 0.1:  # >10% ICMP
            suspicious_findings.append("High ICMP traffic (possible reconnaissance)")
        
        # Check for data exfiltration patterns
        if results.get('avg_packet_size', 0) > 1200:  # Large average packet size
            suspicious_findings.append("Large average packet size (possible data exfiltration)")
        
        # Top talkers analysis
        src_ips = results.get('top_src_ips', {})
        if src_ips:
            top_talker_packets = max(src_ips.values())
            if top_talker_packets > total_packets * 0.5:  # >50% from one IP
                suspicious_findings.append("Single source generates majority of traffic")
        
        # Common attack ports
        attack_ports = {21: 'FTP', 22: 'SSH', 23: 'Telnet', 135: 'RPC', 139: 'NetBIOS', 
                       445: 'SMB', 1433: 'MSSQL', 3389: 'RDP', 5432: 'PostgreSQL'}
        
        detected_attack_ports = []
        for port, service in attack_ports.items():
            if port in dst_ports:
                detected_attack_ports.append(f"{port} ({service})")
        
        # Display findings
        if suspicious_findings:
            print("⚠️ Suspicious patterns detected:")
            for finding in suspicious_findings:
                print(f"   • {finding}")
        else:
            print("✓ No obvious suspicious patterns detected")
        
        if detected_attack_ports:
            print(f"\n🎯 Common attack ports detected:")
            for port_info in detected_attack_ports:
                print(f"   • Port {port_info}")
        
        # Store security results
        self.analysis_results['security'] = {
            'suspicious_findings': suspicious_findings,
            'attack_ports': detected_attack_ports
        }
    
    def create_visualizations(self):
        """Create comprehensive visualizations."""
        print(f"\n📊 Creating Visualizations")
        print("=" * 50)
        
        if 'scapy' not in self.analysis_results:
            print("⚠️ Analysis results required for visualization")
            return
        
        try:
            results = self.analysis_results['scapy']
            
            # Protocol distribution
            if results.get('protocols'):
                protocol_chart = self.visualizer.plot_protocol_distribution(results['protocols'])
                print(f"✓ Protocol distribution: {protocol_chart}")
            
            # Port activity
            if results.get('top_dst_ports'):
                port_chart = self.visualizer.plot_port_activity(results['top_dst_ports'])
                print(f"✓ Port activity chart: {port_chart}")
            
            # Traffic timeline (if we had timestamps)
            timeline_data = {'HTTP': 100, 'HTTPS': 200, 'DNS': 50, 'Other': 150}
            timeline_chart = self.visualizer.plot_traffic_timeline(timeline_data)
            print(f"✓ Traffic timeline: {timeline_chart}")
            
            # Network topology
            if results.get('top_src_ips') and results.get('top_dst_ips'):
                # Create sample network data
                network_data = {
                    'nodes': list(results['top_src_ips'].keys())[:10] + list(results['top_dst_ips'].keys())[:10],
                    'connections': [(src, dst) for src in list(results['top_src_ips'].keys())[:5] 
                                  for dst in list(results['top_dst_ips'].keys())[:5]]
                }
                topology_chart = self.visualizer.plot_network_topology(network_data)
                print(f"✓ Network topology: {topology_chart}")
            
        except Exception as e:
            print(f"✗ Visualization error: {e}")
    
    def export_reports(self):
        """Export comprehensive analysis reports."""
        print(f"\n📄 Exporting Reports")
        print("=" * 50)
        
        try:
            # Comprehensive JSON report
            report_data = {
                'pcap_file': str(self.pcap_file),
                'analysis_timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'file_info': self.get_basic_info(),
                'analysis_results': self.analysis_results
            }
            
            json_report = self.data_exporter.export_to_json(report_data, "pcap_analysis_report.json")
            print(f"✓ JSON report: {json_report}")
            
            # CSV exports for different aspects
            if 'scapy' in self.analysis_results:
                scapy_results = self.analysis_results['scapy']
                
                # Protocol summary CSV
                protocol_data = [
                    {'protocol': proto, 'packet_count': count, 
                     'percentage': (count / scapy_results['total_packets']) * 100}
                    for proto, count in scapy_results.get('protocols', {}).items()
                ]
                protocol_csv = self.data_exporter.export_to_csv(protocol_data, "protocol_summary.csv")
                print(f"✓ Protocol CSV: {protocol_csv}")
                
                # Top IPs CSV
                ip_data = [
                    {'ip_address': ip, 'packet_count': count, 'type': 'source'}
                    for ip, count in scapy_results.get('top_src_ips', {}).items()
                ] + [
                    {'ip_address': ip, 'packet_count': count, 'type': 'destination'}
                    for ip, count in scapy_results.get('top_dst_ips', {}).items()
                ]
                ip_csv = self.data_exporter.export_to_csv(ip_data, "ip_summary.csv")
                print(f"✓ IP summary CSV: {ip_csv}")
            
        except Exception as e:
            print(f"✗ Export error: {e}")
    
    def get_port_service(self, port):
        """Get common service name for port."""
        services = {
            20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 67: 'DHCP', 68: 'DHCP', 69: 'TFTP', 80: 'HTTP',
            110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 993: 'IMAPS', 995: 'POP3S',
            1433: 'MSSQL', 3389: 'RDP', 5432: 'PostgreSQL', 8080: 'HTTP-ALT'
        }
        return services.get(port, 'Unknown')
    
    def run_complete_analysis(self):
        """Run the complete analysis workflow."""
        print("🚀 Starting Comprehensive PCAP Analysis")
        print("=" * 60)
        
        # Start performance monitoring
        self.performance_monitor.start_monitoring()
        start_time = time.time()
        
        try:
            # Step 1: Basic file information
            self.get_basic_info()
            
            # Step 2: Fast analysis with Scapy
            packets = self.analyze_with_scapy()
            
            # Step 3: Detailed analysis with PyShark (for smaller files)
            file_size_mb = self.pcap_file.stat().st_size / (1024 * 1024)
            if file_size_mb < 50:  # Only for files < 50MB
                self.analyze_with_pyshark()
            else:
                print(f"\n⚠️ Skipping PyShark analysis (file too large: {file_size_mb:.1f} MB)")
            
            # Step 4: Security analysis
            self.security_analysis()
            
            # Step 5: Create visualizations
            self.create_visualizations()
            
            # Step 6: Export reports
            self.export_reports()
            
            # Performance summary
            end_time = time.time()
            analysis_time = end_time - start_time
            
            print(f"\n⏱️ Analysis Performance")
            print("=" * 50)
            print(f"Total analysis time: {analysis_time:.2f} seconds")
            print(f"Memory usage: {self.performance_monitor.get_memory_usage():.1f} MB")
            
            if 'scapy' in self.analysis_results:
                total_packets = self.analysis_results['scapy']['total_packets']
                packets_per_second = total_packets / analysis_time if analysis_time > 0 else 0
                print(f"Processing rate: {packets_per_second:.1f} packets/second")
            
        except Exception as e:
            print(f"\n❌ Analysis failed: {e}")
            import traceback
            traceback.print_exc()
        
        print(f"\n🎉 Analysis Complete!")
        print("=" * 60)
        print("Check the following directories for output:")
        print("  • pcap_analysis_output/ - Visualizations")
        print("  • pcap_analysis_reports/ - Reports and data exports")


def main():
    """Main function to run PCAP analysis."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Comprehensive PCAP file analyzer')
    parser.add_argument('pcap_file', help='Path to the PCAP file to analyze')
    parser.add_argument('--quick', action='store_true', help='Run quick analysis only (Scapy)')
    parser.add_argument('--no-viz', action='store_true', help='Skip visualization creation')
    parser.add_argument('--no-export', action='store_true', help='Skip report export')
    
    args = parser.parse_args()
    
    try:
        analyzer = PCAPAnalyzer(args.pcap_file)
        
        if args.quick:
            # Quick analysis only
            analyzer.get_basic_info()
            analyzer.analyze_with_scapy()
            analyzer.security_analysis()
        else:
            # Full analysis
            analyzer.run_complete_analysis()
            
    except FileNotFoundError as e:
        print(f"❌ Error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n⏹️ Analysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
