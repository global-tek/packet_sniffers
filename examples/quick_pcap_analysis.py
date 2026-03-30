#!/usr/bin/env python3
"""
Quick PCAP Analysis Tool

Simple command-line tool for fast PCAP file analysis.
Usage: python3 quick_pcap_analysis.py <pcap_file>
"""

import sys
from pathlib import Path

# Add src to Python path
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))

def quick_analysis(pcap_file):
    """Perform quick PCAP analysis using Scapy."""
    
    try:
        from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP, DNS, Raw
        from collections import Counter
        import time
        
        print(f"🔍 Quick Analysis: {pcap_file}")
        print("=" * 50)
        
        # Load packets
        start_time = time.time()
        packets = rdpcap(pcap_file)
        load_time = time.time() - start_time
        
        print(f"✓ Loaded {len(packets)} packets in {load_time:.2f}s")
        
        # Basic statistics
        protocols = Counter()
        src_ips = Counter()
        dst_ips = Counter()
        src_ports = Counter()
        dst_ports = Counter()
        packet_sizes = []
        
        # Quick analysis loop
        for pkt in packets:
            packet_sizes.append(len(pkt))
            
            if IP in pkt:
                src_ips[pkt[IP].src] += 1
                dst_ips[pkt[IP].dst] += 1
                
                if TCP in pkt:
                    protocols['TCP'] += 1
                    src_ports[pkt[TCP].sport] += 1
                    dst_ports[pkt[TCP].dport] += 1
                elif UDP in pkt:
                    protocols['UDP'] += 1
                    src_ports[pkt[UDP].sport] += 1
                    dst_ports[pkt[UDP].dport] += 1
                elif ICMP in pkt:
                    protocols['ICMP'] += 1
            
            if ARP in pkt:
                protocols['ARP'] += 1
        
        # Results
        total_bytes = sum(packet_sizes)
        avg_size = total_bytes / len(packets)
        
        print(f"\n📊 Summary:")
        print(f"   Packets: {len(packets):,}")
        print(f"   Total size: {total_bytes:,} bytes ({total_bytes/1024/1024:.2f} MB)")
        print(f"   Average packet size: {avg_size:.1f} bytes")
        print(f"   Unique source IPs: {len(src_ips)}")
        print(f"   Unique destination IPs: {len(dst_ips)}")
        
        print(f"\n🌐 Protocols:")
        for proto, count in protocols.most_common():
            pct = (count / len(packets)) * 100
            print(f"   {proto}: {count:,} ({pct:.1f}%)")
        
        print(f"\n📡 Top 5 Source IPs:")
        for ip, count in src_ips.most_common(5):
            pct = (count / len(packets)) * 100
            print(f"   {ip}: {count:,} ({pct:.1f}%)")
        
        print(f"\n🎯 Top 5 Destination IPs:")
        for ip, count in dst_ips.most_common(5):
            pct = (count / len(packets)) * 100
            print(f"   {ip}: {count:,} ({pct:.1f}%)")
        
        print(f"\n🚪 Top 10 Destination Ports:")
        port_services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 993: 'IMAPS',
            995: 'POP3S', 1433: 'MSSQL', 3389: 'RDP', 5432: 'PostgreSQL',
            8080: 'HTTP-ALT'
        }
        
        for port, count in dst_ports.most_common(10):
            pct = (count / len(packets)) * 100
            service = port_services.get(port, 'Unknown')
            print(f"   {port} ({service}): {count:,} ({pct:.1f}%)")
        
        # Quick security check
        print(f"\n🛡️ Quick Security Check:")
        
        # Check for common attack patterns
        security_alerts = []
        
        # Port scanning detection
        if len(dst_ports) > 100:
            security_alerts.append("⚠️ Many destination ports - possible port scan")
        
        # ICMP flood
        icmp_pct = (protocols.get('ICMP', 0) / len(packets)) * 100
        if icmp_pct > 10:
            security_alerts.append(f"⚠️ High ICMP traffic ({icmp_pct:.1f}%)")
        
        # Single source dominance
        if src_ips:
            top_src_pct = (src_ips.most_common(1)[0][1] / len(packets)) * 100
            if top_src_pct > 70:
                security_alerts.append(f"⚠️ Single source dominates traffic ({top_src_pct:.1f}%)")
        
        # Uncommon ports
        uncommon_ports = [p for p in dst_ports.keys() if p > 49152]  # Ephemeral range
        if len(uncommon_ports) > 50:
            security_alerts.append("⚠️ Many high-numbered ports accessed")
        
        if security_alerts:
            for alert in security_alerts:
                print(f"   {alert}")
        else:
            print("   ✓ No obvious security concerns detected")
        
    except ImportError:
        print("❌ Scapy not available. Please install: pip install scapy")
    except Exception as e:
        print(f"❌ Analysis error: {e}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 quick_pcap_analysis.py <pcap_file>")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    if not Path(pcap_file).exists():
        print(f"❌ File not found: {pcap_file}")
        sys.exit(1)
    
    quick_analysis(pcap_file)

if __name__ == "__main__":
    main()
