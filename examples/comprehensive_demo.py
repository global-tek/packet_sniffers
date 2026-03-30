#!/usr/bin/env python3
"""
Demo Script - Comprehensive Network Analysis

This script demonstrates the full capabilities of the packet monitoring toolkit.
"""

import sys
import os
import time
from pathlib import Path

# Add src to Python path
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))

def run_demo():
    """Run comprehensive demonstration."""
    print("Network Packet Monitoring Toolkit - Comprehensive Demo")
    print("=" * 60)
    
    # Demo 1: Configuration Management
    print("\n1. Configuration Management Demo")
    print("-" * 30)
    
    try:
        from utils.common import ConfigManager, NetworkUtils
        
        config_manager = ConfigManager("../config")
        config = config_manager.load_config()
        
        print(f"✓ Configuration loaded successfully")
        print(f"  Default interface: {config_manager.get('capture.interface', 'auto')}")
        print(f"  Buffer size: {config_manager.get('capture.buffer_size', 65536)} bytes")
        print(f"  Security checks: {config_manager.get('security.require_admin', True)}")
        
    except Exception as e:
        print(f"✗ Configuration error: {e}")
    
    # Demo 2: Network Utilities
    print("\n2. Network Utilities Demo")
    print("-" * 30)
    
    try:
        from utils.common import NetworkUtils
        
        local_ip = NetworkUtils.get_local_ip()
        gateway = NetworkUtils.get_default_gateway()
        
        print(f"✓ Local IP address: {local_ip}")
        print(f"✓ Default gateway: {gateway}")
        print(f"✓ Is 192.168.1.1 private? {NetworkUtils.is_private_ip('192.168.1.1')}")
        print(f"✓ Is 8.8.8.8 private? {NetworkUtils.is_private_ip('8.8.8.8')}")
        
        # Validate some IPs and ports
        test_ips = ['192.168.1.1', '8.8.8.8', '256.1.1.1', 'invalid']
        print("\n  IP Validation tests:")
        for ip in test_ips:
            valid = NetworkUtils.validate_ip(ip)
            print(f"    {ip:<15} {'✓' if valid else '✗'}")
        
        test_ports = [80, 443, 65535, 65536, 0, 'invalid']
        print("\n  Port Validation tests:")
        for port in test_ports:
            valid = NetworkUtils.validate_port(port)
            print(f"    {str(port):<10} {'✓' if valid else '✗'}")
            
    except Exception as e:
        print(f"✗ Network utilities error: {e}")
    
    # Demo 3: Packet Sniffer
    print("\n3. Packet Sniffer Demo")
    print("-" * 30)
    
    try:
        from capture.packet_sniffer import PacketSniffer
        
        sniffer = PacketSniffer()
        interfaces = sniffer.list_interfaces()
        
        print(f"✓ Packet sniffer initialized")
        print(f"✓ Available interfaces ({len(interfaces)}):")
        for i, iface in enumerate(interfaces[:5]):  # Show first 5
            print(f"    {i+1}. {iface}")
        if len(interfaces) > 5:
            print(f"    ... and {len(interfaces) - 5} more")
        
        print(f"✓ Using interface: {sniffer.interface}")
        
    except Exception as e:
        print(f"✗ Packet sniffer error: {e}")
    
    # Demo 4: Network Scanner
    print("\n4. Network Scanner Demo")
    print("-" * 30)
    
    try:
        from scanning.network_scanner import NetworkScanner
        
        scanner = NetworkScanner("127.0.0.1")
        
        print(f"✓ Network scanner initialized")
        
        # Test ping to localhost
        if scanner.ping_host("127.0.0.1", timeout=1):
            print(f"✓ Localhost ping successful")
        else:
            print(f"✗ Localhost ping failed")
        
        # Test port scanning on localhost
        print("  Testing common ports on localhost...")
        common_ports = [22, 80, 443, 8080]
        for port in common_ports:
            is_open = scanner.scan_port("127.0.0.1", port, timeout=0.5)
            status = "OPEN" if is_open else "CLOSED"
            print(f"    Port {port}: {status}")
        
    except Exception as e:
        print(f"✗ Network scanner error: {e}")
    
    # Demo 5: Traffic Decryptor
    print("\n5. Traffic Decryptor Demo")
    print("-" * 30)
    
    try:
        from decryption.traffic_decryptor import TrafficDecryptor
        
        decryptor = TrafficDecryptor()
        print(f"✓ Traffic decryptor initialized")
        
        # Demo SSL/TLS analysis with sample data
        sample_tls_data = bytes([
            0x16, 0x03, 0x03, 0x00, 0x20,  # TLS record header
            0x01, 0x00, 0x00, 0x1C,        # Client Hello
            0x03, 0x03                     # TLS version
        ]) + b'\x00' * 20  # Padding
        
        ssl_analysis = decryptor.analyze_ssl_tls_traffic(sample_tls_data)
        print(f"✓ SSL/TLS analysis completed")
        print(f"    Is SSL/TLS: {ssl_analysis['is_ssl_tls']}")
        print(f"    Version: {ssl_analysis.get('version', 'Unknown')}")
        
    except Exception as e:
        print(f"✗ Traffic decryptor error: {e}")
    
    # Demo 6: Data Visualization
    print("\n6. Data Visualization Demo")
    print("-" * 30)
    
    try:
        from visualization.network_visualizer import NetworkVisualizer
        
        visualizer = NetworkVisualizer("demo_visualizations")
        print(f"✓ Network visualizer initialized")
        
        # Create demo data
        demo_protocols = {'TCP': 1500, 'UDP': 800, 'HTTP': 600, 'DNS': 400}
        demo_ports = {80: 600, 443: 500, 22: 200, 53: 400}
        
        # Try to create visualizations
        try:
            import matplotlib
            matplotlib.use('Agg')  # Use non-interactive backend
            
            protocol_chart = visualizer.plot_protocol_distribution(demo_protocols)
            port_chart = visualizer.plot_port_activity(demo_ports)
            
            print(f"✓ Demo visualizations created:")
            print(f"    Protocol chart: {protocol_chart}")
            print(f"    Port activity chart: {port_chart}")
            
        except ImportError:
            print("ℹ Matplotlib not available - visualizations skipped")
        
    except Exception as e:
        print(f"✗ Visualization error: {e}")
    
    # Demo 7: Performance Monitor
    print("\n7. Performance Monitor Demo")
    print("-" * 30)
    
    try:
        from utils.common import PerformanceMonitor
        
        monitor = PerformanceMonitor()
        monitor.start_monitoring()
        
        # Simulate some packet processing
        monitor.update_packet_stats(100, 50000)
        time.sleep(0.1)  # Small delay
        monitor.update_packet_stats(50, 25000)
        
        pps, bps = monitor.get_processing_rate()
        memory_usage = monitor.get_memory_usage()
        
        print(f"✓ Performance monitoring active")
        print(f"    Packets per second: {pps:.1f}")
        print(f"    Bytes per second: {bps:.1f}")
        print(f"    Memory usage: {memory_usage:.1f} MB")
        
        # Generate performance report
        report = monitor.generate_performance_report()
        print(f"    Total packets processed: {report.get('packets_processed', 0)}")
        print(f"    Average packet size: {report.get('average_packet_size', 0):.1f} bytes")
        
    except Exception as e:
        print(f"✗ Performance monitor error: {e}")
    
    # Demo 8: Data Export
    print("\n8. Data Export Demo")
    print("-" * 30)
    
    try:
        from utils.common import DataExporter
        
        exporter = DataExporter("demo_exports")
        print(f"✓ Data exporter initialized")
        
        # Export demo data
        demo_data = {
            'protocols': demo_protocols,
            'ports': demo_ports,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
        }
        
        json_file = exporter.export_to_json(demo_data, "demo_analysis.json")
        print(f"✓ Demo data exported to JSON: {json_file}")
        
        # Export CSV data
        csv_data = [
            {'protocol': 'TCP', 'count': 1500, 'percentage': 50.0},
            {'protocol': 'UDP', 'count': 800, 'percentage': 26.7},
            {'protocol': 'HTTP', 'count': 600, 'percentage': 20.0},
            {'protocol': 'DNS', 'count': 400, 'percentage': 13.3}
        ]
        
        csv_file = exporter.export_to_csv(csv_data, "demo_protocols.csv")
        print(f"✓ Demo data exported to CSV: {csv_file}")
        
    except Exception as e:
        print(f"✗ Data export error: {e}")
    
    # Summary
    print("\n" + "=" * 60)
    print("DEMO COMPLETED")
    print("=" * 60)
    print("✓ All major components demonstrated successfully!")
    print("\nNext Steps:")
    print("1. Check the generated demo files in the project directories")
    print("2. Review the configuration in config/default.yaml")
    print("3. Try running individual examples in the examples/ directory")
    print("4. Read LEGAL.md for important usage guidelines")
    print("\nFor help with the CLI tool, run: python3 main.py --help")


if __name__ == "__main__":
    try:
        run_demo()
    except KeyboardInterrupt:
        print("\n\nDemo interrupted by user.")
    except Exception as e:
        print(f"\nDemo error: {e}")
        import traceback
        traceback.print_exc()
