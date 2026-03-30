#!/usr/bin/env python3
"""
Network Scanning Example

This script demonstrates network scanning and host discovery.
"""

import sys
import os

# Add the src directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from scanning.network_scanner import NetworkScanner
from utils.common import ConfigManager, NetworkUtils


def main():
    """Network scanning example."""
    print("Network Scanning Example")
    print("=" * 40)
    
    # Get local network information
    local_ip = NetworkUtils.get_local_ip()
    gateway = NetworkUtils.get_default_gateway()
    
    print(f"Local IP: {local_ip}")
    print(f"Gateway: {gateway}")
    
    # Determine local network
    if local_ip and local_ip != "127.0.0.1":
        # Assume /24 network
        network_parts = local_ip.split('.')
        network = f"{'.'.join(network_parts[:3])}.0/24"
    else:
        network = "192.168.1.0/24"  # Default fallback
    
    print(f"Scanning network: {network}")
    
    # Initialize scanner
    scanner = NetworkScanner(network)
    
    try:
        # Step 1: Network discovery
        print("\nStep 1: Discovering active hosts...")
        active_hosts = scanner.scan_network(max_threads=50)
        
        print(f"Found {len(active_hosts)} active hosts:")
        for host in active_hosts:
            hostname = host['hostname'] or 'Unknown'
            mac = host['mac'] or 'Unknown'
            print(f"  {host['ip']:<15} {hostname:<20} {mac}")
        
        # Step 2: Port scanning
        if active_hosts:
            print("\nStep 2: Scanning ports on first host...")
            target_host = active_hosts[0]['ip']
            
            # Comprehensive scan of the first host
            scan_result = scanner.comprehensive_scan(target_host)
            
            print(f"\nScan results for {target_host}:")
            print(f"Host alive: {scan_result['alive']}")
            
            if scan_result['alive']:
                if scan_result['hostname']:
                    print(f"Hostname: {scan_result['hostname']}")
                if scan_result['mac']:
                    print(f"MAC Address: {scan_result['mac']}")
                if scan_result['os_detection']:
                    print(f"OS Detection: {scan_result['os_detection']}")
                
                open_ports = scan_result['open_ports']
                if open_ports:
                    print(f"\nOpen Ports ({len(open_ports)}):")
                    for port in sorted(open_ports.keys()):
                        service_info = scan_result['services'].get(port, {})
                        service_name = service_info.get('service', 'Unknown')
                        banner = service_info.get('banner', '')
                        
                        print(f"  {port}/tcp - {service_name}")
                        if banner:
                            print(f"    Banner: {banner[:60]}...")
                else:
                    print("\nNo open ports found.")
        
        # Step 3: Network interface information
        print("\nStep 3: Network interface information...")
        interfaces = scanner.get_network_interfaces()
        
        for interface in interfaces:
            print(f"\nInterface: {interface['name']}")
            for addr in interface.get('addresses', []):
                print(f"  {addr.get('address', 'N/A')}")
    
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
    except Exception as e:
        print(f"Scan error: {e}")


if __name__ == "__main__":
    main()
