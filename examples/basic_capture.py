#!/usr/bin/env python3
"""
Basic Packet Capture Example

This script demonstrates basic packet capture functionality.
"""

import sys
import os

# Add the src directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from capture.packet_sniffer import PacketSniffer
from utils.common import ConfigManager, setup_logging


def main():
    """Basic packet capture example."""
    print("Basic Packet Capture Example")
    print("=" * 40)
    
    # Load configuration
    config_manager = ConfigManager("../config")
    config = config_manager.load_config()
    
    # Set up logging
    setup_logging(config.get('logging', {}))
    
    # Initialize packet sniffer
    interface = config_manager.get('capture.interface')
    if interface == 'auto':
        interface = None  # Let the sniffer auto-detect
    
    sniffer = PacketSniffer(interface=interface)
    
    # List available interfaces
    print("Available network interfaces:")
    for iface in sniffer.list_interfaces():
        print(f"  - {iface}")
    
    print(f"\nUsing interface: {sniffer.interface}")
    
    try:
        # Capture 50 packets
        print("\nStarting packet capture (50 packets)...")
        sniffer.start_capture(count=50, save_to_file="captures/basic_capture.pcap")
        
        # Print statistics
        sniffer.print_statistics()
        
    except KeyboardInterrupt:
        print("\nCapture interrupted by user.")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
