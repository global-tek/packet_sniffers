#!/usr/bin/env python3
"""
Network Analysis Example

This script demonstrates comprehensive network traffic analysis.
"""

import sys
import os

# Add the src directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from capture.packet_sniffer import PacketSniffer
from analysis.protocol_analyzer import ProtocolAnalyzer
from visualization.network_visualizer import NetworkVisualizer
from utils.common import ConfigManager, DataExporter


def main():
    """Network analysis example."""
    print("Network Analysis Example")
    print("=" * 40)
    
    # Load configuration
    config_manager = ConfigManager("../config")
    config = config_manager.load_config()
    
    # Create output directories
    os.makedirs("captures", exist_ok=True)
    os.makedirs("analysis", exist_ok=True)
    
    # Step 1: Capture packets
    print("Step 1: Capturing network traffic...")
    sniffer = PacketSniffer()
    
    try:
        # Capture traffic for 30 seconds or 200 packets, whichever comes first
        sniffer.start_capture(count=200, timeout=30, save_to_file="captures/analysis_capture.pcap")
        print(f"Captured {len(sniffer.captured_packets)} packets")
        
    except KeyboardInterrupt:
        print("Capture interrupted.")
        return
    except Exception as e:
        print(f"Capture error: {e}")
        return
    
    # Step 2: Analyze captured traffic
    print("\nStep 2: Analyzing captured traffic...")
    analyzer = ProtocolAnalyzer("captures/analysis_capture.pcap")
    
    try:
        # Perform analysis
        analysis_results = analyzer.analyze_protocols()
        
        # Generate and save report
        report = analyzer.generate_report("analysis/traffic_report.txt")
        print("Analysis report generated.")
        
        # Export results to JSON
        analyzer.export_to_json("analysis/analysis_results.json")
        
        # Detect suspicious patterns
        suspicious = analyzer.detect_suspicious_patterns()
        if suspicious:
            print(f"\nSuspicious patterns detected: {len(suspicious)}")
            for pattern in suspicious:
                print(f"  - {pattern['description']}")
        
    except Exception as e:
        print(f"Analysis error: {e}")
        return
    
    # Step 3: Create visualizations
    print("\nStep 3: Creating visualizations...")
    visualizer = NetworkVisualizer("analysis/visualizations")
    
    try:
        # Create various charts
        if analysis_results.get('protocols'):
            visualizer.plot_protocol_distribution(dict(analysis_results['protocols']))
        
        if analysis_results.get('port_analysis'):
            visualizer.plot_port_activity(analysis_results['port_analysis'])
        
        if analysis_results.get('ip_conversations'):
            visualizer.plot_ip_conversations(analysis_results['ip_conversations'])
        
        # Create comprehensive dashboard
        dashboard_path = visualizer.create_comprehensive_dashboard(analysis_results)
        print(f"Dashboard created: {dashboard_path}")
        
    except Exception as e:
        print(f"Visualization error: {e}")
    
    # Step 4: Export data
    print("\nStep 4: Exporting data...")
    exporter = DataExporter("analysis/exports")
    
    try:
        # Export to different formats
        exporter.export_to_json(analysis_results, "complete_analysis.json")
        
        # Export packet summaries to CSV
        packet_summaries = []
        for packet_info in sniffer.captured_packets:
            summary = {
                'timestamp': packet_info['timestamp'].isoformat(),
                'src_ip': packet_info.get('src_ip', ''),
                'dst_ip': packet_info.get('dst_ip', ''),
                'src_port': packet_info.get('src_port', ''),
                'dst_port': packet_info.get('dst_port', ''),
                'protocol': packet_info.get('protocol', ''),
                'length': packet_info.get('length', 0)
            }
            packet_summaries.append(summary)
        
        exporter.export_to_csv(packet_summaries, "packet_summaries.csv")
        
        print("Data export completed.")
        
    except Exception as e:
        print(f"Export error: {e}")
    
    print("\nAnalysis completed successfully!")
    print("Check the 'analysis' directory for all generated files.")


if __name__ == "__main__":
    main()
