"""
Network Data Visualization Module

Tools for visualizing network traffic data and analysis results.
"""

import json
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
import os

try:
    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates
    from matplotlib.patches import Wedge
    import seaborn as sns
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False


class NetworkVisualizer:
    """
    Visualize network traffic data and analysis results.
    """
    
    def __init__(self, output_dir: str = "visualizations"):
        """
        Initialize the network visualizer.
        
        Args:
            output_dir: Directory to save visualization files
        """
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        
        if MATPLOTLIB_AVAILABLE:
            # Set up matplotlib style
            plt.style.use('default')
            sns.set_palette("husl") if 'sns' in globals() else None
    
    def plot_protocol_distribution(self, protocol_data: Dict[str, int], 
                                 save_path: Optional[str] = None) -> str:
        """
        Create a pie chart of protocol distribution.
        
        Args:
            protocol_data: Dictionary mapping protocols to packet counts
            save_path: Optional path to save the plot
            
        Returns:
            Path to saved plot
        """
        if not MATPLOTLIB_AVAILABLE:
            print("Matplotlib not available for plotting.")
            return ""
        
        fig, ax = plt.subplots(figsize=(10, 8))
        
        protocols = list(protocol_data.keys())
        counts = list(protocol_data.values())
        
        # Create pie chart
        wedges, texts, autotexts = ax.pie(counts, labels=protocols, autopct='%1.1f%%',
                                         startangle=90, textprops={'fontsize': 10})
        
        # Customize appearance
        for autotext in autotexts:
            autotext.set_color('white')
            autotext.set_fontweight('bold')
        
        ax.set_title('Network Protocol Distribution', fontsize=16, fontweight='bold')
        
        # Add legend
        ax.legend(wedges, [f'{p}: {c}' for p, c in zip(protocols, counts)],
                 title="Protocols", loc="center left", bbox_to_anchor=(1, 0, 0.5, 1))
        
        plt.tight_layout()
        
        if not save_path:
            save_path = os.path.join(self.output_dir, 'protocol_distribution.png')
        
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"Protocol distribution chart saved to: {save_path}")
        return save_path
    
    def plot_traffic_timeline(self, traffic_data: List[Dict[str, Any]], 
                            save_path: Optional[str] = None) -> str:
        """
        Create a timeline plot of network traffic.
        
        Args:
            traffic_data: List of traffic data with timestamps
            save_path: Optional path to save the plot
            
        Returns:
            Path to saved plot
        """
        if not MATPLOTLIB_AVAILABLE or not PANDAS_AVAILABLE:
            print("Matplotlib and Pandas required for timeline plotting.")
            return ""
        
        # Convert to DataFrame
        df = pd.DataFrame(traffic_data)
        
        if 'timestamp' not in df.columns:
            print("Traffic data must include 'timestamp' field.")
            return ""
        
        # Ensure timestamp is datetime
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        # Group by time intervals
        df.set_index('timestamp', inplace=True)
        
        # Count packets per minute
        traffic_per_minute = df.resample('1min').size()
        
        fig, ax = plt.subplots(figsize=(14, 6))
        
        # Plot timeline
        ax.plot(traffic_per_minute.index, traffic_per_minute.values, 
                linewidth=2, marker='o', markersize=4)
        
        ax.set_title('Network Traffic Timeline (Packets per Minute)', 
                    fontsize=16, fontweight='bold')
        ax.set_xlabel('Time', fontsize=12)
        ax.set_ylabel('Packets per Minute', fontsize=12)
        
        # Format x-axis
        ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
        ax.xaxis.set_major_locator(mdates.MinuteLocator(interval=10))
        plt.xticks(rotation=45)
        
        # Add grid
        ax.grid(True, alpha=0.3)
        
        plt.tight_layout()
        
        if not save_path:
            save_path = os.path.join(self.output_dir, 'traffic_timeline.png')
        
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"Traffic timeline plot saved to: {save_path}")
        return save_path
    
    def plot_port_activity(self, port_data: Dict[int, int], 
                          top_n: int = 20, save_path: Optional[str] = None) -> str:
        """
        Create a bar chart of port activity.
        
        Args:
            port_data: Dictionary mapping ports to activity counts
            top_n: Number of top ports to display
            save_path: Optional path to save the plot
            
        Returns:
            Path to saved plot
        """
        if not MATPLOTLIB_AVAILABLE:
            print("Matplotlib not available for plotting.")
            return ""
        
        # Get top N ports
        sorted_ports = sorted(port_data.items(), key=lambda x: x[1], reverse=True)[:top_n]
        ports, counts = zip(*sorted_ports) if sorted_ports else ([], [])
        
        fig, ax = plt.subplots(figsize=(12, 8))
        
        # Create bar chart
        bars = ax.bar(range(len(ports)), counts, color='skyblue', edgecolor='navy', alpha=0.7)
        
        # Customize appearance
        ax.set_title(f'Top {top_n} Port Activity', fontsize=16, fontweight='bold')
        ax.set_xlabel('Port Number', fontsize=12)
        ax.set_ylabel('Packet Count', fontsize=12)
        
        # Set x-axis labels
        ax.set_xticks(range(len(ports)))
        ax.set_xticklabels(ports, rotation=45, ha='right')
        
        # Add value labels on bars
        for i, bar in enumerate(bars):
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height,
                   f'{int(height)}', ha='center', va='bottom', fontsize=8)
        
        # Add grid
        ax.grid(True, alpha=0.3, axis='y')
        
        plt.tight_layout()
        
        if not save_path:
            save_path = os.path.join(self.output_dir, 'port_activity.png')
        
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"Port activity chart saved to: {save_path}")
        return save_path
    
    def plot_ip_conversations(self, conversation_data: Dict[str, int], 
                            top_n: int = 15, save_path: Optional[str] = None) -> str:
        """
        Create a horizontal bar chart of IP conversations.
        
        Args:
            conversation_data: Dictionary mapping conversations to packet counts
            top_n: Number of top conversations to display
            save_path: Optional path to save the plot
            
        Returns:
            Path to saved plot
        """
        if not MATPLOTLIB_AVAILABLE:
            print("Matplotlib not available for plotting.")
            return ""
        
        # Get top N conversations
        sorted_convs = sorted(conversation_data.items(), key=lambda x: x[1], reverse=True)[:top_n]
        conversations, counts = zip(*sorted_convs) if sorted_convs else ([], [])
        
        fig, ax = plt.subplots(figsize=(12, 8))
        
        # Create horizontal bar chart
        y_pos = range(len(conversations))
        bars = ax.barh(y_pos, counts, color='lightcoral', edgecolor='darkred', alpha=0.7)
        
        # Customize appearance
        ax.set_title(f'Top {top_n} IP Conversations', fontsize=16, fontweight='bold')
        ax.set_xlabel('Packet Count', fontsize=12)
        ax.set_ylabel('IP Conversation', fontsize=12)
        
        # Set y-axis labels
        ax.set_yticks(y_pos)
        ax.set_yticklabels(conversations, fontsize=9)
        
        # Add value labels on bars
        for i, bar in enumerate(bars):
            width = bar.get_width()
            ax.text(width, bar.get_y() + bar.get_height()/2.,
                   f'{int(width)}', ha='left', va='center', fontsize=8)
        
        # Add grid
        ax.grid(True, alpha=0.3, axis='x')
        
        plt.tight_layout()
        
        if not save_path:
            save_path = os.path.join(self.output_dir, 'ip_conversations.png')
        
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"IP conversations chart saved to: {save_path}")
        return save_path
    
    def plot_packet_size_distribution(self, packet_sizes: List[int], 
                                    save_path: Optional[str] = None) -> str:
        """
        Create a histogram of packet size distribution.
        
        Args:
            packet_sizes: List of packet sizes
            save_path: Optional path to save the plot
            
        Returns:
            Path to saved plot
        """
        if not MATPLOTLIB_AVAILABLE or not NUMPY_AVAILABLE:
            print("Matplotlib and NumPy required for histogram plotting.")
            return ""
        
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
        
        # Histogram
        ax1.hist(packet_sizes, bins=50, color='lightgreen', edgecolor='darkgreen', alpha=0.7)
        ax1.set_title('Packet Size Distribution', fontsize=14, fontweight='bold')
        ax1.set_xlabel('Packet Size (bytes)', fontsize=12)
        ax1.set_ylabel('Frequency', fontsize=12)
        ax1.grid(True, alpha=0.3)
        
        # Box plot
        ax2.boxplot(packet_sizes, vert=True, patch_artist=True,
                   boxprops=dict(facecolor='lightblue', alpha=0.7))
        ax2.set_title('Packet Size Box Plot', fontsize=14, fontweight='bold')
        ax2.set_ylabel('Packet Size (bytes)', fontsize=12)
        ax2.grid(True, alpha=0.3)
        
        # Add statistics
        stats_text = f'Mean: {np.mean(packet_sizes):.1f}\n'
        stats_text += f'Median: {np.median(packet_sizes):.1f}\n'
        stats_text += f'Std Dev: {np.std(packet_sizes):.1f}'
        
        ax2.text(0.02, 0.98, stats_text, transform=ax2.transAxes, 
                verticalalignment='top', bbox=dict(boxstyle="round", facecolor='wheat', alpha=0.8))
        
        plt.tight_layout()
        
        if not save_path:
            save_path = os.path.join(self.output_dir, 'packet_size_distribution.png')
        
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"Packet size distribution plot saved to: {save_path}")
        return save_path
    
    def create_network_map(self, hosts_data: List[Dict[str, Any]], 
                          save_path: Optional[str] = None) -> str:
        """
        Create a simple network map visualization.
        
        Args:
            hosts_data: List of host information
            save_path: Optional path to save the plot
            
        Returns:
            Path to saved plot
        """
        if not MATPLOTLIB_AVAILABLE or not NUMPY_AVAILABLE:
            print("Matplotlib and NumPy required for network map.")
            return ""
        
        fig, ax = plt.subplots(figsize=(12, 10))
        
        # Generate positions for hosts
        n_hosts = len(hosts_data)
        if n_hosts == 0:
            print("No host data provided for network map.")
            return ""
        
        # Arrange hosts in a circle
        angles = np.linspace(0, 2*np.pi, n_hosts, endpoint=False)
        radius = 3
        
        x_positions = radius * np.cos(angles)
        y_positions = radius * np.sin(angles)
        
        # Plot hosts
        for i, host in enumerate(hosts_data):
            x, y = x_positions[i], y_positions[i]
            
            # Determine host type and color
            ip = host.get('ip', 'Unknown')
            hostname = host.get('hostname', '')
            
            if any(private in ip for private in ['192.168.', '10.', '172.']):
                color = 'lightblue'
                marker = 'o'
            else:
                color = 'lightcoral'
                marker = 's'
            
            # Plot host
            ax.scatter(x, y, s=200, c=color, marker=marker, edgecolors='black', linewidth=2)
            
            # Add label
            label = hostname if hostname else ip
            ax.annotate(label, (x, y), xytext=(5, 5), textcoords='offset points',
                       fontsize=8, ha='left')
        
        # Add central router/gateway representation
        ax.scatter(0, 0, s=300, c='gold', marker='D', edgecolors='black', linewidth=2)
        ax.annotate('Gateway', (0, 0), xytext=(5, 5), textcoords='offset points',
                   fontsize=10, ha='left', fontweight='bold')
        
        # Draw connections to gateway
        for i in range(n_hosts):
            ax.plot([0, x_positions[i]], [0, y_positions[i]], 'gray', alpha=0.5, linewidth=1)
        
        ax.set_title('Network Map', fontsize=16, fontweight='bold')
        ax.set_aspect('equal')
        ax.grid(True, alpha=0.3)
        
        # Remove axis ticks
        ax.set_xticks([])
        ax.set_yticks([])
        
        # Add legend
        from matplotlib.lines import Line2D
        legend_elements = [
            Line2D([0], [0], marker='o', color='w', markerfacecolor='lightblue', 
                  markersize=10, label='Private IP'),
            Line2D([0], [0], marker='s', color='w', markerfacecolor='lightcoral', 
                  markersize=10, label='Public IP'),
            Line2D([0], [0], marker='D', color='w', markerfacecolor='gold', 
                  markersize=12, label='Gateway')
        ]
        ax.legend(handles=legend_elements, loc='upper right')
        
        plt.tight_layout()
        
        if not save_path:
            save_path = os.path.join(self.output_dir, 'network_map.png')
        
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"Network map saved to: {save_path}")
        return save_path
    
    def create_comprehensive_dashboard(self, analysis_data: Dict[str, Any], 
                                     save_path: Optional[str] = None) -> str:
        """
        Create a comprehensive dashboard with multiple visualizations.
        
        Args:
            analysis_data: Complete analysis data
            save_path: Optional path to save the plot
            
        Returns:
            Path to saved plot
        """
        if not MATPLOTLIB_AVAILABLE:
            print("Matplotlib not available for dashboard creation.")
            return ""
        
        fig = plt.figure(figsize=(20, 12))
        
        # Protocol distribution (top-left)
        ax1 = plt.subplot(2, 3, 1)
        protocols = analysis_data.get('protocols', {})
        if protocols:
            ax1.pie(protocols.values(), labels=protocols.keys(), autopct='%1.1f%%')
            ax1.set_title('Protocol Distribution', fontweight='bold')
        
        # Top ports (top-middle)
        ax2 = plt.subplot(2, 3, 2)
        port_data = analysis_data.get('port_analysis', {})
        if port_data:
            top_ports = sorted(port_data.items(), key=lambda x: x[1], reverse=True)[:10]
            if top_ports:
                ports, counts = zip(*top_ports)
                ax2.bar(range(len(ports)), counts)
                ax2.set_xticks(range(len(ports)))
                ax2.set_xticklabels(ports, rotation=45)
                ax2.set_title('Top 10 Ports', fontweight='bold')
        
        # IP conversations (top-right)
        ax3 = plt.subplot(2, 3, 3)
        conversations = analysis_data.get('ip_conversations', {})
        if conversations:
            top_convs = sorted(conversations.items(), key=lambda x: x[1], reverse=True)[:8]
            if top_convs:
                conv_labels, conv_counts = zip(*top_convs)
                # Truncate long labels
                conv_labels = [label[:20] + '...' if len(label) > 20 else label 
                              for label in conv_labels]
                y_pos = range(len(conv_labels))
                ax3.barh(y_pos, conv_counts)
                ax3.set_yticks(y_pos)
                ax3.set_yticklabels(conv_labels, fontsize=8)
                ax3.set_title('Top IP Conversations', fontweight='bold')
        
        # HTTP hosts (bottom-left)
        ax4 = plt.subplot(2, 3, 4)
        http_data = analysis_data.get('http_analysis', {})
        if http_data and http_data.get('hosts'):
            top_hosts = http_data['hosts'].most_common(10)
            if top_hosts:
                hosts, counts = zip(*top_hosts)
                ax4.bar(range(len(hosts)), counts)
                ax4.set_xticks(range(len(hosts)))
                ax4.set_xticklabels([h[:15] + '...' if len(h) > 15 else h for h in hosts], 
                                   rotation=45, ha='right')
                ax4.set_title('Top HTTP Hosts', fontweight='bold')
        
        # DNS queries (bottom-middle)
        ax5 = plt.subplot(2, 3, 5)
        dns_data = analysis_data.get('dns_analysis', {})
        if dns_data and dns_data.get('domains'):
            top_domains = dns_data['domains'].most_common(8)
            if top_domains:
                domains, counts = zip(*top_domains)
                y_pos = range(len(domains))
                ax5.barh(y_pos, counts)
                ax5.set_yticks(y_pos)
                ax5.set_yticklabels([d[:20] + '...' if len(d) > 20 else d for d in domains], 
                                   fontsize=8)
                ax5.set_title('Top DNS Queries', fontweight='bold')
        
        # Summary statistics (bottom-right)
        ax6 = plt.subplot(2, 3, 6)
        ax6.axis('off')
        
        # Create summary text
        total_packets = analysis_data.get('total_packets', 0)
        summary_text = f"SUMMARY STATISTICS\n\n"
        summary_text += f"Total Packets: {total_packets:,}\n"
        summary_text += f"Protocols: {len(protocols)} types\n"
        summary_text += f"Unique IPs: {len(conversations)}\n"
        
        if http_data:
            summary_text += f"HTTP Requests: {len(http_data.get('requests', []))}\n"
        
        if dns_data:
            summary_text += f"DNS Queries: {len(dns_data.get('queries', []))}\n"
        
        ax6.text(0.1, 0.9, summary_text, transform=ax6.transAxes, fontsize=12,
                verticalalignment='top', bbox=dict(boxstyle="round", facecolor='lightgray', alpha=0.8))
        
        plt.suptitle('Network Traffic Analysis Dashboard', fontsize=20, fontweight='bold')
        plt.tight_layout()
        
        if not save_path:
            save_path = os.path.join(self.output_dir, 'dashboard.png')
        
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"Comprehensive dashboard saved to: {save_path}")
        return save_path
    
    def export_data_to_csv(self, data: Dict[str, Any], filename: str) -> str:
        """
        Export analysis data to CSV format.
        
        Args:
            data: Analysis data to export
            filename: Name of the CSV file
            
        Returns:
            Path to saved CSV file
        """
        if not PANDAS_AVAILABLE:
            print("Pandas not available for CSV export.")
            return ""
        
        csv_path = os.path.join(self.output_dir, filename)
        
        # Convert different data types to DataFrames and save
        if 'protocols' in data:
            protocols_df = pd.DataFrame(list(data['protocols'].items()), 
                                       columns=['Protocol', 'Count'])
            protocols_path = csv_path.replace('.csv', '_protocols.csv')
            protocols_df.to_csv(protocols_path, index=False)
            print(f"Protocol data exported to: {protocols_path}")
        
        if 'ip_conversations' in data:
            convs_df = pd.DataFrame(list(data['ip_conversations'].items()), 
                                   columns=['Conversation', 'Count'])
            convs_path = csv_path.replace('.csv', '_conversations.csv')
            convs_df.to_csv(convs_path, index=False)
            print(f"Conversation data exported to: {convs_path}")
        
        return csv_path


def main():
    """Example usage of NetworkVisualizer."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Network Data Visualization')
    parser.add_argument('--demo', action='store_true', help='Generate demo visualizations')
    parser.add_argument('--data-file', help='JSON file containing analysis data')
    
    args = parser.parse_args()
    
    visualizer = NetworkVisualizer()
    
    if args.demo:
        # Generate demo data
        demo_protocols = {'TCP': 1500, 'UDP': 800, 'HTTP': 600, 'DNS': 400, 'SSH': 200}
        demo_ports = {80: 600, 443: 500, 22: 200, 53: 400, 21: 100, 25: 150}
        demo_conversations = {
            '192.168.1.100 -> 8.8.8.8': 300,
            '192.168.1.101 -> 142.250.191.14': 250,
            '192.168.1.102 -> 151.101.65.140': 200,
            '192.168.1.100 -> 172.217.164.110': 180
        }
        demo_hosts = [
            {'ip': '192.168.1.100', 'hostname': 'desktop-01'},
            {'ip': '192.168.1.101', 'hostname': 'laptop-02'},
            {'ip': '8.8.8.8', 'hostname': 'dns.google'},
            {'ip': '142.250.191.14', 'hostname': 'google.com'}
        ]
        
        print("Generating demo visualizations...")
        visualizer.plot_protocol_distribution(demo_protocols)
        visualizer.plot_port_activity(demo_ports)
        visualizer.plot_ip_conversations(demo_conversations)
        visualizer.create_network_map(demo_hosts)
        
        # Create demo packet sizes
        if NUMPY_AVAILABLE:
            demo_sizes = np.random.normal(800, 200, 1000).astype(int)
            demo_sizes = np.clip(demo_sizes, 64, 1500)
            visualizer.plot_packet_size_distribution(demo_sizes.tolist())
    
    elif args.data_file:
        try:
            with open(args.data_file, 'r') as f:
                data = json.load(f)
            
            print(f"Creating visualizations from {args.data_file}...")
            visualizer.create_comprehensive_dashboard(data)
            
            if 'protocols' in data:
                visualizer.plot_protocol_distribution(data['protocols'])
            
            if 'port_analysis' in data:
                visualizer.plot_port_activity(data['port_analysis'])
        
        except Exception as e:
            print(f"Error processing data file: {e}")


if __name__ == "__main__":
    main()
