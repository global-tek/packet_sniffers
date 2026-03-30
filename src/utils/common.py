"""
Utility Functions Module

Common utilities and helper functions for the packet sniffing toolkit.
"""

import os
import json
import yaml
import time
import socket
import subprocess
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union, Tuple
import logging
import hashlib

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ConfigManager:
    """
    Configuration management for the packet sniffing toolkit.
    """
    
    def __init__(self, config_dir: str = "config"):
        """
        Initialize the configuration manager.
        
        Args:
            config_dir: Directory containing configuration files
        """
        self.config_dir = config_dir
        os.makedirs(config_dir, exist_ok=True)
        self.config = {}
        
    def load_config(self, config_file: str = "default.yaml") -> Dict[str, Any]:
        """
        Load configuration from file.
        
        Args:
            config_file: Configuration file name
            
        Returns:
            Configuration dictionary
        """
        config_path = os.path.join(self.config_dir, config_file)
        
        try:
            if config_file.endswith('.yaml') or config_file.endswith('.yml'):
                with open(config_path, 'r') as f:
                    self.config = yaml.safe_load(f)
            elif config_file.endswith('.json'):
                with open(config_path, 'r') as f:
                    self.config = json.load(f)
            else:
                logger.error(f"Unsupported config file format: {config_file}")
                return {}
                
            logger.info(f"Configuration loaded from {config_path}")
            return self.config
            
        except FileNotFoundError:
            logger.warning(f"Config file not found: {config_path}")
            return self._create_default_config(config_path)
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            return {}
    
    def _create_default_config(self, config_path: str) -> Dict[str, Any]:
        """Create default configuration file."""
        default_config = {
            'capture': {
                'interface': 'auto',
                'buffer_size': 65536,
                'timeout': 1000,
                'promiscuous_mode': True,
                'capture_filter': '',
                'max_packets': 0
            },
            'analysis': {
                'deep_inspection': True,
                'protocol_analysis': True,
                'suspicious_pattern_detection': True,
                'export_format': 'json'
            },
            'scanning': {
                'ping_timeout': 3,
                'port_scan_timeout': 1,
                'max_threads': 100,
                'common_ports_only': False
            },
            'visualization': {
                'output_dir': 'visualizations',
                'image_format': 'png',
                'dpi': 300,
                'style': 'default'
            },
            'logging': {
                'level': 'INFO',
                'log_file': 'packet_sniffer.log',
                'max_file_size': '10MB',
                'backup_count': 5
            },
            'security': {
                'require_admin': True,
                'allowed_interfaces': [],
                'blocked_networks': [],
                'encryption_analysis': True
            }
        }
        
        try:
            if config_path.endswith('.yaml') or config_path.endswith('.yml'):
                with open(config_path, 'w') as f:
                    yaml.dump(default_config, f, default_flow_style=False, indent=2)
            else:
                with open(config_path, 'w') as f:
                    json.dump(default_config, f, indent=2)
            
            logger.info(f"Default configuration created at {config_path}")
            return default_config
            
        except Exception as e:
            logger.error(f"Error creating default config: {e}")
            return default_config
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value using dot notation.
        
        Args:
            key: Configuration key (e.g., 'capture.interface')
            default: Default value if key not found
            
        Returns:
            Configuration value
        """
        keys = key.split('.')
        value = self.config
        
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default
    
    def set(self, key: str, value: Any):
        """
        Set configuration value using dot notation.
        
        Args:
            key: Configuration key (e.g., 'capture.interface')
            value: Value to set
        """
        keys = key.split('.')
        config = self.config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
    
    def save_config(self, config_file: str = "default.yaml"):
        """Save current configuration to file."""
        config_path = os.path.join(self.config_dir, config_file)
        
        try:
            if config_file.endswith('.yaml') or config_file.endswith('.yml'):
                with open(config_path, 'w') as f:
                    yaml.dump(self.config, f, default_flow_style=False, indent=2)
            else:
                with open(config_path, 'w') as f:
                    json.dump(self.config, f, indent=2)
            
            logger.info(f"Configuration saved to {config_path}")
            
        except Exception as e:
            logger.error(f"Error saving config: {e}")


class NetworkUtils:
    """
    Network utility functions.
    """
    
    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """
        Check if an IP address is private.
        
        Args:
            ip: IP address string
            
        Returns:
            True if IP is private, False otherwise
        """
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except Exception:
            # Fallback method
            private_ranges = [
                '10.', '172.16.', '172.17.', '172.18.', '172.19.',
                '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
                '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
                '172.30.', '172.31.', '192.168.', '127.', '169.254.'
            ]
            return any(ip.startswith(prefix) for prefix in private_ranges)
    
    @staticmethod
    def get_local_ip() -> str:
        """
        Get the local IP address.
        
        Returns:
            Local IP address
        """
        try:
            # Connect to a remote address to determine local IP
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            return "127.0.0.1"
    
    @staticmethod
    def get_default_gateway() -> Optional[str]:
        """
        Get the default gateway IP address.
        
        Returns:
            Default gateway IP or None
        """
        try:
            # For macOS and Linux
            result = subprocess.run(['route', '-n', 'get', 'default'], 
                                  capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'gateway:' in line:
                        return line.split(':')[1].strip()
            
            # Alternative method
            result = subprocess.run(['netstat', '-rn'], 
                                  capture_output=True, text=True, timeout=5)
            
            for line in result.stdout.split('\n'):
                if line.startswith('0.0.0.0') or line.startswith('default'):
                    parts = line.split()
                    if len(parts) > 1:
                        return parts[1]
            
        except Exception as e:
            logger.error(f"Error getting default gateway: {e}")
        
        return None
    
    @staticmethod
    def get_network_interfaces() -> List[Dict[str, str]]:
        """
        Get available network interfaces.
        
        Returns:
            List of interface information
        """
        interfaces = []
        
        try:
            result = subprocess.run(['ifconfig'], capture_output=True, text=True, timeout=10)
            
            current_interface = None
            for line in result.stdout.split('\n'):
                line = line.strip()
                
                # New interface
                if line and not line.startswith('\t') and ':' in line:
                    if current_interface:
                        interfaces.append(current_interface)
                    
                    interface_name = line.split(':')[0]
                    current_interface = {
                        'name': interface_name,
                        'ip': '',
                        'mac': '',
                        'status': 'unknown'
                    }
                
                # IP address
                elif current_interface and 'inet ' in line:
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part == 'inet' and i + 1 < len(parts):
                            current_interface['ip'] = parts[i + 1]
                            break
                
                # MAC address
                elif current_interface and 'ether ' in line:
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part == 'ether' and i + 1 < len(parts):
                            current_interface['mac'] = parts[i + 1]
                            break
                
                # Status
                elif current_interface and 'status:' in line:
                    status = line.split('status:')[1].strip()
                    current_interface['status'] = status
            
            # Add the last interface
            if current_interface:
                interfaces.append(current_interface)
        
        except Exception as e:
            logger.error(f"Error getting network interfaces: {e}")
        
        return interfaces
    
    @staticmethod
    def validate_ip(ip: str) -> bool:
        """
        Validate IP address format.
        
        Args:
            ip: IP address string
            
        Returns:
            True if valid, False otherwise
        """
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False
    
    @staticmethod
    def validate_port(port: Union[str, int]) -> bool:
        """
        Validate port number.
        
        Args:
            port: Port number
            
        Returns:
            True if valid, False otherwise
        """
        try:
            port_num = int(port)
            return 1 <= port_num <= 65535
        except (ValueError, TypeError):
            return False


class DataExporter:
    """
    Export analysis data to various formats.
    """
    
    def __init__(self, output_dir: str = "exports"):
        """
        Initialize the data exporter.
        
        Args:
            output_dir: Directory for exported files
        """
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
    
    def export_to_json(self, data: Dict[str, Any], filename: str) -> str:
        """
        Export data to JSON format.
        
        Args:
            data: Data to export
            filename: Output filename
            
        Returns:
            Path to exported file
        """
        filepath = os.path.join(self.output_dir, filename)
        
        try:
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            
            logger.info(f"Data exported to JSON: {filepath}")
            return filepath
            
        except Exception as e:
            logger.error(f"Error exporting to JSON: {e}")
            return ""
    
    def export_to_csv(self, data: List[Dict[str, Any]], filename: str) -> str:
        """
        Export data to CSV format.
        
        Args:
            data: List of dictionaries to export
            filename: Output filename
            
        Returns:
            Path to exported file
        """
        filepath = os.path.join(self.output_dir, filename)
        
        try:
            if not data:
                logger.warning("No data to export to CSV")
                return ""
            
            # Get all unique keys
            all_keys = set()
            for item in data:
                all_keys.update(item.keys())
            
            # Write CSV
            with open(filepath, 'w', newline='') as f:
                import csv
                writer = csv.DictWriter(f, fieldnames=sorted(all_keys))
                writer.writeheader()
                writer.writerows(data)
            
            logger.info(f"Data exported to CSV: {filepath}")
            return filepath
            
        except Exception as e:
            logger.error(f"Error exporting to CSV: {e}")
            return ""
    
    def export_to_xml(self, data: Dict[str, Any], filename: str, root_name: str = "data") -> str:
        """
        Export data to XML format.
        
        Args:
            data: Data to export
            filename: Output filename
            root_name: Root element name
            
        Returns:
            Path to exported file
        """
        filepath = os.path.join(self.output_dir, filename)
        
        try:
            import xml.etree.ElementTree as ET
            
            def dict_to_xml(parent, data):
                if isinstance(data, dict):
                    for key, value in data.items():
                        elem = ET.SubElement(parent, str(key))
                        dict_to_xml(elem, value)
                elif isinstance(data, list):
                    for item in data:
                        elem = ET.SubElement(parent, "item")
                        dict_to_xml(elem, item)
                else:
                    parent.text = str(data)
            
            root = ET.Element(root_name)
            dict_to_xml(root, data)
            
            tree = ET.ElementTree(root)
            tree.write(filepath, encoding='utf-8', xml_declaration=True)
            
            logger.info(f"Data exported to XML: {filepath}")
            return filepath
            
        except Exception as e:
            logger.error(f"Error exporting to XML: {e}")
            return ""


class PerformanceMonitor:
    """
    Monitor performance metrics during packet capture and analysis.
    """
    
    def __init__(self):
        """Initialize the performance monitor."""
        self.start_time = None
        self.metrics = {
            'packets_processed': 0,
            'bytes_processed': 0,
            'processing_time': 0,
            'memory_usage': 0,
            'cpu_usage': 0
        }
    
    def start_monitoring(self):
        """Start performance monitoring."""
        self.start_time = time.time()
        self.metrics = {key: 0 for key in self.metrics}
        logger.info("Performance monitoring started")
    
    def update_packet_stats(self, packet_count: int, byte_count: int):
        """
        Update packet processing statistics.
        
        Args:
            packet_count: Number of packets processed
            byte_count: Number of bytes processed
        """
        self.metrics['packets_processed'] += packet_count
        self.metrics['bytes_processed'] += byte_count
    
    def get_processing_rate(self) -> Tuple[float, float]:
        """
        Get current processing rates.
        
        Returns:
            Tuple of (packets per second, bytes per second)
        """
        if not self.start_time:
            return 0.0, 0.0
        
        elapsed = time.time() - self.start_time
        if elapsed == 0:
            return 0.0, 0.0
        
        pps = self.metrics['packets_processed'] / elapsed
        bps = self.metrics['bytes_processed'] / elapsed
        
        return pps, bps
    
    def get_memory_usage(self) -> float:
        """
        Get current memory usage in MB.
        
        Returns:
            Memory usage in megabytes
        """
        try:
            import psutil
            process = psutil.Process()
            memory_info = process.memory_info()
            return memory_info.rss / 1024 / 1024  # Convert to MB
        except ImportError:
            return 0.0
    
    def generate_performance_report(self) -> Dict[str, Any]:
        """
        Generate performance report.
        
        Returns:
            Performance metrics dictionary
        """
        if self.start_time:
            elapsed = time.time() - self.start_time
            pps, bps = self.get_processing_rate()
            
            return {
                'elapsed_time': elapsed,
                'packets_processed': self.metrics['packets_processed'],
                'bytes_processed': self.metrics['bytes_processed'],
                'packets_per_second': pps,
                'bytes_per_second': bps,
                'memory_usage_mb': self.get_memory_usage(),
                'average_packet_size': (self.metrics['bytes_processed'] / 
                                      self.metrics['packets_processed'] 
                                      if self.metrics['packets_processed'] > 0 else 0)
            }
        
        return {}


class SecurityUtils:
    """
    Security-related utility functions.
    """
    
    @staticmethod
    def require_admin() -> bool:
        """
        Check if running with administrative privileges.
        
        Returns:
            True if running as admin, False otherwise
        """
        try:
            import os
            return os.geteuid() == 0
        except AttributeError:
            # Windows
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    
    @staticmethod
    def hash_sensitive_data(data: str, algorithm: str = 'sha256') -> str:
        """
        Hash sensitive data for logging/storage.
        
        Args:
            data: Data to hash
            algorithm: Hash algorithm to use
            
        Returns:
            Hexadecimal hash string
        """
        hash_obj = hashlib.new(algorithm)
        hash_obj.update(data.encode('utf-8'))
        return hash_obj.hexdigest()
    
    @staticmethod
    def validate_network_range(network: str) -> bool:
        """
        Validate network range format (CIDR notation).
        
        Args:
            network: Network range (e.g., "192.168.1.0/24")
            
        Returns:
            True if valid, False otherwise
        """
        try:
            import ipaddress
            ipaddress.ip_network(network, strict=False)
            return True
        except Exception:
            return False
    
    @staticmethod
    def is_allowed_interface(interface: str, allowed_list: List[str]) -> bool:
        """
        Check if interface is in allowed list.
        
        Args:
            interface: Interface name
            allowed_list: List of allowed interfaces
            
        Returns:
            True if allowed, False otherwise
        """
        if not allowed_list:  # Empty list means all interfaces allowed
            return True
        
        return interface in allowed_list


def setup_logging(config: Dict[str, Any]):
    """
    Set up logging configuration.
    
    Args:
        config: Logging configuration dictionary
    """
    log_level = getattr(logging, config.get('level', 'INFO').upper())
    log_file = config.get('log_file', 'packet_sniffer.log')
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Set up file handler
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        file_handler.setLevel(log_level)
        
        # Add rotation if supported
        try:
            from logging.handlers import RotatingFileHandler
            max_size = config.get('max_file_size', '10MB')
            size_bytes = int(max_size.replace('MB', '')) * 1024 * 1024
            backup_count = config.get('backup_count', 5)
            
            file_handler = RotatingFileHandler(
                log_file, maxBytes=size_bytes, backupCount=backup_count
            )
            file_handler.setFormatter(formatter)
            file_handler.setLevel(log_level)
        except ImportError:
            pass
        
        logging.getLogger().addHandler(file_handler)
    
    # Set up console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(log_level)
    
    logging.getLogger().addHandler(console_handler)
    logging.getLogger().setLevel(log_level)


def main():
    """Example usage of utility functions."""
    # Demo configuration management
    config_manager = ConfigManager()
    config = config_manager.load_config()
    
    print("Configuration loaded:")
    print(f"Default interface: {config_manager.get('capture.interface')}")
    print(f"Buffer size: {config_manager.get('capture.buffer_size')}")
    
    # Demo network utilities
    print(f"\nLocal IP: {NetworkUtils.get_local_ip()}")
    print(f"Default Gateway: {NetworkUtils.get_default_gateway()}")
    print(f"Is 192.168.1.1 private? {NetworkUtils.is_private_ip('192.168.1.1')}")
    
    # Demo performance monitoring
    perf_monitor = PerformanceMonitor()
    perf_monitor.start_monitoring()
    perf_monitor.update_packet_stats(100, 50000)
    
    print(f"\nProcessing rate: {perf_monitor.get_processing_rate()}")
    print(f"Performance report: {perf_monitor.generate_performance_report()}")


if __name__ == "__main__":
    main()
