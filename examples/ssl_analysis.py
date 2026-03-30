#!/usr/bin/env python3
"""
SSL/TLS Analysis Example

This script demonstrates SSL/TLS traffic analysis and certificate extraction.
"""

import sys
import os

# Add the src directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from decryption.traffic_decryptor import TrafficDecryptor


def main():
    """SSL/TLS analysis example."""
    print("SSL/TLS Analysis Example")
    print("=" * 40)
    
    # Initialize traffic decryptor
    decryptor = TrafficDecryptor()
    
    # Example 1: Extract certificate chain from a website
    print("Example 1: Extracting certificate chain...")
    
    test_hosts = [
        ("google.com", 443),
        ("github.com", 443),
        ("stackoverflow.com", 443)
    ]
    
    for host, port in test_hosts:
        try:
            print(f"\nExtracting certificates from {host}:{port}...")
            certificates = decryptor.extract_certificate_chain(host, port)
            
            if certificates:
                print(f"Found {len(certificates)} certificates:")
                for i, cert in enumerate(certificates):
                    print(f"\nCertificate {i + 1}:")
                    
                    subject = cert.get('subject', {})
                    issuer = cert.get('issuer', {})
                    
                    # Handle both dict and bytes keys
                    cn = None
                    for key in [b'CN', 'CN']:
                        if key in subject:
                            cn = subject[key]
                            break
                    
                    issuer_cn = None
                    for key in [b'CN', 'CN']:
                        if key in issuer:
                            issuer_cn = issuer[key]
                            break
                    
                    print(f"  Subject CN: {cn}")
                    print(f"  Issuer CN: {issuer_cn}")
                    print(f"  Valid From: {cert.get('not_before', 'Unknown')}")
                    print(f"  Valid To: {cert.get('not_after', 'Unknown')}")
                    print(f"  Signature Algorithm: {cert.get('signature_algorithm', 'Unknown')}")
                    print(f"  Fingerprint: {cert.get('fingerprint_sha256', 'Unknown')}")
            else:
                print(f"  No certificates found or connection failed.")
                
        except Exception as e:
            print(f"  Error: {e}")
    
    # Example 2: Demonstrate SSL/TLS traffic analysis (simulated)
    print("\n\nExample 2: SSL/TLS Traffic Analysis...")
    
    # Simulate some SSL/TLS handshake data (this would normally come from packet capture)
    print("Note: In a real scenario, this data would come from captured packets.")
    
    # Example TLS Client Hello packet data (simplified for demonstration)
    # This is just an example - real packet data would be much more complex
    sample_tls_data = bytes([
        0x16,  # Content Type: Handshake
        0x03, 0x03,  # Version: TLS 1.2
        0x00, 0x20,  # Length
        0x01,  # Handshake Type: Client Hello
        0x00, 0x00, 0x1C,  # Length
        0x03, 0x03,  # Version: TLS 1.2
        # Random (32 bytes) - simplified
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        0x00,  # Session ID Length
        0x00, 0x02,  # Cipher Suites Length
        0x00, 0x2F,  # Cipher Suite: AES128-SHA
        0x01,  # Compression Methods Length
        0x00   # Compression Method: null
    ])
    
    # Analyze the sample data
    ssl_analysis = decryptor.analyze_ssl_tls_traffic(sample_tls_data)
    
    print("Sample SSL/TLS analysis results:")
    print(f"  Is SSL/TLS: {ssl_analysis['is_ssl_tls']}")
    print(f"  Version: {ssl_analysis.get('version', 'Unknown')}")
    print(f"  Message Type: {ssl_analysis.get('message_type', 'Unknown')}")
    
    # Example 3: Generate encryption analysis report
    print("\n\nExample 3: Encryption Analysis Report...")
    
    # Simulate analysis data
    analysis_data = {
        'total_packets': 150,
        'ssl_tls_sessions': {
            'google.com': [ssl_analysis],
            'github.com': [{'is_ssl_tls': True, 'version': 'TLS 1.3'}]
        },
        'ssh_sessions': {
            'ssh_session_1': {'is_ssh': True, 'version': 'SSH-2.0-OpenSSH_8.0'}
        },
        'size_patterns': {
            'min_size': 64,
            'max_size': 1500,
            'avg_size': 642.5,
            'size_distribution': {
                'tiny': 20,
                'small': 45,
                'medium': 70,
                'large': 15
            }
        }
    }
    
    # Generate report
    report = decryptor.generate_encryption_report(analysis_data)
    print(report)
    
    # Save report to file
    os.makedirs("analysis", exist_ok=True)
    with open("analysis/encryption_report.txt", "w") as f:
        f.write(report)
    
    print("\nEncryption analysis report saved to: analysis/encryption_report.txt")


if __name__ == "__main__":
    main()
