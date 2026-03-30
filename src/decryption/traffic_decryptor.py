"""
Traffic Decryption Module

Tools for analyzing encrypted traffic and extracting metadata.
Note: Performs metadata analysis only — no traffic decryption without keys.
"""

import base64
import hashlib
import logging
import ssl
import socket
import struct
import re
from datetime import datetime
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

try:
    from cryptography import x509 as _x509
    from cryptography.hazmat.backends import default_backend as _default_backend
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.fernet import Fernet
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False


class TrafficDecryptor:
    """
    Metadata analysis for encrypted network traffic.
    Supports TLS/SSL handshake inspection, SSH version detection,
    and certificate chain extraction using the cryptography library.
    """

    def __init__(self):
        self.ssl_sessions: Dict[str, Any] = {}
        self.encryption_stats = {
            'total_encrypted_packets': 0,
            'ssl_tls_packets': 0,
            'ssh_packets': 0,
            'unknown_encrypted': 0,
        }

    # ------------------------------------------------------------------
    # SSL/TLS handshake analysis
    # ------------------------------------------------------------------

    def analyze_ssl_tls_traffic(self, packet_data: bytes) -> Dict[str, Any]:
        """
        Analyse raw packet bytes for SSL/TLS metadata.

        Returns: is_ssl_tls, version, cipher_suite, server_name, certificate_info, session_info
        """
        analysis: Dict[str, Any] = {
            'is_ssl_tls':        False,
            'version':           None,
            'cipher_suite':      None,
            'server_name':       None,
            'certificate_info':  {},
            'session_info':      {},
        }

        try:
            if len(packet_data) < 5:
                return analysis

            content_type = packet_data[0]
            version_int  = (packet_data[1] << 8) | packet_data[2]

            # TLS content types: 20=ChangeCipher 21=Alert 22=Handshake 23=AppData
            if content_type in (20, 21, 22, 23):
                analysis['is_ssl_tls'] = True
                analysis['version']    = self._parse_tls_version(version_int)

                if content_type == 22:
                    hs = self._analyze_tls_handshake(packet_data[5:])
                    analysis.update(hs)

        except Exception as e:
            logger.debug(f"SSL/TLS analysis error: {e}")

        return analysis

    def _parse_tls_version(self, version: int) -> str:
        return {
            0x0300: 'SSL 3.0',
            0x0301: 'TLS 1.0',
            0x0302: 'TLS 1.1',
            0x0303: 'TLS 1.2',
            0x0304: 'TLS 1.3',
        }.get(version, f'Unknown (0x{version:04x})')

    def _analyze_tls_handshake(self, data: bytes) -> Dict[str, Any]:
        analysis: Dict[str, Any] = {}
        if len(data) < 4:
            return analysis

        try:
            msg_type   = data[0]
            msg_length = (data[1] << 16) | (data[2] << 8) | data[3]
            body       = data[4:4 + msg_length]

            if msg_type == 1:
                analysis['message_type'] = 'Client Hello'
                analysis.update(self._parse_client_hello(body))
            elif msg_type == 2:
                analysis['message_type'] = 'Server Hello'
                analysis.update(self._parse_server_hello(body))
            elif msg_type == 11:
                analysis['message_type']    = 'Certificate'
                analysis['certificate_info'] = self._parse_certificate_message(body)
        except Exception as e:
            logger.debug(f"TLS handshake parse error: {e}")

        return analysis

    def _parse_client_hello(self, data: bytes) -> Dict[str, Any]:
        info: Dict[str, Any] = {}
        try:
            if len(data) < 34:
                return info
            pos = 34  # skip version(2) + random(32)

            if pos < len(data):
                sid_len = data[pos]
                pos += 1 + sid_len

            if pos + 2 <= len(data):
                cs_len = (data[pos] << 8) | data[pos + 1]
                pos += 2
                suites = []
                for i in range(0, cs_len, 2):
                    if pos + i + 1 < len(data):
                        cs = (data[pos + i] << 8) | data[pos + i + 1]
                        suites.append(f'0x{cs:04x}')
                info['cipher_suites'] = suites[:10]
                pos += cs_len

            # compression methods
            if pos < len(data):
                cm_len = data[pos]
                pos += 1 + cm_len

            if pos + 2 <= len(data):
                ext_len = (data[pos] << 8) | data[pos + 1]
                pos += 2
                info.update(self._parse_extensions(data[pos:pos + ext_len]))

        except Exception as e:
            logger.debug(f"Client Hello parse error: {e}")
        return info

    def _parse_server_hello(self, data: bytes) -> Dict[str, Any]:
        info: Dict[str, Any] = {}
        try:
            if len(data) < 34:
                return info
            pos = 34

            if pos < len(data):
                sid_len = data[pos]
                pos += 1 + sid_len

            if pos + 2 <= len(data):
                cs = (data[pos] << 8) | data[pos + 1]
                info['selected_cipher_suite'] = f'0x{cs:04x}'
                pos += 2

            if pos < len(data):
                info['compression_method'] = data[pos]
                pos += 1

            if pos + 2 <= len(data):
                ext_len = (data[pos] << 8) | data[pos + 1]
                pos += 2
                info.update(self._parse_extensions(data[pos:pos + ext_len]))

        except Exception as e:
            logger.debug(f"Server Hello parse error: {e}")
        return info

    def _parse_extensions(self, ext_data: bytes) -> Dict[str, Any]:
        extensions: Dict[str, Any] = {}
        pos = 0

        try:
            while pos + 4 <= len(ext_data):
                ext_type = (ext_data[pos] << 8) | ext_data[pos + 1]
                ext_len  = (ext_data[pos + 2] << 8) | ext_data[pos + 3]
                pos += 4
                body = ext_data[pos:pos + ext_len]

                # SNI (type 0)
                if ext_type == 0 and len(body) > 5:
                    if body[2] == 0:  # hostname type
                        name_len = (body[3] << 8) | body[4]
                        if 5 + name_len <= len(body):
                            extensions['server_name'] = (
                                body[5:5 + name_len].decode('utf-8', errors='ignore')
                            )

                # ALPN (type 16)
                elif ext_type == 16 and len(body) > 2:
                    protocols = []
                    ap = 2
                    while ap < len(body):
                        plen = body[ap]
                        ap += 1
                        if ap + plen <= len(body):
                            protocols.append(
                                body[ap:ap + plen].decode('utf-8', errors='ignore')
                            )
                            ap += plen
                        else:
                            break
                    if protocols:
                        extensions['alpn_protocols'] = protocols

                pos += ext_len

        except Exception as e:
            logger.debug(f"Extension parse error: {e}")

        return extensions

    def _parse_certificate_message(self, data: bytes) -> Dict[str, Any]:
        cert_info: Dict[str, Any] = {}
        try:
            if len(data) < 3:
                return cert_info
            pos = 3  # skip 3-byte chain length
            certs = []

            while pos + 3 <= len(data) and len(certs) < 5:
                cert_len = (data[pos] << 16) | (data[pos + 1] << 8) | data[pos + 2]
                pos += 3
                if pos + cert_len > len(data):
                    break
                cert_der = data[pos:pos + cert_len]
                certs.append(self._parse_cert_der(cert_der))
                pos += cert_len

            cert_info['certificates'] = certs
        except Exception as e:
            logger.debug(f"Certificate message parse error: {e}")
        return cert_info

    # ------------------------------------------------------------------
    # Certificate parsing (uses cryptography library when available)
    # ------------------------------------------------------------------

    def _parse_cert_der(self, cert_der: bytes) -> Dict[str, Any]:
        """Parse a DER-encoded certificate using the cryptography library."""
        info: Dict[str, Any] = {
            'length':            len(cert_der),
            'fingerprint_sha256': hashlib.sha256(cert_der).hexdigest(),
        }

        if not CRYPTO_AVAILABLE:
            return info

        try:
            cert = _x509.load_der_x509_certificate(cert_der, _default_backend())

            def _get_cn(name) -> Optional[str]:
                try:
                    return name.get_attributes_for_oid(
                        _x509.oid.NameOID.COMMON_NAME
                    )[0].value
                except (IndexError, Exception):
                    return None

            info['subject_cn'] = _get_cn(cert.subject)
            info['issuer_cn']  = _get_cn(cert.issuer)
            info['serial_number'] = str(cert.serial_number)
            info['version']    = cert.version.name

            # Support both old and new cryptography API
            try:
                info['not_before'] = cert.not_valid_before_utc.isoformat()
                info['not_after']  = cert.not_valid_after_utc.isoformat()
            except AttributeError:
                info['not_before'] = cert.not_valid_before.isoformat()
                info['not_after']  = cert.not_valid_after.isoformat()

            try:
                san_ext = cert.extensions.get_extension_for_oid(
                    _x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                )
                info['san'] = [str(n) for n in san_ext.value]
            except Exception:
                info['san'] = []

        except Exception as e:
            logger.debug(f"DER cert parse error: {e}")

        return info

    # ------------------------------------------------------------------
    # Certificate chain extraction (live connection)
    # ------------------------------------------------------------------

    def extract_certificate_chain(self, host: str, port: int = 443) -> List[Dict[str, Any]]:
        """
        Connect to host:port and extract the server's certificate chain.

        Uses Python ssl (stdlib) + cryptography for rich parsing.
        Works on Python 3.8+ without any non-stdlib dependencies.
        """
        certificates: List[Dict[str, Any]] = []

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    # Leaf certificate
                    cert_der = ssock.getpeercert(binary_form=True)
                    if cert_der:
                        certificates.append(self._parse_cert_der(cert_der))

                    # Full verified chain (Python ≥ 3.10)
                    if hasattr(ssock, 'get_verified_chain'):
                        chain = ssock.get_verified_chain()
                        for chain_cert in chain[1:]:  # skip leaf already added
                            try:
                                certificates.append(
                                    self._parse_cert_der(bytes(chain_cert))
                                )
                            except Exception:
                                pass

        except ssl.SSLError as e:
            logger.warning(f"SSL error connecting to {host}:{port}: {e}")
        except OSError as e:
            logger.warning(f"Network error connecting to {host}:{port}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error extracting cert chain from {host}:{port}: {e}")

        return certificates

    # ------------------------------------------------------------------
    # SSH traffic detection
    # ------------------------------------------------------------------

    def detect_ssh_traffic(self, packet_data: bytes) -> Dict[str, Any]:
        """
        Detect SSH banner and extract version string.
        """
        analysis: Dict[str, Any] = {
            'is_ssh':           False,
            'version':          None,
            'protocol_version': None,
            'software_version': None,
        }

        try:
            if packet_data.startswith(b'SSH-'):
                analysis['is_ssh'] = True
                nl = packet_data.find(b'\n')
                version_line = packet_data[: nl if nl > 0 else 64].decode(
                    'utf-8', errors='ignore'
                ).strip()
                analysis['version'] = version_line

                parts = version_line.split('-', 2)
                if len(parts) >= 3:
                    analysis['protocol_version'] = parts[1]
                    analysis['software_version'] = parts[2]

        except Exception as e:
            logger.debug(f"SSH detection error: {e}")

        return analysis

    # ------------------------------------------------------------------
    # Bulk metadata analysis
    # ------------------------------------------------------------------

    def analyze_encrypted_metadata(self, packets: List[bytes]) -> Dict[str, Any]:
        """
        Analyse metadata from a list of raw packet payloads.
        Does NOT decrypt content.
        """
        metadata: Dict[str, Any] = {
            'total_packets':    len(packets),
            'ssl_tls_sessions': {},
            'ssh_sessions':     {},
            'size_patterns':    {},
        }

        ssl_sessions: Dict[str, Any] = {}
        ssh_sessions: Dict[str, Any] = {}
        sizes: List[int] = []

        for packet_data in packets:
            sizes.append(len(packet_data))

            ssl_result = self.analyze_ssl_tls_traffic(packet_data)
            if ssl_result['is_ssl_tls']:
                key = ssl_result.get('server_name') or f'session_{len(ssl_sessions)}'
                ssl_sessions.setdefault(key, []).append(ssl_result)

            ssh_result = self.detect_ssh_traffic(packet_data)
            if ssh_result['is_ssh']:
                key = f'ssh_{len(ssh_sessions)}'
                ssh_sessions[key] = ssh_result

        metadata['ssl_tls_sessions'] = ssl_sessions
        metadata['ssh_sessions']     = ssh_sessions

        if sizes:
            metadata['size_patterns'] = {
                'min_size': min(sizes),
                'max_size': max(sizes),
                'avg_size': sum(sizes) / len(sizes),
                'distribution': self._size_distribution(sizes),
            }

        return metadata

    def _size_distribution(self, sizes: List[int]) -> Dict[str, int]:
        d = {'tiny': 0, 'small': 0, 'medium': 0, 'large': 0}
        for s in sizes:
            if s <= 64:
                d['tiny'] += 1
            elif s <= 512:
                d['small'] += 1
            elif s <= 1500:
                d['medium'] += 1
            else:
                d['large'] += 1
        return d

    # ------------------------------------------------------------------
    # Report
    # ------------------------------------------------------------------

    def generate_encryption_report(self, analysis_data: Dict[str, Any]) -> str:
        lines = [
            '=' * 60,
            'ENCRYPTED TRAFFIC ANALYSIS REPORT',
            '=' * 60,
            f"Generated:             {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Total Packets:         {analysis_data['total_packets']}",
            '',
        ]

        ssl_sessions = analysis_data.get('ssl_tls_sessions', {})
        if ssl_sessions:
            lines += ['SSL/TLS SESSIONS', '-' * 30]
            for name, data in ssl_sessions.items():
                first = data[0] if isinstance(data, list) and data else data
                lines.append(f"Session: {name}")
                if isinstance(first, dict):
                    if first.get('version'):
                        lines.append(f"  Version: {first['version']}")
                    if first.get('selected_cipher_suite'):
                        lines.append(f"  Cipher: {first['selected_cipher_suite']}")
                pkt_count = len(data) if isinstance(data, list) else 1
                lines.append(f"  Packets: {pkt_count}")
                lines.append('')

        ssh_sessions = analysis_data.get('ssh_sessions', {})
        if ssh_sessions:
            lines += ['SSH SESSIONS', '-' * 30]
            for name, data in ssh_sessions.items():
                lines.append(f"Session: {name}")
                if data.get('version'):
                    lines.append(f"  Version: {data['version']}")
                lines.append('')

        size_p = analysis_data.get('size_patterns', {})
        if size_p:
            lines += [
                'PACKET SIZE ANALYSIS', '-' * 30,
                f"Min:     {size_p['min_size']} bytes",
                f"Max:     {size_p['max_size']} bytes",
                f"Average: {size_p['avg_size']:.1f} bytes",
                '',
            ]

        return '\n'.join(lines)


def main():
    import argparse

    parser = argparse.ArgumentParser(description='Traffic Decryption and Analysis')
    parser.add_argument('--cert-chain', help='Extract certificate chain from host:port')
    args = parser.parse_args()

    decryptor = TrafficDecryptor()

    if args.cert_chain:
        parts = args.cert_chain.split(':')
        host  = parts[0]
        port  = int(parts[1]) if len(parts) > 1 else 443

        logger.info(f"Extracting certificate chain from {host}:{port}...")
        certs = decryptor.extract_certificate_chain(host, port)

        if certs:
            print(f"Found {len(certs)} certificate(s):")
            for i, cert in enumerate(certs, 1):
                print(f"\nCertificate {i}:")
                print(f"  Subject CN:  {cert.get('subject_cn', 'Unknown')}")
                print(f"  Issuer CN:   {cert.get('issuer_cn',  'Unknown')}")
                print(f"  Valid from:  {cert.get('not_before', 'Unknown')}")
                print(f"  Valid until: {cert.get('not_after',  'Unknown')}")
                print(f"  SHA-256:     {cert.get('fingerprint_sha256', 'Unknown')}")
                if cert.get('san'):
                    print(f"  SANs: {', '.join(cert['san'][:5])}")
        else:
            print("No certificates retrieved.")


if __name__ == '__main__':
    main()
