"""
Test Suite for Network Packet Monitoring Toolkit
"""

import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))


# ===========================================================================
# Utilities
# ===========================================================================

class TestNetworkUtils(unittest.TestCase):

    def setUp(self):
        from utils.common import NetworkUtils
        self.utils = NetworkUtils

    def test_ip_validation_valid(self):
        for ip in ('192.168.1.1', '8.8.8.8', '127.0.0.1', '0.0.0.0', '255.255.255.255'):
            self.assertTrue(self.utils.validate_ip(ip), ip)

    def test_ip_validation_invalid(self):
        for ip in ('256.1.1.1', 'invalid.ip', '', '999.0.0.1', 'abc'):
            self.assertFalse(self.utils.validate_ip(ip), ip)

    def test_port_validation_valid(self):
        for p in (1, 80, 443, 65535, '8080'):
            self.assertTrue(self.utils.validate_port(p), p)

    def test_port_validation_invalid(self):
        for p in (0, 65536, -1, 'abc', None):
            self.assertFalse(self.utils.validate_port(p), p)

    def test_private_ip_detection_private(self):
        for ip in ('192.168.1.1', '10.0.0.1', '172.16.0.1', '127.0.0.1', '169.254.1.1'):
            self.assertTrue(self.utils.is_private_ip(ip), ip)

    def test_private_ip_detection_public(self):
        for ip in ('8.8.8.8', '1.1.1.1', '142.250.191.14'):
            self.assertFalse(self.utils.is_private_ip(ip), ip)

    def test_get_local_ip_returns_string(self):
        ip = self.utils.get_local_ip()
        self.assertIsInstance(ip, str)
        self.assertGreater(len(ip), 0)

    def test_network_range_validation(self):
        from utils.common import SecurityUtils
        self.assertTrue(SecurityUtils.validate_network_range('192.168.1.0/24'))
        self.assertTrue(SecurityUtils.validate_network_range('10.0.0.0/8'))
        self.assertFalse(SecurityUtils.validate_network_range('invalid/range'))
        self.assertFalse(SecurityUtils.validate_network_range('999.0.0.0/24'))


class TestConfigManager(unittest.TestCase):

    def setUp(self):
        from utils.common import ConfigManager
        self.tmp = tempfile.mkdtemp()
        self.cm = ConfigManager(self.tmp)

    def test_get_set_dot_notation(self):
        self.cm.set('capture.interface', 'en0')
        self.assertEqual(self.cm.get('capture.interface'), 'en0')

    def test_get_missing_key_returns_default(self):
        self.assertIsNone(self.cm.get('nonexistent.key'))
        self.assertEqual(self.cm.get('nonexistent.key', 'fallback'), 'fallback')

    def test_nested_set(self):
        self.cm.set('a.b.c', 42)
        self.assertEqual(self.cm.get('a.b.c'), 42)

    def test_save_and_reload_json(self):
        self.cm.set('test.value', 'hello')
        self.cm.save_config('test.json')
        self.cm.config = {}
        self.cm.load_config('test.json')
        self.assertEqual(self.cm.get('test.value'), 'hello')


class TestSecurityUtils(unittest.TestCase):

    def test_hash_sensitive_data(self):
        from utils.common import SecurityUtils
        h = SecurityUtils.hash_sensitive_data('secret')
        self.assertIsInstance(h, str)
        self.assertEqual(len(h), 64)  # sha256 hex

    def test_hash_deterministic(self):
        from utils.common import SecurityUtils
        self.assertEqual(
            SecurityUtils.hash_sensitive_data('abc'),
            SecurityUtils.hash_sensitive_data('abc'),
        )

    def test_require_admin_returns_bool(self):
        from utils.common import SecurityUtils
        result = SecurityUtils.require_admin()
        self.assertIsInstance(result, bool)


class TestPerformanceMonitor(unittest.TestCase):

    def setUp(self):
        from utils.common import PerformanceMonitor
        self.monitor = PerformanceMonitor()

    def test_initial_state(self):
        self.assertIsNone(self.monitor.start_time)

    def test_start_monitoring(self):
        self.monitor.start_monitoring()
        self.assertIsNotNone(self.monitor.start_time)

    def test_update_and_rate(self):
        self.monitor.start_monitoring()
        self.monitor.update_packet_stats(100, 50_000)
        self.assertEqual(self.monitor.metrics['packets_processed'], 100)
        pps, bps = self.monitor.get_processing_rate()
        self.assertIsInstance(pps, float)
        self.assertIsInstance(bps, float)
        self.assertGreater(pps, 0)

    def test_report_keys(self):
        self.monitor.start_monitoring()
        self.monitor.update_packet_stats(10, 1500)
        report = self.monitor.generate_performance_report()
        for key in ('elapsed_time', 'packets_processed', 'bytes_processed'):
            self.assertIn(key, report)


# ===========================================================================
# Packet sniffer
# ===========================================================================

class TestPacketSniffer(unittest.TestCase):

    def test_interface_listing(self):
        try:
            from capture.packet_sniffer import PacketSniffer
        except ImportError:
            self.skipTest("Scapy not available")
        sniffer = PacketSniffer()
        ifaces = sniffer.list_interfaces()
        self.assertIsInstance(ifaces, list)
        self.assertGreater(len(ifaces), 0)

    def test_statistics_empty(self):
        try:
            from capture.packet_sniffer import PacketSniffer
        except ImportError:
            self.skipTest("Scapy not available")
        sniffer = PacketSniffer()
        self.assertEqual(sniffer.get_capture_statistics(), {})

    def test_default_interface_is_string(self):
        try:
            from capture.packet_sniffer import PacketSniffer
        except ImportError:
            self.skipTest("Scapy not available")
        sniffer = PacketSniffer()
        self.assertIsInstance(sniffer.interface, str)


# ===========================================================================
# Protocol analyzer
# ===========================================================================

class TestProtocolAnalyzer(unittest.TestCase):

    def test_init(self):
        from analysis.protocol_analyzer import ProtocolAnalyzer
        a = ProtocolAnalyzer()
        self.assertIsNone(a.pcap_file)
        self.assertEqual(a.packets, [])

    def test_analyze_empty_returns_empty(self):
        from analysis.protocol_analyzer import ProtocolAnalyzer
        a = ProtocolAnalyzer()
        result = a.analyze_protocols()
        self.assertEqual(result, {})

    def test_load_nonexistent_pcap(self):
        from analysis.protocol_analyzer import ProtocolAnalyzer
        a = ProtocolAnalyzer()
        a.load_pcap('/nonexistent/file.pcap')  # should not raise
        self.assertEqual(a.packets, [])

    def test_detect_suspicious_no_results(self):
        from analysis.protocol_analyzer import ProtocolAnalyzer
        a = ProtocolAnalyzer()
        self.assertEqual(a.detect_suspicious_patterns(), [])

    def test_fresh_analysis_has_required_keys(self):
        from analysis.protocol_analyzer import _fresh_analysis
        analysis = _fresh_analysis()
        for key in ('protocols', 'ip_conversations', 'port_analysis',
                    'http_analysis', 'dns_analysis', 'tcp_analysis',
                    'ipv6_analysis', 'suspicious_patterns'):
            self.assertIn(key, analysis)


# ===========================================================================
# Network scanner
# ===========================================================================

class TestNetworkScanner(unittest.TestCase):

    def setUp(self):
        from scanning.network_scanner import NetworkScanner
        self.scanner = NetworkScanner('192.168.1.0/24')

    def test_init(self):
        self.assertEqual(self.scanner.target, '192.168.1.0/24')
        self.assertEqual(self.scanner.max_threads, 50)
        self.assertEqual(self.scanner.scan_delay, 0.05)

    def test_common_ports(self):
        ports = self.scanner.get_common_ports()
        self.assertIsInstance(ports, list)
        self.assertIn(80, ports)
        self.assertIn(443, ports)
        self.assertIn(22, ports)

    def test_scan_port_closed(self):
        # Port 1 should be closed on localhost
        result = self.scanner.scan_port('127.0.0.1', 1, timeout=0.5)
        self.assertIsInstance(result, bool)

    def test_resolve_hostname_localhost(self):
        hostname = self.scanner.resolve_hostname('127.0.0.1')
        # Should return 'localhost' or similar, or None
        self.assertTrue(hostname is None or isinstance(hostname, str))

    def test_detect_os_returns_string_or_none(self):
        result = self.scanner.detect_os('127.0.0.1')
        self.assertTrue(result is None or isinstance(result, str))

    def test_get_network_interfaces(self):
        ifaces = self.scanner.get_network_interfaces()
        self.assertIsInstance(ifaces, list)

    def test_nmap_unavailable_returns_none(self):
        from scanning import network_scanner as ns
        orig = ns.NMAP_AVAILABLE
        ns.NMAP_AVAILABLE = False
        try:
            result = self.scanner.nmap_scan()
            self.assertIsNone(result)
        finally:
            ns.NMAP_AVAILABLE = orig


# ===========================================================================
# Traffic decryptor
# ===========================================================================

class TestTrafficDecryptor(unittest.TestCase):

    def setUp(self):
        from decryption.traffic_decryptor import TrafficDecryptor
        self.d = TrafficDecryptor()

    def test_init(self):
        self.assertIsInstance(self.d.ssl_sessions, dict)
        self.assertIsInstance(self.d.encryption_stats, dict)

    def test_analyze_ssl_tls_empty(self):
        result = self.d.analyze_ssl_tls_traffic(b'')
        self.assertFalse(result['is_ssl_tls'])

    def test_analyze_ssl_tls_handshake_marker(self):
        # TLS 1.2 Client Hello prefix
        data = bytes([22, 3, 3, 0, 10]) + b'\x01' + b'\x00\x00\x06' + b'\x03\x03' + b'\x00' * 32
        result = self.d.analyze_ssl_tls_traffic(data)
        self.assertTrue(result['is_ssl_tls'])
        self.assertEqual(result['version'], 'TLS 1.2')

    def test_detect_ssh_traffic(self):
        result = self.d.detect_ssh_traffic(b'SSH-2.0-OpenSSH_8.9\r\n')
        self.assertTrue(result['is_ssh'])
        self.assertEqual(result['protocol_version'], '2.0')
        self.assertIn('OpenSSH', result['software_version'])

    def test_detect_ssh_non_ssh(self):
        result = self.d.detect_ssh_traffic(b'HTTP/1.1 200 OK\r\n')
        self.assertFalse(result['is_ssh'])

    def test_size_distribution(self):
        dist = self.d._size_distribution([32, 100, 800, 2000])
        self.assertEqual(dist['tiny'], 1)
        self.assertEqual(dist['small'], 1)
        self.assertEqual(dist['medium'], 1)
        self.assertEqual(dist['large'], 1)

    def test_parse_tls_version(self):
        self.assertEqual(self.d._parse_tls_version(0x0303), 'TLS 1.2')
        self.assertEqual(self.d._parse_tls_version(0x0304), 'TLS 1.3')

    def test_analyze_encrypted_metadata(self):
        result = self.d.analyze_encrypted_metadata([b'SSH-2.0-OpenSSH_8.9\n'])
        self.assertEqual(result['total_packets'], 1)
        self.assertIn('ssh_sessions', result)


# ===========================================================================
# PII Redactor
# ===========================================================================

class TestPIIRedactor(unittest.TestCase):

    def setUp(self):
        from privacy.pii_redactor import PIIRedactor
        self.r = PIIRedactor()

    def test_redact_email(self):
        text = self.r.redact_string('Contact: user@example.com for details')
        self.assertNotIn('user@example.com', text)
        self.assertIn('[EMAIL]', text)

    def test_redact_credit_card(self):
        text = self.r.redact_string('Card: 4111111111111111 is valid')
        self.assertNotIn('4111111111111111', text)
        self.assertIn('[CREDIT_CARD]', text)

    def test_redact_bearer_token(self):
        text = self.r.redact_string('Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.abc.def')
        self.assertIn('[TOKEN]', text)

    def test_redact_dict_recursive(self):
        data = {'email': 'test@test.com', 'nested': {'value': 'no pii here'}}
        result = self.r.redact_dict(data)
        self.assertNotIn('test@test.com', result['email'])

    def test_scan_for_pii(self):
        data = {'field': 'Contact admin@corp.com'}
        findings = self.r.scan_for_pii(data)
        self.assertIn('email', findings)
        self.assertGreater(len(findings['email']), 0)

    def test_redact_stats_tracked(self):
        self.r.reset_stats()
        self.r.redact_string('Email: foo@bar.com and baz@qux.com')
        stats = self.r.get_stats()
        self.assertEqual(stats.get('email', 0), 2)

    def test_non_string_passthrough(self):
        self.assertEqual(self.r.redact_string(123), 123)
        self.assertEqual(self.r.redact_dict({'n': 42}), {'n': 42})


# ===========================================================================
# GeoIP Lookup
# ===========================================================================

class TestGeoIPLookup(unittest.TestCase):

    def setUp(self):
        from geo.geo_lookup import GeoIPLookup
        self.geo = GeoIPLookup()  # No DB — falls back to ip-api.com

    def test_private_ip_no_api_call(self):
        result = self.geo.lookup('192.168.1.1')
        self.assertTrue(result['is_private'])
        self.assertEqual(result['country_code'], 'LAN')

    def test_loopback_is_private(self):
        result = self.geo.lookup('127.0.0.1')
        self.assertTrue(result['is_private'])

    def test_result_has_required_keys(self):
        result = self.geo.lookup('192.168.1.100')
        for key in ('ip', 'country', 'country_code', 'city', 'is_private'):
            self.assertIn(key, result)

    def test_batch_lookup(self):
        ips = ['192.168.1.1', '10.0.0.1', '192.168.0.1']
        results = self.geo.batch_lookup(ips)
        self.assertEqual(len(results), len(set(ips)))

    def test_format_location_private(self):
        info = self.geo.lookup('10.0.0.1')
        loc = self.geo.format_location(info)
        self.assertEqual(loc, 'Private Network')


# ===========================================================================
# ML Traffic Classifier
# ===========================================================================

class TestTrafficClassifier(unittest.TestCase):

    def setUp(self):
        from ml.traffic_classifier import TrafficClassifier
        self.clf = TrafficClassifier()

    def _make_packet(self, src_port, dst_port, proto=6, length=100,
                     src_ip='192.168.1.1', dst_ip='8.8.8.8'):
        return {
            'src_ip': src_ip, 'dst_ip': dst_ip,
            'src_port': src_port, 'dst_port': dst_port,
            'protocol': proto, 'length': length,
        }

    def test_rule_based_web(self):
        pkt = self._make_packet(12345, 80)
        result = self.clf.rule_based_classify(pkt)
        self.assertEqual(result, 'web')

    def test_rule_based_dns(self):
        pkt = self._make_packet(54321, 53, proto=17)
        result = self.clf.rule_based_classify(pkt)
        self.assertEqual(result, 'dns')

    def test_rule_based_ssh(self):
        pkt = self._make_packet(55000, 22)
        result = self.clf.rule_based_classify(pkt)
        self.assertEqual(result, 'ssh')

    def test_rule_based_unknown(self):
        pkt = self._make_packet(50000, 50001)
        result = self.clf.rule_based_classify(pkt)
        self.assertEqual(result, 'unknown')

    def test_classify_packet_returns_dict(self):
        pkt = self._make_packet(12345, 443)
        result = self.clf.classify_packet(pkt)
        self.assertIn('rule_based', result)
        self.assertIn('ml_based', result)
        self.assertIn('is_anomaly', result)

    def test_classify_batch(self):
        pkts = [self._make_packet(i, 80) for i in range(10, 20)]
        result = self.clf.classify_traffic_batch(pkts)
        self.assertEqual(result['total_packets'], 10)
        self.assertIn('category_distribution', result)
        self.assertIn('web', result['category_distribution'])

    def test_train_requires_enough_samples(self):
        pkts = [self._make_packet(i, 80) for i in range(3)]
        success = self.clf.train(pkts)
        self.assertFalse(success)

    def test_feature_extraction(self):
        pkt = self._make_packet(12345, 443, length=1400)
        features = self.clf.extract_features(pkt)
        if features is not None:  # numpy available
            self.assertEqual(len(features), 12)


# ===========================================================================
# VoIP / RTP Analyzer
# ===========================================================================

class TestVoIPAnalyzer(unittest.TestCase):

    def setUp(self):
        from voip.rtp_analyzer import VoIPAnalyzer
        self.voip = VoIPAnalyzer()

    def _make_rtp(self, seq, ts, ssrc=0xABCD1234, pt=8):
        """Craft a minimal valid RTP packet."""
        import struct
        # V=2 P=0 X=0 CC=0 | M=0 PT=pt
        header = struct.pack('!BBHII', 0x80, pt & 0x7F, seq, ts, ssrc)
        return header + b'\x00' * 160  # 20ms G.711 payload

    def test_parse_rtp_valid(self):
        from voip.rtp_analyzer import VoIPAnalyzer
        pkt = self._make_rtp(1, 0)
        result = VoIPAnalyzer.parse_rtp_packet(pkt)
        self.assertIsNotNone(result)
        self.assertEqual(result.sequence_number, 1)
        self.assertEqual(result.payload_type, 8)

    def test_parse_rtp_too_short(self):
        from voip.rtp_analyzer import VoIPAnalyzer
        result = VoIPAnalyzer.parse_rtp_packet(b'\x80\x08\x00')
        self.assertIsNone(result)

    def test_parse_rtp_bad_version(self):
        from voip.rtp_analyzer import VoIPAnalyzer
        import struct
        # version = 1 (invalid)
        data = struct.pack('!BBHII', 0x40, 0x08, 1, 0, 0xABCD) + b'\x00' * 100
        result = VoIPAnalyzer.parse_rtp_packet(data)
        self.assertIsNone(result)

    def test_is_likely_rtp(self):
        pkt = self._make_rtp(1, 0)
        self.assertTrue(self.voip.is_likely_rtp(pkt, 12000))
        self.assertFalse(self.voip.is_likely_rtp(pkt, 80))  # low port

    def test_stream_quality_insufficient_data(self):
        result = self.voip.calculate_stream_quality(0xDEAD)
        self.assertTrue(result.get('insufficient_data'))

    def test_stream_quality_metrics(self):
        ssrc = 0x1234
        for i in range(10):
            pkt = self.voip.parse_rtp_packet(self._make_rtp(i, i * 160, ssrc=ssrc))
            if pkt:
                self.voip.rtp_streams[ssrc].append(pkt)
        quality = self.voip.calculate_stream_quality(ssrc)
        self.assertIn('loss_rate_pct', quality)
        self.assertIn('jitter', quality)
        self.assertIn('codec', quality)
        self.assertFalse(quality.get('insufficient_data'))

    def test_sip_parsing(self):
        sip_invite = (
            b"INVITE sip:bob@biloxi.com SIP/2.0\r\n"
            b"Via: SIP/2.0/UDP pc33.atlanta.com\r\n"
            b"Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n"
            b"From: Alice <sip:alice@atlanta.com>\r\n"
            b"To: Bob <sip:bob@biloxi.com>\r\n"
            b"\r\n"
        )
        self.voip._analyze_sip(sip_invite, '10.0.0.1', '10.0.0.2', 5060, 5060)
        self.assertEqual(len(self.voip.sip_sessions), 1)
        call = list(self.voip.sip_sessions.values())[0]
        self.assertEqual(call['state'], 'inviting')

    def test_generate_report(self):
        report = self.voip.generate_report()
        for key in ('rtp_streams', 'sip_sessions', 'stream_quality',
                    'average_loss_rate', 'active_calls'):
            self.assertIn(key, report)


# ===========================================================================
# Alert Manager
# ===========================================================================

class TestAlertManager(unittest.TestCase):

    def setUp(self):
        from alerts.alert_manager import AlertManager, AlertSeverity
        self.mgr = AlertManager()
        self.mgr.channels = []  # disable console output during tests
        self.Sev = AlertSeverity

    def test_fire_alert(self):
        self.mgr.start()
        self.mgr.fire(self.Sev.HIGH, 'test', 'Unit test alert')
        time.sleep(0.1)
        self.mgr.stop()
        self.assertEqual(len(self.mgr.alert_history), 1)

    def test_alert_to_dict(self):
        from alerts.alert_manager import Alert, AlertSeverity
        a = Alert(AlertSeverity.MEDIUM, 'test_type', 'msg', {'k': 'v'}, '1.2.3.4', '5.6.7.8')
        d = a.to_dict()
        self.assertEqual(d['severity'], 'MEDIUM')
        self.assertEqual(d['alert_type'], 'test_type')
        self.assertEqual(d['source_ip'], '1.2.3.4')

    def test_acknowledge(self):
        self.mgr.start()
        self.mgr.fire(self.Sev.LOW, 'ack_test', 'ack me')
        time.sleep(0.1)
        self.mgr.stop()
        alert_id = self.mgr.alert_history[0].id
        self.mgr.acknowledge(alert_id)
        self.assertTrue(self.mgr.alert_history[0].acknowledged)

    def test_get_alerts_filter_severity(self):
        from alerts.alert_manager import Alert, AlertSeverity
        self.mgr.start()
        self.mgr.fire(AlertSeverity.LOW,      't', 'low alert')
        self.mgr.fire(AlertSeverity.CRITICAL, 't', 'critical alert')
        time.sleep(0.15)
        self.mgr.stop()
        critical = self.mgr.get_alerts(severity=AlertSeverity.CRITICAL)
        self.assertEqual(len(critical), 1)
        self.assertEqual(critical[0]['severity'], 'CRITICAL')

    def test_default_rules_port_scan(self):
        from collections import Counter
        self.mgr.start()
        data = {
            'tcp_analysis': {
                'ports': Counter({p: 1 for p in range(200)}),
                'flags': Counter(),
            },
            'dns_analysis': {'domains': Counter()},
        }
        self.mgr.check(data)
        time.sleep(0.1)
        self.mgr.stop()
        types = [a.alert_type for a in self.mgr.alert_history]
        self.assertIn('port_scan', types)

    def test_summary_structure(self):
        self.mgr.start()
        self.mgr.fire(self.Sev.HIGH, 'x', 'y')
        time.sleep(0.1)
        self.mgr.stop()
        summary = self.mgr.get_summary()
        self.assertIn('total', summary)
        self.assertIn('by_severity', summary)

    def test_file_channel(self):
        from alerts.alert_manager import FileAlertChannel, AlertSeverity, Alert
        with tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False) as f:
            path = f.name
        try:
            ch = FileAlertChannel(path)
            a = Alert(AlertSeverity.HIGH, 'file_test', 'written to file')
            ch.send(a)
            with open(path) as fh:
                lines = fh.readlines()
            self.assertEqual(len(lines), 1)
            data = json.loads(lines[0])
            self.assertEqual(data['alert_type'], 'file_test')
        finally:
            os.unlink(path)

    def test_severity_ordering(self):
        from alerts.alert_manager import AlertSeverity
        self.assertLess(AlertSeverity.INFO, AlertSeverity.CRITICAL)
        self.assertLess(AlertSeverity.LOW, AlertSeverity.HIGH)
        self.assertLessEqual(AlertSeverity.MEDIUM, AlertSeverity.MEDIUM)


# ===========================================================================
# Data exporter
# ===========================================================================

class TestDataExporter(unittest.TestCase):

    def setUp(self):
        from utils.common import DataExporter
        self.tmp = tempfile.mkdtemp()
        self.exporter = DataExporter(self.tmp)

    def test_export_json(self):
        data = {'key': 'value', 'count': 42}
        path = self.exporter.export_to_json(data, 'test.json')
        self.assertTrue(os.path.exists(path))
        with open(path) as f:
            loaded = json.load(f)
        self.assertEqual(loaded['count'], 42)

    def test_export_csv(self):
        rows = [{'a': 1, 'b': 2}, {'a': 3, 'b': 4}]
        path = self.exporter.export_to_csv(rows, 'test.csv')
        self.assertTrue(os.path.exists(path))
        content = open(path).read()
        self.assertIn('a', content)
        self.assertIn('b', content)

    def test_export_empty_csv(self):
        path = self.exporter.export_to_csv([], 'empty.csv')
        self.assertEqual(path, '')  # should return empty string

    def test_export_xml(self):
        data = {'root': {'child': 'value'}}
        path = self.exporter.export_to_xml(data, 'test.xml')
        self.assertTrue(os.path.exists(path))


# ===========================================================================
# TestDeviceFingerprinter
# ===========================================================================

class TestDeviceFingerprinter(unittest.TestCase):

    def setUp(self):
        sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))
        from fingerprinting.device_fingerprinter import (
            MACAnalyzer, DHCPFingerprinter, JA3Fingerprinter,
            mDNSTracker, DeviceFingerprinter,
        )
        self.MAC = MACAnalyzer
        self.DHCP = DHCPFingerprinter
        self.JA3 = JA3Fingerprinter
        self.mDNS = mDNSTracker
        self.FP = DeviceFingerprinter

    # --- MACAnalyzer ---

    def test_normalize_mac_colons(self):
        self.assertEqual(self.MAC.normalize_mac('AA:BB:CC:DD:EE:FF'),
                         'aa:bb:cc:dd:ee:ff')

    def test_normalize_mac_dashes(self):
        self.assertEqual(self.MAC.normalize_mac('AA-BB-CC-DD-EE-FF'),
                         'aa:bb:cc:dd:ee:ff')

    def test_locally_administered_true(self):
        # Second char of first octet is '2','6','A','E' → randomized
        self.assertTrue(self.MAC.is_locally_administered('02:00:00:00:00:00'))
        self.assertTrue(self.MAC.is_locally_administered('06:00:00:00:00:00'))
        self.assertTrue(self.MAC.is_locally_administered('0a:00:00:00:00:00'))
        self.assertTrue(self.MAC.is_locally_administered('0e:00:00:00:00:00'))

    def test_locally_administered_false(self):
        # Universally administered OUI
        self.assertFalse(self.MAC.is_locally_administered('00:1A:2B:3C:4D:5E'))
        self.assertFalse(self.MAC.is_locally_administered('ac:de:48:00:11:22'))

    def test_get_oui_prefix(self):
        self.assertEqual(self.MAC.get_oui_prefix('aa:bb:cc:dd:ee:ff'), 'AA:BB:CC')

    # --- DHCPFingerprinter ---

    def test_dhcp_exact_windows(self):
        windows_prl = [1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252]
        result = self.DHCP.identify_os(windows_prl)
        self.assertEqual(result, 'Windows')

    def test_dhcp_exact_macos(self):
        macos_prl = [1, 3, 6, 15, 119, 95, 252, 46]
        result = self.DHCP.identify_os(macos_prl)
        self.assertEqual(result, 'macOS/iOS')

    def test_dhcp_exact_android(self):
        android_prl = [1, 3, 6, 15, 26, 28, 51, 58, 59, 43]
        result = self.DHCP.identify_os(android_prl)
        self.assertEqual(result, 'Android')

    def test_dhcp_vendor_class_override(self):
        # Unknown PRL but vendor class identifies Windows
        result = self.DHCP.identify_os([99, 98, 97], vendor_class='MSFT 5.0')
        self.assertEqual(result, 'Windows')

    def test_dhcp_jaccard_fallback(self):
        # Mostly Windows options → should still match Windows via Jaccard
        partial_windows = [1, 3, 6, 15, 31, 33, 43, 44, 46]
        result = self.DHCP.identify_os(partial_windows)
        self.assertIsNotNone(result)
        self.assertIn('Windows', result)

    def test_dhcp_low_confidence_returns_none(self):
        result = self.DHCP.identify_os([99, 100, 101, 102])
        self.assertIsNone(result)

    # --- JA3Fingerprinter ---

    def test_ja3_compute_returns_md5(self):
        h = self.JA3.compute_ja3(769, [49195, 49199], [0, 23], [23, 24], [0])
        self.assertRegex(h, r'^[0-9a-f]{32}$')

    def test_ja3_grease_excluded(self):
        # 0x0a0a is GREASE — should be stripped before hashing
        with_grease    = self.JA3.compute_ja3(769, [0x0a0a, 49195], [0], [], [])
        without_grease = self.JA3.compute_ja3(769, [49195],         [0], [], [])
        self.assertEqual(with_grease, without_grease)

    def test_ja3_deterministic(self):
        h1 = self.JA3.compute_ja3(771, [49196, 49200], [0, 23], [23], [0])
        h2 = self.JA3.compute_ja3(771, [49196, 49200], [0, 23], [23], [0])
        self.assertEqual(h1, h2)

    # --- mDNSTracker ---

    def test_mdns_invalid_payload_no_crash(self):
        tracker = self.mDNS()
        result = tracker.process_packet('192.168.1.1', None, b'\x00\x01')
        self.assertEqual(result['hostnames'], [])

    # --- DeviceFingerprinter ---

    def test_empty_report(self):
        fp = self.FP()
        report = fp.generate_report()
        self.assertEqual(report['total_devices'], 0)
        self.assertEqual(report['randomized_macs'], 0)
        self.assertEqual(report['devices'], [])

    def test_profile_created_on_process(self):
        from fingerprinting.device_fingerprinter import _empty_profile, MACAnalyzer
        fp = self.FP()
        # Inject a profile directly (unit test without real packets)
        mac = '02:aa:bb:cc:dd:ee'
        fp._profiles[mac] = _empty_profile(mac)
        report = fp.generate_report()
        self.assertEqual(report['total_devices'], 1)
        self.assertEqual(report['randomized_macs'], 1)

    def test_mac_alias_correlation(self):
        fp = self.FP()
        mac1 = '00:11:22:33:44:55'
        mac2 = '02:aa:bb:cc:dd:ee'
        from fingerprinting.device_fingerprinter import _empty_profile
        fp._profiles[mac1] = _empty_profile(mac1)
        fp._profiles[mac1]['hostname'] = 'myphone.local'
        fp._hostname_index['myphone.local'] = mac1
        fp._profiles[mac2] = _empty_profile(mac2)
        fp._correlate_hostname(mac2, 'myphone.local')
        self.assertIn(mac2, fp._profiles[mac1]['aliases'])


# ===========================================================================
# Runner
# ===========================================================================

def run_tests():
    print('Network Packet Monitoring Toolkit — Test Suite')
    print('=' * 60)

    loader = unittest.TestLoader()
    suite  = unittest.TestSuite()

    test_classes = [
        TestNetworkUtils,
        TestConfigManager,
        TestSecurityUtils,
        TestPerformanceMonitor,
        TestPacketSniffer,
        TestProtocolAnalyzer,
        TestNetworkScanner,
        TestTrafficDecryptor,
        TestPIIRedactor,
        TestGeoIPLookup,
        TestTrafficClassifier,
        TestVoIPAnalyzer,
        TestAlertManager,
        TestDataExporter,
        TestDeviceFingerprinter,
    ]

    for cls in test_classes:
        suite.addTests(loader.loadTestsFromTestCase(cls))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print('\n' + '=' * 60)
    if result.wasSuccessful():
        print(f'All {result.testsRun} tests passed.')
    else:
        print(f'{result.testsRun} tests run — '
              f'{len(result.failures)} failures, {len(result.errors)} errors')

    return result.wasSuccessful()


if __name__ == '__main__':
    run_tests()
