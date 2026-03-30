#!/usr/bin/env python3
"""
Main CLI Interface for Network Packet Monitoring Toolkit
"""

import json
import logging
import os
import sys
from pathlib import Path

# Add src to Python path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from utils.common import ConfigManager, setup_logging, SecurityUtils
from capture.packet_sniffer import PacketSniffer
from analysis.protocol_analyzer import ProtocolAnalyzer
from scanning.network_scanner import NetworkScanner
from decryption.traffic_decryptor import TrafficDecryptor
from visualization.network_visualizer import NetworkVisualizer


def build_parser():
    import argparse

    parser = argparse.ArgumentParser(
        description='Network Packet Monitoring Toolkit',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s capture -i en0 -c 100                      # Capture 100 packets
  %(prog)s analyze traffic.pcap --visualize            # Analyse + visualise PCAP
  %(prog)s scan 192.168.1.0/24                         # Network discovery
  %(prog)s scan 192.168.1.1 --comprehensive            # Full host scan
  %(prog)s scan 192.168.1.0/24 --nmap --nmap-type tcp  # Nmap scan
  %(prog)s ssl-cert google.com                         # Extract SSL cert
  %(prog)s geo 8.8.8.8                                 # GeoIP lookup
  %(prog)s classify traffic.pcap                       # ML traffic classification
  %(prog)s voip traffic.pcap                           # VoIP/RTP analysis
  %(prog)s visualize analysis.json --dashboard         # Dashboard from JSON
  %(prog)s fingerprint traffic.pcap                    # Device fingerprinting

Legal Notice:
  For educational and authorised network monitoring only.
        """,
    )

    parser.add_argument('--config', default='config/default.yaml')
    parser.add_argument('--verbose', '-v', action='store_true')
    parser.add_argument('--no-admin-check', action='store_true')

    sub = parser.add_subparsers(dest='command', help='Command')

    # ---- capture ----
    p = sub.add_parser('capture', help='Live packet capture')
    p.add_argument('-i', '--interface')
    p.add_argument('-c', '--count', type=int, default=0)
    p.add_argument('-t', '--timeout', type=int)
    p.add_argument('-f', '--filter', default='')
    p.add_argument('-o', '--output', help='Save to PCAP file')
    p.add_argument('--list-interfaces', action='store_true')

    # ---- analyze ----
    p = sub.add_parser('analyze', help='Analyse PCAP file')
    p.add_argument('pcap_file')
    p.add_argument('-r', '--report', help='Save text report')
    p.add_argument('-j', '--json', help='Save JSON export')
    p.add_argument('--visualize', action='store_true')
    p.add_argument('--redact-pii', action='store_true',
                   help='Redact PII before JSON export')

    # ---- scan ----
    p = sub.add_parser('scan', help='Network scanning')
    p.add_argument('target')
    p.add_argument('-p', '--ports', help='Port range e.g. 1-1000')
    p.add_argument('--ping-only', action='store_true')
    p.add_argument('--comprehensive', action='store_true')
    p.add_argument('--nmap', action='store_true', help='Use nmap')
    p.add_argument('--nmap-type',
                   choices=['syn', 'tcp', 'udp', 'ping', 'version'],
                   default='tcp')
    p.add_argument('--scan-delay', type=float, default=0.05,
                   help='Seconds between port probes (rate limit)')
    p.add_argument('--max-threads', type=int, default=50)
    p.add_argument('--geo', action='store_true',
                   help='Enrich discovered hosts with GeoIP data')

    # ---- ssl-cert ----
    p = sub.add_parser('ssl-cert', help='Extract SSL/TLS certificate chain')
    p.add_argument('host')
    p.add_argument('-p', '--port', type=int, default=443)

    # ---- geo ----
    p = sub.add_parser('geo', help='GeoIP lookup for IP address(es)')
    p.add_argument('ips', nargs='+', help='One or more IP addresses')
    p.add_argument('--db', help='Path to MaxMind GeoLite2-City.mmdb (optional)')

    # ---- classify ----
    p = sub.add_parser('classify', help='ML traffic classification on PCAP')
    p.add_argument('pcap_file')
    p.add_argument('--model', help='Path to saved classifier model')
    p.add_argument('--train', action='store_true',
                   help='Train model on this PCAP then classify')
    p.add_argument('--save-model', help='Save trained model to path')

    # ---- voip ----
    p = sub.add_parser('voip', help='VoIP / RTP analysis on PCAP')
    p.add_argument('pcap_file')
    p.add_argument('-j', '--json', help='Save JSON report')

    # ---- visualize ----
    p = sub.add_parser('visualize', help='Visualise analysis JSON')
    p.add_argument('data_file')
    p.add_argument('--dashboard', action='store_true')

    # ---- alerts ----
    p = sub.add_parser('alerts', help='Show alert summary for a PCAP')
    p.add_argument('pcap_file')
    p.add_argument('--output', help='Save alerts to JSONL file')

    # ---- fingerprint ----
    p = sub.add_parser('fingerprint', help='Device fingerprinting from PCAP')
    p.add_argument('pcap_file')
    p.add_argument('-j', '--json', help='Save JSON report to file')
    p.add_argument('--show-randomized', action='store_true',
                   help='Only show devices with randomized/spoofed MACs')

    return parser


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------

def execute_capture(args, _config):
    sniffer = PacketSniffer(interface=args.interface, filter_expr=args.filter)

    if args.list_interfaces:
        for iface in sniffer.list_interfaces():
            print(f"  {iface}")
        return

    sniffer.start_capture(count=args.count, timeout=args.timeout,
                          save_to_file=args.output)
    sniffer.print_statistics()


def execute_analyze(args, _config):
    if not os.path.exists(args.pcap_file):
        print(f"Error: file not found: {args.pcap_file}")
        return

    analyzer = ProtocolAnalyzer(args.pcap_file)
    analyzer.load_pcap(args.pcap_file)
    results = analyzer.analyze_protocols()

    if args.report:
        analyzer.generate_report(args.report)
        print(f"Report saved: {args.report}")
    else:
        print(analyzer.generate_report())

    if args.json:
        export_data = results
        if args.redact_pii:
            from privacy.pii_redactor import PIIRedactor
            redactor = PIIRedactor()
            export_data = redactor.redact_dict(results)
            stats = redactor.get_stats()
            if stats:
                print(f"PII redacted: {stats}")
        analyzer.export_to_json(args.json)
        print(f"JSON saved: {args.json}")

    if args.visualize:
        viz = NetworkVisualizer()
        if results.get('protocols'):
            viz.plot_protocol_distribution(dict(results['protocols']))
        if results.get('port_analysis'):
            viz.plot_port_activity(dict(results['port_analysis']))
        viz.create_comprehensive_dashboard(results)
        print("Visualisations saved to visualizations/")

    # Run alert checks
    from alerts.alert_manager import AlertManager
    mgr = AlertManager()
    mgr.start()
    mgr.check(results)
    mgr.stop()


def execute_scan(args, _config):
    scanner = NetworkScanner(
        args.target,
        max_threads=args.max_threads,
        scan_delay=args.scan_delay,
    )

    geo_lookup = None
    if args.geo:
        try:
            from geo.geo_lookup import GeoIPLookup
            geo_lookup = GeoIPLookup()
        except ImportError:
            print("GeoIP unavailable — continuing without geo enrichment.")

    if args.ping_only:
        hosts = scanner.scan_network()
        print(f"\nActive hosts ({len(hosts)}):")
        for h in hosts:
            geo_str = ''
            if geo_lookup:
                info = geo_lookup.lookup(h['ip'])
                geo_str = f"  [{geo_lookup.format_location(info)}]"
            print(f"  {h['ip']:<18} {h.get('hostname') or 'Unknown'}{geo_str}")

    elif args.nmap:
        results = scanner.nmap_scan(
            args.nmap_type,
            port_range=args.ports,
        )
        if results:
            for host, info in results.items():
                print(f"\n{host}  ({info.get('hostname', '')})")
                if info.get('os'):
                    print(f"  OS: {info['os']['name']} ({info['os']['accuracy']}%)")
                for p in info.get('ports', []):
                    if p['state'] == 'open':
                        svc = f"{p['name']} {p.get('version', '')}".strip()
                        print(f"  {p['port']:>5}/{p['proto']}  {svc}")

    elif args.comprehensive:
        port_range = None
        if args.ports:
            try:
                s, e = map(int, args.ports.split('-'))
                port_range = (s, e)
            except ValueError:
                print("Invalid port range — use start-end e.g. 1-1000")
                return
        result = scanner.comprehensive_scan(args.target, port_range)
        _print_scan_result(result, geo_lookup)

    else:
        hosts = scanner.scan_network()
        print(f"\nDiscovered {len(hosts)} host(s):")
        for h in hosts:
            geo_str = ''
            if geo_lookup:
                info = geo_lookup.lookup(h['ip'])
                geo_str = f"  [{geo_lookup.format_location(info)}]"
            mac = h.get('mac') or 'Unknown'
            print(f"  {h['ip']:<18} {(h.get('hostname') or 'Unknown'):<22} {mac}{geo_str}")


def _print_scan_result(result, geo_lookup=None):
    print(f"\nHost: {result['host']}")
    print(f"Alive: {result['alive']}")
    if not result.get('alive'):
        return
    if result.get('hostname'):
        print(f"Hostname: {result['hostname']}")
    if result.get('os_detection'):
        print(f"OS: {result['os_detection']}")
    if result.get('scan_method'):
        print(f"Method: {result['scan_method']}")
    if geo_lookup:
        info = geo_lookup.lookup(result['host'])
        print(f"Location: {geo_lookup.format_location(info)}")
    open_ports = result.get('open_ports', {})
    if open_ports:
        print(f"\nOpen ports ({len(open_ports)}):")
        for port in sorted(open_ports):
            svc = result.get('services', {}).get(port, {})
            name = svc.get('service', 'Unknown')
            detail = svc.get('version') or svc.get('banner', '')
            detail_str = f"  — {detail[:60]}" if detail else ''
            print(f"  {port:>5}/tcp  {name}{detail_str}")


def execute_ssl_cert(args, _config):
    decryptor = TrafficDecryptor()
    print(f"Extracting certificate chain from {args.host}:{args.port} …")
    certs = decryptor.extract_certificate_chain(args.host, args.port)

    if not certs:
        print("No certificates retrieved.")
        return

    print(f"Found {len(certs)} certificate(s):\n")
    for i, cert in enumerate(certs, 1):
        print(f"Certificate {i}:")
        print(f"  Subject:  {cert.get('subject_cn', 'Unknown')}")
        print(f"  Issuer:   {cert.get('issuer_cn',  'Unknown')}")
        print(f"  Valid:    {cert.get('not_before', '?')} → {cert.get('not_after', '?')}")
        print(f"  SHA-256:  {cert.get('fingerprint_sha256', '?')}")
        if cert.get('san'):
            print(f"  SANs:     {', '.join(cert['san'][:5])}")
        print()


def execute_geo(args, _config):
    from geo.geo_lookup import GeoIPLookup
    geo = GeoIPLookup(db_path=getattr(args, 'db', None))

    for ip in args.ips:
        info = geo.lookup(ip)
        loc = geo.format_location(info)
        isp = info.get('isp', 'Unknown')
        print(f"{ip:<20} {loc:<40} ISP: {isp}")


def execute_classify(args, _config):
    if not os.path.exists(args.pcap_file):
        print(f"Error: file not found: {args.pcap_file}")
        return

    from ml.traffic_classifier import TrafficClassifier

    analyzer = ProtocolAnalyzer(args.pcap_file)
    analyzer.load_pcap(args.pcap_file)

    classifier = TrafficClassifier(model_path=getattr(args, 'model', None))

    # Build packet info list from the analysis
    packets_info = []
    for pkt in analyzer.packets:
        try:
            info = {}
            if hasattr(pkt, 'haslayer'):
                from scapy.layers.inet import IP, TCP, UDP
                if pkt.haslayer(IP):
                    ip = pkt[IP]
                    info = {
                        'src_ip': ip.src, 'dst_ip': ip.dst,
                        'protocol': ip.proto, 'length': ip.len,
                    }
                    if pkt.haslayer(TCP):
                        info['src_port'] = pkt[TCP].sport
                        info['dst_port'] = pkt[TCP].dport
                    elif pkt.haslayer(UDP):
                        info['src_port'] = pkt[UDP].sport
                        info['dst_port'] = pkt[UDP].dport
            if info:
                packets_info.append(info)
        except Exception:
            pass

    if not packets_info:
        print("No IP packets found for classification.")
        return

    if args.train:
        print(f"Training on {len(packets_info)} packets …")
        classifier.train(packets_info)
        if hasattr(args, 'save_model') and args.save_model:
            classifier.save_model(args.save_model)
            print(f"Model saved: {args.save_model}")

    print(f"\nClassifying {len(packets_info)} packets …")
    result = classifier.classify_traffic_batch(packets_info)

    print(f"\nTraffic Classification Results:")
    print(f"  Total packets:    {result['total_packets']}")
    print(f"  ML model active:  {result['ml_available']}")
    print(f"\n  Category Distribution:")
    for cat, count in sorted(result['category_distribution'].items(),
                              key=lambda x: x[1], reverse=True):
        pct = count / result['total_packets'] * 100
        print(f"    {cat:<20} {count:>6}  ({pct:.1f}%)")
    print(f"\n  Anomalies detected: {result['anomalies_detected']}")
    if result['anomalies']:
        feat_imp = classifier.get_feature_importance()
        if feat_imp:
            print("\n  Top feature importances:")
            for feat, imp in list(feat_imp.items())[:5]:
                print(f"    {feat}: {imp:.3f}")


def execute_voip(args, _config):
    if not os.path.exists(args.pcap_file):
        print(f"Error: file not found: {args.pcap_file}")
        return

    from voip.rtp_analyzer import VoIPAnalyzer

    analyzer = ProtocolAnalyzer(args.pcap_file)
    analyzer.load_pcap(args.pcap_file)

    voip = VoIPAnalyzer()
    report = voip.analyze_scapy_packets(analyzer.packets)

    print(f"\nVoIP Analysis: {args.pcap_file}")
    print(f"  RTP streams:      {report['rtp_streams']}")
    print(f"  Total RTP pkts:   {report['total_rtp_packets']}")
    print(f"  SIP sessions:     {report['sip_sessions']}")
    print(f"  Active calls:     {report['active_calls']}")
    print(f"  Avg packet loss:  {report['average_loss_rate']}%")

    if report['stream_quality']:
        print("\n  Stream Quality:")
        for stream in report['stream_quality']:
            if not stream.get('insufficient_data'):
                print(f"    SSRC {stream['ssrc']:>10}  "
                      f"loss={stream['loss_rate_pct']}%  "
                      f"jitter={stream['jitter']}  "
                      f"codec={stream['codec']}")

    if report['sip_calls']:
        print("\n  SIP Calls:")
        for call in report['sip_calls'][:5]:
            print(f"    [{call.get('state','?')}] "
                  f"{call.get('from','?')} → {call.get('to','?')}")

    if hasattr(args, 'json') and args.json:
        with open(args.json, 'w') as fh:
            json.dump(report, fh, indent=2)
        print(f"\nJSON report saved: {args.json}")


def execute_visualize(args, _config):
    if not os.path.exists(args.data_file):
        print(f"Error: file not found: {args.data_file}")
        return

    with open(args.data_file) as fh:
        data = json.load(fh)

    viz = NetworkVisualizer()

    if args.dashboard:
        path = viz.create_comprehensive_dashboard(data)
        print(f"Dashboard: {path}")
    else:
        if 'protocols' in data:
            viz.plot_protocol_distribution(data['protocols'])
        if 'port_analysis' in data:
            viz.plot_port_activity(data['port_analysis'])
        if 'ip_conversations' in data:
            viz.plot_ip_conversations(data['ip_conversations'])
        print("Visualisations saved to visualizations/")


def execute_alerts(args, _config):
    if not os.path.exists(args.pcap_file):
        print(f"Error: file not found: {args.pcap_file}")
        return

    from alerts.alert_manager import AlertManager

    analyzer = ProtocolAnalyzer(args.pcap_file)
    analyzer.load_pcap(args.pcap_file)
    results = analyzer.analyze_protocols()

    mgr = AlertManager()
    if hasattr(args, 'output') and args.output:
        mgr.add_file_channel(args.output)
    mgr.start()
    mgr.check(results)
    mgr.stop()

    summary = mgr.get_summary()
    print(f"\nAlert Summary:")
    print(f"  Total:           {summary['total']}")
    print(f"  Unacknowledged:  {summary.get('unacknowledged', 0)}")
    if summary.get('by_severity'):
        print("  By severity:")
        for sev, count in summary['by_severity'].items():
            print(f"    {sev}: {count}")
    if hasattr(args, 'output') and args.output:
        print(f"\n  Alerts written to: {args.output}")


def execute_fingerprint(args, _config):
    if not os.path.exists(args.pcap_file):
        print(f"Error: file not found: {args.pcap_file}")
        return

    from fingerprinting.device_fingerprinter import DeviceFingerprinter

    analyzer = ProtocolAnalyzer(args.pcap_file)
    analyzer.load_pcap(args.pcap_file)

    fp = DeviceFingerprinter()
    fp.process_packets(analyzer.packets)
    report = fp.generate_report()

    devices = report['devices']
    if args.show_randomized:
        devices = [d for d in devices if d['is_randomized']]

    print(f"\nDevice Fingerprinting: {args.pcap_file}")
    print(f"  Total devices:    {report['total_devices']}")
    print(f"  Randomized MACs:  {report['randomized_macs']}")
    if report['os_distribution']:
        print("\n  OS Distribution:")
        for os_name, count in sorted(report['os_distribution'].items(),
                                     key=lambda x: x[1], reverse=True):
            print(f"    {os_name:<25} {count}")

    if devices:
        print(f"\n  Devices ({len(devices)}):")
        for d in devices:
            rand_flag = " [RANDOMIZED]" if d['is_randomized'] else ""
            hostname  = d.get('hostname') or '-'
            os_guess  = d.get('os_guess') or 'Unknown'
            print(f"    {d['mac']}{rand_flag}")
            print(f"      Hostname:  {hostname}")
            print(f"      OS guess:  {os_guess}")
            if d.get('vendor_class'):
                print(f"      Vendor:    {d['vendor_class']}")
            if d.get('ja3_hashes'):
                print(f"      JA3:       {', '.join(d['ja3_hashes'][:3])}")
            if d.get('mdns_services'):
                print(f"      Services:  {', '.join(d['mdns_services'][:5])}")
            if d.get('aliases'):
                print(f"      Aliases:   {', '.join(d['aliases'])}")

    if hasattr(args, 'json') and args.json:
        with open(args.json, 'w') as fh:
            json.dump(report, fh, indent=2)
        print(f"\nJSON report saved: {args.json}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    import argparse

    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    # Configuration
    config_manager = ConfigManager()
    try:
        config = config_manager.load_config(args.config)
    except Exception:
        config = {}

    log_config = config.get('logging', {})
    if args.verbose:
        log_config['level'] = 'DEBUG'
    setup_logging(log_config)

    # Admin check
    if (not args.no_admin_check
            and config.get('security', {}).get('require_admin', True)
            and not SecurityUtils.require_admin()):
        print("Warning: root/admin privileges may be needed for raw packet capture.")
        print("         Use --no-admin-check to suppress this warning.")

    try:
        dispatch = {
            'capture':     execute_capture,
            'analyze':     execute_analyze,
            'scan':        execute_scan,
            'ssl-cert':    execute_ssl_cert,
            'geo':         execute_geo,
            'classify':    execute_classify,
            'voip':        execute_voip,
            'visualize':   execute_visualize,
            'alerts':      execute_alerts,
            'fingerprint': execute_fingerprint,
        }
        handler = dispatch.get(args.command)
        if handler:
            handler(args, config)
        else:
            parser.print_help()

    except KeyboardInterrupt:
        print('\nInterrupted.')
    except Exception as e:
        print(f"Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()


if __name__ == '__main__':
    main()
