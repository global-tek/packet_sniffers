"""
Device Fingerprinting Module

Identifies and tracks network devices using:
  - MAC address randomization detection (U/L bit)
  - DHCP Option 55 / 12 / 60 OS fingerprinting
  - JA3 TLS ClientHello fingerprinting
  - mDNS hostname and service discovery
  - Cross-MAC device correlation via hostname

All public methods return plain dicts (no dataclasses) consistent with the
rest of this codebase.
"""

import hashlib
import logging
import socket
import struct
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# GREASE values (RFC 8701) — must be excluded from JA3 hashes
# Values: 0x0a0a, 0x1a1a, 0x2a2a, …, 0xfafa  (step 0x1010)
# ---------------------------------------------------------------------------
_GREASE: frozenset = frozenset(range(0x0a0a, 0x10000, 0x1010))


# ---------------------------------------------------------------------------
# DHCP Option 55 OS fingerprint database
# Key: frozenset of requested option codes → OS label
# ---------------------------------------------------------------------------
_DHCP_OS_DB: Dict[frozenset, str] = {
    frozenset({1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252}): "Windows",
    frozenset({1, 3, 6, 15, 119, 95, 252, 46}):                            "macOS/iOS",
    frozenset({1, 3, 6, 15, 26, 28, 51, 58, 59, 43}):                      "Android",
    frozenset({1, 3, 6, 12, 15, 17, 28, 40}):                              "Linux",
    frozenset({1, 3, 6, 15, 44, 46, 47}):                                  "Linux (minimal)",
    frozenset({1, 3, 6, 15, 119, 252}):                                    "iOS/macOS (older)",
    frozenset({1, 3, 6, 44, 46, 47, 31, 33, 121, 249, 252, 43}):           "Windows (older)",
}

_VENDOR_CLASS_OS: Dict[str, str] = {
    "MSFT":        "Windows",
    "android":     "Android",
    "dhcpcd":      "Linux",
    "udhcp":       "Linux (BusyBox)",
    "iPhone":      "iOS",
    "iPad":        "iPadOS",
    "macOS":       "macOS",
    "OpenBSD":     "OpenBSD",
    "FreeBSD":     "FreeBSD",
}


# ---------------------------------------------------------------------------
# MACAnalyzer
# ---------------------------------------------------------------------------

class MACAnalyzer:
    """Static helpers for MAC address analysis."""

    @staticmethod
    def normalize_mac(mac: str) -> str:
        """Return lowercase colon-separated MAC, e.g. 'aa:bb:cc:dd:ee:ff'."""
        raw = mac.replace(':', '').replace('-', '').replace('.', '').lower()
        if len(raw) != 12:
            raise ValueError(f"Invalid MAC address: {mac!r}")
        return ':'.join(raw[i:i+2] for i in range(0, 12, 2))

    @staticmethod
    def is_locally_administered(mac: str) -> bool:
        """
        Return True if the U/L bit (bit 1 of first octet) is set, indicating
        the MAC is locally administered (randomized or spoofed).

        The second-least-significant bit of the first octet encodes the U/L
        flag: 0 = universally administered (OUI-assigned), 1 = locally
        administered.  In hex, first-octet chars 2, 6, A, E have this bit set.
        """
        raw = mac.replace(':', '').replace('-', '').replace('.', '')
        first_octet = int(raw[:2], 16)
        return bool(first_octet & 0x02)

    @staticmethod
    def is_multicast(mac: str) -> bool:
        """Return True if the I/G bit (LSB of first octet) is set."""
        raw = mac.replace(':', '').replace('-', '').replace('.', '')
        return bool(int(raw[:2], 16) & 0x01)

    @staticmethod
    def get_oui_prefix(mac: str) -> str:
        """Return the OUI (first 3 octets) in uppercase colon format."""
        raw = mac.replace(':', '').replace('-', '').replace('.', '').upper()
        return ':'.join(raw[i:i+2] for i in range(0, 6, 2))


# ---------------------------------------------------------------------------
# DHCPFingerprinter
# ---------------------------------------------------------------------------

class DHCPFingerprinter:
    """
    Parses DHCP packets (scapy BOOTP/DHCP layers) and identifies the client OS
    via Option 55 (Parameter Request List), Option 12 (hostname), and
    Option 60 (Vendor Class Identifier).
    """

    @staticmethod
    def _jaccard(a: Set[int], b: Set[int]) -> float:
        if not a and not b:
            return 1.0
        union = a | b
        return len(a & b) / len(union)

    @classmethod
    def identify_os(cls, prl: List[int],
                    vendor_class: Optional[str] = None) -> Optional[str]:
        """
        Return an OS guess string, or None if confidence is too low.

        Steps:
          1. Exact PRL match in _DHCP_OS_DB
          2. Vendor Class prefix match in _VENDOR_CLASS_OS
          3. Jaccard similarity ≥ 0.60 fallback
        """
        prl_set = frozenset(prl)

        # Exact match
        if prl_set in _DHCP_OS_DB:
            return _DHCP_OS_DB[prl_set]

        # Vendor class prefix
        if vendor_class:
            for prefix, os_name in _VENDOR_CLASS_OS.items():
                if vendor_class.startswith(prefix):
                    return os_name

        # Jaccard similarity fallback
        best_score = 0.0
        best_os = None
        for db_set, os_name in _DHCP_OS_DB.items():
            score = cls._jaccard(set(prl), set(db_set))
            if score > best_score:
                best_score = score
                best_os = os_name

        if best_score >= 0.60:
            return f"{best_os} (similarity {best_score:.0%})"
        return None

    @staticmethod
    def parse_scapy_dhcp(packet) -> Dict[str, Any]:
        """
        Extract fingerprint fields from a scapy packet with DHCP layer.

        Returns dict with keys: mac, hostname, vendor_class, prl, os_guess
        """
        result: Dict[str, Any] = {
            'mac': None,
            'hostname': None,
            'vendor_class': None,
            'prl': [],
            'os_guess': None,
        }

        try:
            from scapy.layers.l2 import Ether
            from scapy.layers.dhcp import DHCP, BOOTP

            if not packet.haslayer(DHCP):
                return result

            if packet.haslayer(Ether):
                result['mac'] = packet[Ether].src

            if packet.haslayer(BOOTP):
                bootp = packet[BOOTP]
                # chaddr is the client hardware address (6 bytes for Ethernet)
                if bootp.chaddr:
                    raw_mac = bootp.chaddr[:6]
                    if len(raw_mac) == 6:
                        result['mac'] = ':'.join(f'{b:02x}' for b in raw_mac)

            dhcp = packet[DHCP]
            for opt in dhcp.options:
                if not isinstance(opt, tuple) or len(opt) < 2:
                    continue
                name, value = opt[0], opt[1]
                if name == 'param_req_list':
                    result['prl'] = list(value) if hasattr(value, '__iter__') else [value]
                elif name == 'hostname':
                    result['hostname'] = value.decode('utf-8', errors='replace') \
                        if isinstance(value, bytes) else str(value)
                elif name == 'vendor_class_id':
                    result['vendor_class'] = value.decode('utf-8', errors='replace') \
                        if isinstance(value, bytes) else str(value)

            result['os_guess'] = DHCPFingerprinter.identify_os(
                result['prl'], result.get('vendor_class')
            )

        except Exception as exc:
            logger.debug("DHCP parse error: %s", exc)

        return result


# ---------------------------------------------------------------------------
# JA3Fingerprinter
# ---------------------------------------------------------------------------

class JA3Fingerprinter:
    """
    Computes JA3 fingerprints from TLS ClientHello messages.

    JA3 string format (RFC reference: salesforce/ja3):
      "{TLSVersion},{CipherSuites},{Extensions},{EllipticCurves},{ECPointFormats}"
    GREASE values (RFC 8701) are excluded from all fields.
    The string is MD5-hashed to produce the final fingerprint.
    """

    @staticmethod
    def _exclude_grease(values: List[int]) -> List[int]:
        return [v for v in values if v not in _GREASE]

    @classmethod
    def compute_ja3(cls,
                    ssl_version: int,
                    cipher_suites: List[int],
                    extensions: List[int],
                    elliptic_curves: List[int],
                    ec_point_formats: List[int]) -> str:
        """
        Build the JA3 string and return its MD5 hex digest.
        All input lists have GREASE values pre-filtered.
        """
        cs = cls._exclude_grease(cipher_suites)
        ext = cls._exclude_grease(extensions)
        ec = cls._exclude_grease(elliptic_curves)
        epf = cls._exclude_grease(ec_point_formats)

        ja3_str = (
            f"{ssl_version},"
            f"{'-'.join(str(c) for c in cs)},"
            f"{'-'.join(str(e) for e in ext)},"
            f"{'-'.join(str(c) for c in ec)},"
            f"{'-'.join(str(f) for f in epf)}"
        )
        return hashlib.md5(ja3_str.encode()).hexdigest()

    @classmethod
    def compute_ja3_from_packet(cls, packet) -> Optional[str]:
        """
        Attempt to extract a JA3 hash from a scapy TLS packet.

        Works with scapy's TLS layer (requires scapy[complete] or
        scapy-ssl_tls).  Returns None if the packet does not contain a
        ClientHello or if parsing fails.
        """
        try:
            # scapy TLS support path
            from scapy.layers.tls.handshake import TLSClientHello
            from scapy.layers.tls.record import TLS

            if not packet.haslayer(TLSClientHello):
                return None

            ch = packet[TLSClientHello]
            ssl_version = getattr(ch, 'version', 0)
            cipher_suites = [int(c) for c in getattr(ch, 'ciphers', [])]

            ext_types: List[int] = []
            elliptic_curves: List[int] = []
            ec_point_formats: List[int] = []

            for ext in getattr(ch, 'ext', []) or []:
                ext_type = getattr(ext, 'type', None)
                if ext_type is None:
                    continue
                if ext_type not in _GREASE:
                    ext_types.append(ext_type)

                # supported_groups (0x000a) → elliptic curves
                if ext_type == 0x000a:
                    groups = getattr(ext, 'groups', []) or []
                    elliptic_curves = [int(g) for g in groups]

                # ec_point_formats (0x000b)
                elif ext_type == 0x000b:
                    fmts = getattr(ext, 'ecpl', []) or []
                    ec_point_formats = [int(f) for f in fmts]

            return cls.compute_ja3(ssl_version, cipher_suites, ext_types,
                                   elliptic_curves, ec_point_formats)

        except ImportError:
            logger.debug("scapy TLS layer not available for JA3 extraction")
        except Exception as exc:
            logger.debug("JA3 extraction error: %s", exc)

        return None

    @classmethod
    def compute_ja3_from_raw(cls, data: bytes) -> Optional[str]:
        """
        Parse a raw TLS record byte string and extract a JA3 hash.

        Supports the common case where a raw UDP/TCP payload begins with a
        TLS ClientHello record (type=0x16, version 0x0301-0x0303).
        Returns None if the bytes don't look like a ClientHello.
        """
        try:
            if len(data) < 5:
                return None

            # TLS record header: type(1) version(2) length(2)
            rec_type = data[0]
            if rec_type != 0x16:          # Handshake
                return None

            rec_version = struct.unpack('!H', data[1:3])[0]
            if rec_version not in (0x0301, 0x0302, 0x0303, 0x0304):
                return None

            rec_len = struct.unpack('!H', data[3:5])[0]
            if len(data) < 5 + rec_len:
                return None

            # Handshake header: type(1) length(3)
            hs = data[5:5 + rec_len]
            if not hs or hs[0] != 0x01:   # ClientHello
                return None

            hs_len = struct.unpack('!I', b'\x00' + hs[1:4])[0]
            body = hs[4:4 + hs_len]
            if len(body) < 34:
                return None

            offset = 0
            ssl_version = struct.unpack('!H', body[offset:offset+2])[0]
            offset += 2 + 32              # version + random

            # session id
            sid_len = body[offset]; offset += 1 + sid_len

            # cipher suites
            cs_len = struct.unpack('!H', body[offset:offset+2])[0]; offset += 2
            cipher_suites = []
            for i in range(0, cs_len, 2):
                cs = struct.unpack('!H', body[offset+i:offset+i+2])[0]
                if cs not in _GREASE:
                    cipher_suites.append(cs)
            offset += cs_len

            # compression methods
            cm_len = body[offset]; offset += 1 + cm_len

            if offset + 2 > len(body):
                return cls.compute_ja3(ssl_version, cipher_suites, [], [], [])

            ext_total = struct.unpack('!H', body[offset:offset+2])[0]; offset += 2
            ext_end = offset + ext_total

            ext_types: List[int] = []
            elliptic_curves: List[int] = []
            ec_point_formats: List[int] = []

            while offset + 4 <= ext_end and offset + 4 <= len(body):
                ext_type = struct.unpack('!H', body[offset:offset+2])[0]; offset += 2
                ext_len  = struct.unpack('!H', body[offset:offset+2])[0]; offset += 2
                ext_data = body[offset:offset+ext_len]; offset += ext_len

                if ext_type in _GREASE:
                    continue
                ext_types.append(ext_type)

                if ext_type == 0x000a and len(ext_data) >= 2:  # supported_groups
                    gl = struct.unpack('!H', ext_data[:2])[0]
                    for i in range(2, 2 + gl, 2):
                        if i + 2 <= len(ext_data):
                            g = struct.unpack('!H', ext_data[i:i+2])[0]
                            if g not in _GREASE:
                                elliptic_curves.append(g)

                elif ext_type == 0x000b and len(ext_data) >= 1:  # ec_point_formats
                    fl = ext_data[0]
                    ec_point_formats = list(ext_data[1:1+fl])

            return cls.compute_ja3(ssl_version, cipher_suites, ext_types,
                                   elliptic_curves, ec_point_formats)

        except Exception as exc:
            logger.debug("JA3 raw parse error: %s", exc)
            return None


# ---------------------------------------------------------------------------
# mDNSTracker
# ---------------------------------------------------------------------------

class mDNSTracker:
    """
    Extracts hostnames and service types from mDNS (Multicast DNS) traffic.

    mDNS: UDP port 5353, multicast 224.0.0.251 (IPv4) / ff02::fb (IPv6).
    We inspect DNS PTR records for .local hostnames and
    '_services._dns-sd._udp.local' queries for service discovery.
    """

    MDNS_PORT = 5353
    MDNS_V4   = '224.0.0.251'
    MDNS_V6   = 'ff02::fb'
    MAX_JUMPS = 10          # DNS pointer compression guard

    @staticmethod
    def _decompress_name(data: bytes, offset: int,
                         jumps: int = 0) -> tuple[str, int]:
        """
        Parse a DNS name starting at `offset` in `data`.

        Handles RFC 1035 label compression (0xC0 pointer prefix).
        Returns (name_str, new_offset_after_name_in_original_data).
        Raises ValueError on malformed input or too many pointer jumps.
        """
        if jumps > mDNSTracker.MAX_JUMPS:
            raise ValueError("Too many DNS pointer jumps (possible loop)")

        labels = []
        orig_offset = offset

        while offset < len(data):
            length = data[offset]

            if length == 0:
                offset += 1
                break

            if (length & 0xC0) == 0xC0:       # Pointer
                if offset + 1 >= len(data):
                    raise ValueError("Truncated DNS pointer")
                ptr = ((length & 0x3F) << 8) | data[offset + 1]
                name_from_ptr, _ = mDNSTracker._decompress_name(
                    data, ptr, jumps + 1
                )
                labels.append(name_from_ptr)
                offset += 2
                break

            offset += 1
            labels.append(data[offset:offset + length].decode('utf-8', errors='replace'))
            offset += length

        return '.'.join(labels), offset

    def process_packet(self, src_ip: str, src_mac: Optional[str],
                       udp_payload: bytes) -> Dict[str, Any]:
        """
        Parse one mDNS UDP payload and return extracted metadata.

        Returns:
          {
            'src_ip': str,
            'src_mac': str | None,
            'hostnames': [str, …],
            'services': [str, …],
          }
        """
        result: Dict[str, Any] = {
            'src_ip': src_ip,
            'src_mac': src_mac,
            'hostnames': [],
            'services': [],
        }

        try:
            if len(udp_payload) < 12:
                return result

            # DNS header: id(2) flags(2) qdcount(2) ancount(2) nscount(2) arcount(2)
            qdcount = struct.unpack('!H', udp_payload[4:6])[0]
            ancount = struct.unpack('!H', udp_payload[6:8])[0]

            offset = 12

            # Skip questions
            for _ in range(qdcount):
                _, offset = self._decompress_name(udp_payload, offset)
                offset += 4   # qtype + qclass

            # Parse answers
            for _ in range(ancount):
                if offset >= len(udp_payload):
                    break

                name, offset = self._decompress_name(udp_payload, offset)
                if offset + 10 > len(udp_payload):
                    break

                rtype  = struct.unpack('!H', udp_payload[offset:offset+2])[0]; offset += 2
                offset += 2   # rclass
                offset += 4   # ttl
                rdlen  = struct.unpack('!H', udp_payload[offset:offset+2])[0]; offset += 2
                rdata  = udp_payload[offset:offset+rdlen]; offset += rdlen

                # PTR record (type 12) — pointer to a name
                if rtype == 12:
                    try:
                        ptr_name, _ = self._decompress_name(udp_payload,
                                                            offset - rdlen)
                        target = ptr_name
                    except Exception:
                        target = rdata.decode('utf-8', errors='replace')

                    if target.endswith('.local'):
                        host = target.rstrip('.')
                        if not host.startswith('_'):
                            result['hostnames'].append(host)

                    # Service discovery: _services._dns-sd._udp.local
                    if '_services._dns-sd._udp' in name:
                        svc = target.rstrip('.')
                        if svc not in result['services']:
                            result['services'].append(svc)

        except Exception as exc:
            logger.debug("mDNS parse error from %s: %s", src_ip, exc)

        return result

    def process_scapy_packet(self, packet) -> Optional[Dict[str, Any]]:
        """
        Convenience wrapper: extract mDNS data from a scapy packet.
        Returns None if the packet is not an mDNS packet.
        """
        try:
            from scapy.layers.inet import IP, UDP
            from scapy.layers.l2 import Ether

            if not packet.haslayer(UDP):
                return None
            if packet[UDP].dport != self.MDNS_PORT and \
               packet[UDP].sport != self.MDNS_PORT:
                return None

            src_ip = packet[IP].src if packet.haslayer(IP) else None
            if src_ip is None:
                return None
            if packet[IP].dst not in (self.MDNS_V4,):
                return None

            src_mac = packet[Ether].src if packet.haslayer(Ether) else None
            payload = bytes(packet[UDP].payload)
            return self.process_packet(src_ip, src_mac, payload)

        except Exception as exc:
            logger.debug("mDNS scapy error: %s", exc)
            return None


# ---------------------------------------------------------------------------
# DeviceFingerprinter — orchestrator
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _empty_profile(mac: str) -> Dict[str, Any]:
    return {
        'mac':           mac,
        'is_randomized': MACAnalyzer.is_locally_administered(mac),
        'oui_prefix':    MACAnalyzer.get_oui_prefix(mac),
        'hostname':      None,
        'vendor_class':  None,
        'os_guess':      None,
        'ja3_hashes':    [],
        'mdns_services': [],
        'mdns_hostnames':[],
        'first_seen':    _now_iso(),
        'last_seen':     _now_iso(),
        'aliases':       [],
    }


class DeviceFingerprinter:
    """
    Orchestrates all fingerprinting sources into per-device profiles.

    Usage:
      fp = DeviceFingerprinter()
      fp.process_packets(scapy_packet_list)
      report = fp.generate_report()
    """

    def __init__(self):
        self._profiles: Dict[str, Dict[str, Any]] = {}   # mac → profile
        self._hostname_index: Dict[str, str] = {}         # hostname → canonical mac
        self._dhcp = DHCPFingerprinter()
        self._ja3  = JA3Fingerprinter()
        self._mdns = mDNSTracker()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_or_create(self, mac: str) -> Dict[str, Any]:
        mac = MACAnalyzer.normalize_mac(mac)
        if mac not in self._profiles:
            self._profiles[mac] = _empty_profile(mac)
        return self._profiles[mac]

    def _touch(self, profile: Dict[str, Any]) -> None:
        profile['last_seen'] = _now_iso()

    def _correlate_hostname(self, mac: str, hostname: str) -> None:
        """
        Link mac to an existing profile by hostname, creating an alias entry
        instead of a duplicate profile when two MACs share the same hostname
        (i.e., the device rotated its MAC).
        """
        mac = MACAnalyzer.normalize_mac(mac)
        if hostname in self._hostname_index:
            canonical = self._hostname_index[hostname]
            if canonical != mac:
                # Same physical device, different MAC — record alias
                canon_profile = self._profiles[canonical]
                if mac not in canon_profile['aliases']:
                    canon_profile['aliases'].append(mac)
                    logger.debug("MAC alias: %s → %s (hostname=%s)",
                                 mac, canonical, hostname)
        else:
            self._hostname_index[hostname] = mac

    # ------------------------------------------------------------------
    # Per-packet processing
    # ------------------------------------------------------------------

    def _process_dhcp(self, packet) -> None:
        try:
            from scapy.layers.dhcp import DHCP
            if not packet.haslayer(DHCP):
                return

            info = DHCPFingerprinter.parse_scapy_dhcp(packet)
            if not info.get('mac'):
                return

            profile = self._get_or_create(info['mac'])
            self._touch(profile)

            if info['hostname'] and not profile['hostname']:
                profile['hostname'] = info['hostname']
                self._correlate_hostname(info['mac'], info['hostname'])

            if info['vendor_class'] and not profile['vendor_class']:
                profile['vendor_class'] = info['vendor_class']

            if info['os_guess'] and not profile['os_guess']:
                profile['os_guess'] = info['os_guess']

        except Exception as exc:
            logger.debug("DHCP processing error: %s", exc)

    def _process_tls(self, packet) -> None:
        try:
            from scapy.layers.l2 import Ether
            from scapy.layers.inet import IP, TCP

            if not packet.haslayer(TCP):
                return

            src_mac = packet[Ether].src if packet.haslayer(Ether) else None
            if not src_mac:
                return

            # Try scapy TLS layer first, fall back to raw payload
            ja3_hash = self._ja3.compute_ja3_from_packet(packet)
            if ja3_hash is None:
                raw = bytes(packet[TCP].payload)
                ja3_hash = self._ja3.compute_ja3_from_raw(raw)

            if ja3_hash:
                profile = self._get_or_create(src_mac)
                self._touch(profile)
                if ja3_hash not in profile['ja3_hashes']:
                    profile['ja3_hashes'].append(ja3_hash)

        except Exception as exc:
            logger.debug("TLS/JA3 processing error: %s", exc)

    def _process_mdns(self, packet) -> None:
        try:
            result = self._mdns.process_scapy_packet(packet)
            if not result or not result.get('src_mac'):
                return

            mac = result['src_mac']
            profile = self._get_or_create(mac)
            self._touch(profile)

            for hostname in result['hostnames']:
                if hostname not in profile['mdns_hostnames']:
                    profile['mdns_hostnames'].append(hostname)
                if not profile['hostname']:
                    profile['hostname'] = hostname
                    self._correlate_hostname(mac, hostname)

            for svc in result['services']:
                if svc not in profile['mdns_services']:
                    profile['mdns_services'].append(svc)

        except Exception as exc:
            logger.debug("mDNS processing error: %s", exc)

    def process_packet(self, packet) -> None:
        """Process a single scapy packet through all fingerprinting sources."""
        try:
            from scapy.layers.dhcp import DHCP
            from scapy.layers.inet import UDP, TCP

            if packet.haslayer(DHCP):
                self._process_dhcp(packet)

            if packet.haslayer(TCP):
                self._process_tls(packet)

            if packet.haslayer(UDP):
                try:
                    from scapy.layers.inet import UDP
                    if (packet[UDP].dport == mDNSTracker.MDNS_PORT or
                            packet[UDP].sport == mDNSTracker.MDNS_PORT):
                        self._process_mdns(packet)
                except Exception:
                    pass

        except Exception as exc:
            logger.debug("process_packet error: %s", exc)

    def process_packets(self, packets) -> None:
        """Process an iterable of scapy packets."""
        for pkt in packets:
            self.process_packet(pkt)

    # ------------------------------------------------------------------
    # Report generation
    # ------------------------------------------------------------------

    def get_profiles(self) -> List[Dict[str, Any]]:
        """Return all device profiles as a list of dicts, sorted by first_seen."""
        return sorted(self._profiles.values(), key=lambda p: p['first_seen'])

    def generate_report(self) -> Dict[str, Any]:
        """
        Return a summary report dict:
          {
            'total_devices': int,
            'randomized_macs': int,
            'os_distribution': {os: count},
            'devices': [DeviceProfile, …],
          }
        """
        profiles = self.get_profiles()
        os_dist: Dict[str, int] = {}
        randomized = 0

        for p in profiles:
            if p['is_randomized']:
                randomized += 1
            os_label = p.get('os_guess') or 'Unknown'
            # Strip similarity annotation for grouping
            os_key = os_label.split(' (similarity')[0]
            os_dist[os_key] = os_dist.get(os_key, 0) + 1

        return {
            'total_devices':   len(profiles),
            'randomized_macs': randomized,
            'os_distribution': os_dist,
            'devices':         profiles,
        }
