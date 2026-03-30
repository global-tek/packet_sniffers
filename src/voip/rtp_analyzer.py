"""
VoIP and RTP Analysis Module

Parses SIP signalling, RTP media streams, and RTCP reports.
Calculates per-stream call quality metrics (jitter, packet loss, codec).
"""

import logging
import struct
from collections import Counter, defaultdict
from datetime import datetime
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

try:
    from scapy.layers.inet import IP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# SIP request methods (RFC 3261)
SIP_METHODS = frozenset({
    'INVITE', 'ACK', 'BYE', 'CANCEL', 'OPTIONS', 'REGISTER',
    'PRACK', 'SUBSCRIBE', 'NOTIFY', 'UPDATE', 'REFER', 'MESSAGE', 'INFO',
})

# RTP payload types (RFC 3551)
RTP_PAYLOAD_TYPES: Dict[int, str] = {
    0:  'PCMU (G.711 µ-law)',
    3:  'GSM',
    4:  'G.723',
    8:  'PCMA (G.711 A-law)',
    9:  'G.722',
    18: 'G.729',
    26: 'JPEG Video',
    31: 'H.261',
    34: 'H.263',
    96: 'Dynamic (Opus/VP8/H.264)',
    97: 'Dynamic',
    98: 'Dynamic',
    99: 'Dynamic',
}

# SIP default ports
SIP_PORTS = frozenset({5060, 5061})


class RTPPacket:
    """Parsed RTP packet fields (RFC 3550 §5.1)."""

    __slots__ = (
        'version', 'padding', 'extension', 'cc', 'marker',
        'payload_type', 'sequence_number', 'timestamp', 'ssrc',
        'payload_size', 'total_size',
    )

    def __init__(self, version: int, padding: bool, extension: bool, cc: int,
                 marker: bool, payload_type: int, sequence_number: int,
                 timestamp: int, ssrc: int, payload_size: int, total_size: int):
        self.version = version
        self.padding = padding
        self.extension = extension
        self.cc = cc
        self.marker = marker
        self.payload_type = payload_type
        self.sequence_number = sequence_number
        self.timestamp = timestamp
        self.ssrc = ssrc
        self.payload_size = payload_size
        self.total_size = total_size


class VoIPAnalyzer:
    """
    Analyses VoIP traffic: SIP call tracking, RTP stream metrics, basic RTCP.

    Usage:
        analyzer = VoIPAnalyzer()
        analyzer.analyze_scapy_packets(packet_list)
        report = analyzer.generate_report()
    """

    def __init__(self):
        # SSRC → list of RTPPacket
        self.rtp_streams: Dict[int, List[RTPPacket]] = defaultdict(list)
        # call-id → session dict
        self.sip_sessions: Dict[str, Dict[str, Any]] = {}

    # ------------------------------------------------------------------
    # RTP parsing
    # ------------------------------------------------------------------

    @staticmethod
    def parse_rtp_packet(data: bytes) -> Optional[RTPPacket]:
        """
        Parse raw bytes as an RTP packet.  Returns None if not valid RTP v2.

        RTP fixed header (12 bytes):
          V(2) P(1) X(1) CC(4) | M(1) PT(7) | Sequence(16)
          Timestamp(32) | SSRC(32)
        """
        if len(data) < 12:
            return None
        try:
            b0, b1 = data[0], data[1]
            version = (b0 >> 6) & 0x3
            if version != 2:
                return None

            padding   = bool((b0 >> 5) & 0x1)
            extension = bool((b0 >> 4) & 0x1)
            cc        = b0 & 0x0F
            marker    = bool((b1 >> 7) & 0x1)
            pt        = b1 & 0x7F

            # RTCP compound packets use PT 72–76 — skip those
            if 72 <= pt <= 76:
                return None

            seq, ts, ssrc = struct.unpack('!HII', data[2:12])

            header_len = 12 + cc * 4
            if extension and len(data) >= header_len + 4:
                ext_words = struct.unpack('!H', data[header_len + 2: header_len + 4])[0]
                header_len += 4 + ext_words * 4

            payload_size = max(0, len(data) - header_len)
            return RTPPacket(version, padding, extension, cc, marker,
                             pt, seq, ts, ssrc, payload_size, len(data))
        except struct.error:
            return None

    @staticmethod
    def is_likely_rtp(data: bytes, dst_port: int) -> bool:
        """
        Heuristic: is this UDP payload likely to be RTP?
        Conditions: ≥12 bytes, version==2, PT not in RTCP range, high port.
        """
        if len(data) < 12 or dst_port < 1024:
            return False
        version = (data[0] >> 6) & 0x3
        if version != 2:
            return False
        pt = data[1] & 0x7F
        return not (72 <= pt <= 76)

    # ------------------------------------------------------------------
    # SIP parsing
    # ------------------------------------------------------------------

    def _analyze_sip(self, data: bytes, src_ip: str, dst_ip: str,
                     src_port: int, dst_port: int):
        """Parse a SIP message and update session state."""
        try:
            text = data.decode('utf-8', errors='ignore')
            sep = '\r\n' if '\r\n' in text else '\n'
            lines = text.split(sep)
            if not lines:
                return

            first_line = lines[0].strip()
            method: Optional[str] = None
            status_code: Optional[int] = None

            for m in SIP_METHODS:
                if first_line.startswith(m):
                    method = m
                    break

            if not method and first_line.startswith('SIP/2.0'):
                parts = first_line.split(' ', 2)
                if len(parts) >= 2:
                    try:
                        status_code = int(parts[1])
                    except ValueError:
                        pass

            if not method and not status_code:
                return

            # Extract key headers
            headers: Dict[str, str] = {}
            for line in lines[1:]:
                if ':' in line:
                    key, _, value = line.partition(':')
                    headers[key.strip().lower()] = value.strip()

            call_id = headers.get('call-id') or headers.get('i', '')
            if not call_id:
                return

            if call_id not in self.sip_sessions:
                self.sip_sessions[call_id] = {
                    'call_id': call_id,
                    'from':    headers.get('from') or headers.get('f', ''),
                    'to':      headers.get('to')   or headers.get('t', ''),
                    'src_ip':  src_ip,
                    'dst_ip':  dst_ip,
                    'messages': [],
                    'state':   'new',
                }

            session = self.sip_sessions[call_id]
            session['messages'].append({
                'method':      method,
                'status_code': status_code,
                'timestamp':   datetime.now().isoformat(),
            })

            if method == 'INVITE':
                session['state'] = 'inviting'
            elif method == 'BYE':
                session['state'] = 'terminated'
            elif (status_code and 200 <= status_code < 300
                  and session['state'] == 'inviting'):
                session['state'] = 'active'

        except Exception as e:
            logger.debug(f"SIP parse error: {e}")

    # ------------------------------------------------------------------
    # Packet ingestion
    # ------------------------------------------------------------------

    def analyze_udp_payload(self, payload: bytes, src_ip: str, dst_ip: str,
                             src_port: int, dst_port: int):
        """Route a UDP payload to SIP or RTP handler."""
        if dst_port in SIP_PORTS or src_port in SIP_PORTS:
            self._analyze_sip(payload, src_ip, dst_ip, src_port, dst_port)
        elif self.is_likely_rtp(payload, dst_port):
            pkt = self.parse_rtp_packet(payload)
            if pkt:
                self.rtp_streams[pkt.ssrc].append(pkt)

    def analyze_scapy_packets(self, packets) -> Dict[str, Any]:
        """Feed a list of Scapy packets into the analyzer."""
        if not SCAPY_AVAILABLE:
            logger.error("Scapy is required for packet-level VoIP analysis.")
            return self.generate_report()

        for packet in packets:
            try:
                if not (packet.haslayer(IP) and packet.haslayer(UDP)):
                    continue
                ip  = packet[IP]
                udp = packet[UDP]
                payload = bytes(udp.payload)
                if payload:
                    self.analyze_udp_payload(
                        payload, ip.src, ip.dst, udp.sport, udp.dport
                    )
            except Exception as e:
                logger.debug(f"VoIP packet analysis error: {e}")

        return self.generate_report()

    # ------------------------------------------------------------------
    # Quality metrics
    # ------------------------------------------------------------------

    def calculate_stream_quality(self, ssrc: int) -> Dict[str, Any]:
        """
        Per-stream quality metrics:
          - packet_loss_rate (%)
          - out_of_order_count
          - jitter (RTP timestamp variance)
          - dominant codec
        """
        packets = self.rtp_streams.get(ssrc, [])
        base: Dict[str, Any] = {'ssrc': ssrc, 'packet_count': len(packets)}

        if len(packets) < 2:
            base['insufficient_data'] = True
            return base

        seq_nums = [p.sequence_number for p in packets]
        ts_vals  = [p.timestamp       for p in packets]

        expected = max(seq_nums) - min(seq_nums) + 1
        received = len(packets)
        loss_rate = max(0.0, (expected - received) / expected) * 100 if expected else 0.0

        out_of_order = sum(
            1 for i in range(1, len(seq_nums)) if seq_nums[i] < seq_nums[i - 1]
        )

        diffs = [abs(ts_vals[i] - ts_vals[i - 1]) for i in range(1, len(ts_vals))]
        if diffs:
            avg = sum(diffs) / len(diffs)
            variance = sum((d - avg) ** 2 for d in diffs) / len(diffs)
            jitter = variance ** 0.5
        else:
            jitter = 0.0

        pt_counter = Counter(p.payload_type for p in packets)
        dominant_pt = pt_counter.most_common(1)[0][0]
        codec = RTP_PAYLOAD_TYPES.get(dominant_pt, f'Unknown (PT={dominant_pt})')

        mean_size = sum(p.total_size for p in packets) / len(packets)

        return {
            'ssrc':                ssrc,
            'packet_count':        received,
            'expected_packets':    expected,
            'loss_rate_pct':       round(loss_rate, 2),
            'out_of_order_count':  out_of_order,
            'jitter':              round(jitter, 2),
            'codec':               codec,
            'payload_type':        dominant_pt,
            'mean_packet_size':    round(mean_size, 1),
        }

    # ------------------------------------------------------------------
    # Report
    # ------------------------------------------------------------------

    def generate_report(self) -> Dict[str, Any]:
        """Aggregate VoIP analysis results into a report dict."""
        stream_quality = [
            self.calculate_stream_quality(ssrc) for ssrc in self.rtp_streams
        ]

        valid_streams = [s for s in stream_quality if not s.get('insufficient_data')]
        avg_loss = (
            sum(s['loss_rate_pct'] for s in valid_streams) / len(valid_streams)
            if valid_streams else 0.0
        )

        total_rtp_packets = sum(len(v) for v in self.rtp_streams.values())

        return {
            'rtp_streams':         len(self.rtp_streams),
            'total_rtp_packets':   total_rtp_packets,
            'sip_sessions':        len(self.sip_sessions),
            'active_calls':        sum(
                1 for s in self.sip_sessions.values() if s.get('state') == 'active'
            ),
            'sip_calls':           list(self.sip_sessions.values()),
            'stream_quality':      stream_quality,
            'average_loss_rate':   round(avg_loss, 2),
        }
