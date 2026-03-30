"""
Real-time Alert Manager

Configurable rule-based alerting for network anomalies and threshold violations.
Supports console, file, and webhook output channels.
Background dispatch thread keeps the hot path non-blocking.
"""

import json
import logging
import queue
import threading
import time
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

try:
    import requests as _requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------

class AlertSeverity(Enum):
    INFO     = "INFO"
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"

    def __lt__(self, other: 'AlertSeverity') -> bool:
        _order = [AlertSeverity.INFO, AlertSeverity.LOW, AlertSeverity.MEDIUM,
                  AlertSeverity.HIGH, AlertSeverity.CRITICAL]
        return _order.index(self) < _order.index(other)

    def __le__(self, other: 'AlertSeverity') -> bool:
        return self == other or self < other


# ---------------------------------------------------------------------------
# Alert data class
# ---------------------------------------------------------------------------

class Alert:
    """An individual network alert."""

    _counter = 0
    _lock = threading.Lock()

    def __init__(
        self,
        severity: AlertSeverity,
        alert_type: str,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        source_ip: Optional[str] = None,
        dest_ip: Optional[str] = None,
    ):
        with Alert._lock:
            Alert._counter += 1
            self.id = Alert._counter

        self.timestamp    = datetime.now()
        self.severity     = severity
        self.alert_type   = alert_type
        self.message      = message
        self.details      = details or {}
        self.source_ip    = source_ip
        self.dest_ip      = dest_ip
        self.acknowledged = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id':           self.id,
            'timestamp':    self.timestamp.isoformat(),
            'severity':     self.severity.value,
            'alert_type':   self.alert_type,
            'message':      self.message,
            'details':      self.details,
            'source_ip':    self.source_ip,
            'dest_ip':      self.dest_ip,
            'acknowledged': self.acknowledged,
        }

    def __repr__(self) -> str:
        return f"Alert(#{self.id} {self.severity.value} {self.alert_type}: {self.message})"


# ---------------------------------------------------------------------------
# Alert rule
# ---------------------------------------------------------------------------

# check_fn signature: (data) -> None | str | (message, details, src_ip, dst_ip)
CheckFn = Callable[[Any], Optional[Any]]


class AlertRule:
    """
    A named rule that fires an Alert when check_fn returns a truthy value.

    check_fn should return:
      - None / False  → no alert
      - str           → message string (no extra detail)
      - tuple         → (message, details_dict, src_ip, dst_ip)
    """

    def __init__(
        self,
        name: str,
        check_fn: CheckFn,
        severity: AlertSeverity,
        cooldown_seconds: int = 60,
        enabled: bool = True,
    ):
        self.name             = name
        self.check_fn         = check_fn
        self.severity         = severity
        self.cooldown_seconds = cooldown_seconds
        self.enabled          = enabled
        self._last_triggered: float = 0.0

    def check(self, data: Any) -> Optional[Alert]:
        """Evaluate the rule; return an Alert if triggered."""
        if not self.enabled:
            return None
        if time.monotonic() - self._last_triggered < self.cooldown_seconds:
            return None
        try:
            result = self.check_fn(data)
            if not result:
                return None
            self._last_triggered = time.monotonic()
            if isinstance(result, tuple):
                message, details, src_ip, dst_ip = (list(result) + [None, None, None])[:4]
            else:
                message, details, src_ip, dst_ip = str(result), {}, None, None
            return Alert(self.severity, self.name, message, details, src_ip, dst_ip)
        except Exception as e:
            logger.debug(f"Rule '{self.name}' check error: {e}")
            return None


# ---------------------------------------------------------------------------
# Output channels
# ---------------------------------------------------------------------------

class AlertChannel:
    """Base class for alert output channels."""

    def send(self, alert: Alert):
        raise NotImplementedError


class ConsoleAlertChannel(AlertChannel):
    """Coloured console output for alerts."""

    _COLORS = {
        AlertSeverity.INFO:     '\033[94m',
        AlertSeverity.LOW:      '\033[92m',
        AlertSeverity.MEDIUM:   '\033[93m',
        AlertSeverity.HIGH:     '\033[91m',
        AlertSeverity.CRITICAL: '\033[95m',
    }
    _RESET = '\033[0m'

    def __init__(self, min_severity: AlertSeverity = AlertSeverity.INFO):
        self.min_severity = min_severity

    def send(self, alert: Alert):
        if alert.severity < self.min_severity:
            return
        color = self._COLORS.get(alert.severity, '')
        ts = alert.timestamp.strftime('%H:%M:%S')
        print(
            f"{color}[{ts}] [{alert.severity.value}] "
            f"{alert.alert_type}: {alert.message}{self._RESET}"
        )


class FileAlertChannel(AlertChannel):
    """Append JSON-serialised alerts to a file (one per line)."""

    def __init__(self, filepath: str, min_severity: AlertSeverity = AlertSeverity.INFO):
        self.filepath     = filepath
        self.min_severity = min_severity
        self._lock        = threading.Lock()

    def send(self, alert: Alert):
        if alert.severity < self.min_severity:
            return
        try:
            with self._lock:
                with open(self.filepath, 'a') as fh:
                    fh.write(json.dumps(alert.to_dict()) + '\n')
        except Exception as e:
            logger.error(f"FileAlertChannel write error: {e}")


class WebhookAlertChannel(AlertChannel):
    """POST alert JSON to a webhook URL."""

    def __init__(
        self,
        webhook_url: str,
        min_severity: AlertSeverity = AlertSeverity.MEDIUM,
        timeout: float = 5.0,
    ):
        self.webhook_url  = webhook_url
        self.min_severity = min_severity
        self.timeout      = timeout

    def send(self, alert: Alert):
        if alert.severity < self.min_severity:
            return
        if not REQUESTS_AVAILABLE:
            logger.warning("requests not installed — webhook alerts unavailable.")
            return
        try:
            _requests.post(self.webhook_url, json=alert.to_dict(), timeout=self.timeout)
        except Exception as e:
            logger.debug(f"WebhookAlertChannel error: {e}")


# ---------------------------------------------------------------------------
# Alert manager
# ---------------------------------------------------------------------------

class AlertManager:
    """
    Central alert manager.

    - Registers rules and output channels.
    - Evaluates rules via `check(data)` on any analysis result dict.
    - Fires arbitrary alerts via `fire(...)`.
    - Dispatches to channels asynchronously from a background thread.

    Usage:
        mgr = AlertManager()
        mgr.add_file_channel('alerts.jsonl')
        mgr.start()
        mgr.check(analysis_results)   # called after each analysis run
        mgr.stop()
    """

    def __init__(self, max_history: int = 1000):
        self.rules:         List[AlertRule]    = []
        self.channels:      List[AlertChannel] = []
        self.alert_history: List[Alert]        = []
        self._max_history   = max_history
        self._queue:        queue.Queue        = queue.Queue()
        self._running       = False
        self._thread:       Optional[threading.Thread] = None

        # Default console channel
        self.add_channel(ConsoleAlertChannel())

        # Built-in detection rules
        self._register_default_rules()

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def add_rule(self, rule: AlertRule):
        """Register a custom alert rule."""
        self.rules.append(rule)

    def add_channel(self, channel: AlertChannel):
        """Register an output channel."""
        self.channels.append(channel)

    def add_file_channel(
        self, filepath: str,
        min_severity: AlertSeverity = AlertSeverity.INFO,
    ):
        """Convenience: register a file output channel."""
        self.channels.append(FileAlertChannel(filepath, min_severity))

    def add_webhook_channel(
        self, url: str,
        min_severity: AlertSeverity = AlertSeverity.MEDIUM,
    ):
        """Convenience: register a webhook output channel."""
        self.channels.append(WebhookAlertChannel(url, min_severity))

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self):
        """Start the background dispatch thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._dispatch_loop, daemon=True, name='AlertDispatch'
        )
        self._thread.start()
        logger.info("AlertManager started.")

    def stop(self, timeout: float = 5.0):
        """Drain the queue and stop the dispatch thread."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=timeout)
        logger.info("AlertManager stopped.")

    # ------------------------------------------------------------------
    # Alert generation
    # ------------------------------------------------------------------

    def check(self, data: Any):
        """Evaluate all registered rules against *data*."""
        for rule in self.rules:
            alert = rule.check(data)
            if alert:
                self._queue.put(alert)

    def fire(
        self,
        severity: AlertSeverity,
        alert_type: str,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        source_ip: Optional[str] = None,
        dest_ip: Optional[str] = None,
    ):
        """Manually enqueue an alert."""
        self._queue.put(Alert(severity, alert_type, message, details, source_ip, dest_ip))

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def get_alerts(
        self,
        severity: Optional[AlertSeverity] = None,
        alert_type: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Return recent alerts, optionally filtered."""
        alerts = self.alert_history
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        if alert_type:
            alerts = [a for a in alerts if a.alert_type == alert_type]
        return [a.to_dict() for a in alerts[-limit:]]

    def acknowledge(self, alert_id: int):
        """Mark an alert as acknowledged by ID."""
        for alert in self.alert_history:
            if alert.id == alert_id:
                alert.acknowledged = True
                return

    def get_summary(self) -> Dict[str, Any]:
        """Return aggregate alert statistics."""
        if not self.alert_history:
            return {'total': 0}

        by_severity: Dict[str, int] = {}
        by_type:     Dict[str, int] = {}

        for a in self.alert_history:
            by_severity[a.severity.value] = by_severity.get(a.severity.value, 0) + 1
            by_type[a.alert_type]         = by_type.get(a.alert_type, 0) + 1

        return {
            'total':           len(self.alert_history),
            'unacknowledged':  sum(1 for a in self.alert_history if not a.acknowledged),
            'by_severity':     by_severity,
            'by_type':         by_type,
            'latest':          self.alert_history[-1].to_dict(),
        }

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _dispatch_loop(self):
        while self._running or not self._queue.empty():
            try:
                alert = self._queue.get(timeout=1.0)
                self._dispatch(alert)
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Alert dispatch loop error: {e}")

    def _dispatch(self, alert: Alert):
        self.alert_history.append(alert)
        if len(self.alert_history) > self._max_history:
            self.alert_history = self.alert_history[-self._max_history:]
        for channel in self.channels:
            try:
                channel.send(alert)
            except Exception as e:
                logger.error(f"Channel {type(channel).__name__} error: {e}")

    def _register_default_rules(self):
        """Built-in detection rules."""

        def _port_scan(data: Dict) -> Optional[Tuple]:
            if not isinstance(data, dict):
                return None
            ports = data.get('tcp_analysis', {}).get('ports', {})
            if len(ports) > 50:
                return (
                    f"Potential port scan: {len(ports)} unique destination ports",
                    {'port_count': len(ports)},
                    None, None,
                )
            return None

        def _dns_flood(data: Dict) -> Optional[Tuple]:
            if not isinstance(data, dict):
                return None
            domains = data.get('dns_analysis', {}).get('domains', {})
            hot = {d: c for d, c in domains.items() if c > 100}
            if hot:
                top5 = dict(list(hot.items())[:5])
                return (
                    f"High DNS query rate across {len(hot)} domains",
                    {'top_domains': top5},
                    None, None,
                )
            return None

        def _syn_flood(data: Dict) -> Optional[Tuple]:
            if not isinstance(data, dict):
                return None
            flags = data.get('tcp_analysis', {}).get('flags', {})
            syn = flags.get('SYN', 0)
            ack = flags.get('ACK', 0)
            if syn > 100 and syn > ack * 5:
                return (
                    f"Potential SYN flood: {syn} SYN vs {ack} ACK packets",
                    {'syn_count': syn, 'ack_count': ack},
                    None, None,
                )
            return None

        def _jumbo_frame(data: Dict) -> Optional[Tuple]:
            if not isinstance(data, dict):
                return None
            max_size = data.get('size_patterns', {}).get('max_size', 0)
            if max_size > 9000:
                return (
                    f"Jumbo frame detected: {max_size} bytes",
                    {'max_size': max_size},
                    None, None,
                )
            return None

        def _suspicious_domain(data: Dict) -> Optional[Tuple]:
            if not isinstance(data, dict):
                return None
            domains = data.get('dns_analysis', {}).get('domains', {})
            bad_tlds = {'.tk', '.ml', '.ga', '.cf', '.pw', '.xyz'}
            flagged = [d for d in domains if any(d.lower().endswith(t) for t in bad_tlds)]
            if flagged:
                return (
                    f"Suspicious TLD domains queried: {len(flagged)} found",
                    {'domains': flagged[:10]},
                    None, None,
                )
            return None

        self.add_rule(AlertRule('port_scan',         _port_scan,         AlertSeverity.HIGH,     300))
        self.add_rule(AlertRule('dns_flood',          _dns_flood,         AlertSeverity.MEDIUM,   120))
        self.add_rule(AlertRule('syn_flood',          _syn_flood,         AlertSeverity.CRITICAL,  60))
        self.add_rule(AlertRule('jumbo_frame',        _jumbo_frame,       AlertSeverity.LOW,        60))
        self.add_rule(AlertRule('suspicious_domain',  _suspicious_domain, AlertSeverity.MEDIUM,   180))
