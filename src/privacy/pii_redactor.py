"""
PII Redaction Module

Scans and redacts personally identifiable information from network capture
data before export.  Supports emails, phone numbers, SSNs, credit cards,
public IPs, MAC addresses, URLs with embedded credentials, and auth tokens.
"""

import re
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# PII detection patterns
# ---------------------------------------------------------------------------

PII_PATTERNS: Dict[str, re.Pattern] = {
    'email': re.compile(
        r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'
    ),
    'phone_us': re.compile(
        r'\b(?:\+?1[\s.\-]?)?\(?[2-9][0-9]{2}\)?[\s.\-]?[2-9][0-9]{2}[\s.\-]?[0-9]{4}\b'
    ),
    'ssn': re.compile(
        r'\b(?!000|666|9\d{2})\d{3}[-\s](?!00)\d{2}[-\s](?!0000)\d{4}\b'
    ),
    'credit_card': re.compile(
        r'\b(?:'
        r'4[0-9]{12}(?:[0-9]{3})?'          # Visa
        r'|5[1-5][0-9]{14}'                  # Mastercard
        r'|3[47][0-9]{13}'                   # Amex
        r'|6(?:011|5[0-9]{2})[0-9]{12}'     # Discover
        r')\b'
    ),
    'ipv4_public': re.compile(
        r'\b(?!'
        r'10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|127\.|169\.254\.|0\.'
        r')(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    ),
    'mac_address': re.compile(
        r'\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b'
    ),
    'url_with_creds': re.compile(
        r'https?://[^:@\s]+:[^@\s]+@[^\s]+'
    ),
    'bearer_token': re.compile(
        r'Bearer\s+[A-Za-z0-9\-._~+/]+=*',
        re.IGNORECASE,
    ),
    'basic_auth': re.compile(
        r'Basic\s+[A-Za-z0-9+/]+=*',
        re.IGNORECASE,
    ),
    'aws_access_key': re.compile(
        r'\b(AKIA|AIPA|AIIA|AROA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b'
    ),
    'jwt_token': re.compile(
        r'\beyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b'
    ),
}

REDACTION_PLACEHOLDERS: Dict[str, str] = {
    'email':          '[EMAIL]',
    'phone_us':       '[PHONE]',
    'ssn':            '[SSN]',
    'credit_card':    '[CREDIT_CARD]',
    'ipv4_public':    '[PUBLIC_IP]',
    'mac_address':    '[MAC]',
    'url_with_creds': '[URL_WITH_CREDS]',
    'bearer_token':   'Bearer [TOKEN]',
    'basic_auth':     'Basic [CREDENTIALS]',
    'aws_access_key': '[AWS_KEY]',
    'jwt_token':      '[JWT_TOKEN]',
}


class PIIRedactor:
    """
    Redacts PII from strings, dicts, and lists before export.

    Usage:
        redactor = PIIRedactor()
        clean_text = redactor.redact_string(raw_text)
        clean_data = redactor.redact_dict(analysis_results)
        findings   = redactor.scan_for_pii(data)  # audit without redacting
    """

    def __init__(
        self,
        enabled_types: Optional[List[str]] = None,
        redact_public_ips: bool = False,
    ):
        """
        Args:
            enabled_types:     Limit redaction to these PII types.
                               None = redact all types.
            redact_public_ips: If True, also redact public IP addresses.
                               Default False — useful when IPs are the analysis subject.
        """
        if enabled_types is not None:
            self.active_patterns = {
                k: v for k, v in PII_PATTERNS.items() if k in enabled_types
            }
        else:
            self.active_patterns = dict(PII_PATTERNS)

        if not redact_public_ips:
            self.active_patterns.pop('ipv4_public', None)

        self.redaction_stats: Dict[str, int] = {k: 0 for k in self.active_patterns}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def redact_string(self, text: str) -> str:
        """Replace all PII occurrences in *text* with placeholders."""
        if not isinstance(text, str) or not text:
            return text
        for pii_type, pattern in self.active_patterns.items():
            placeholder = REDACTION_PLACEHOLDERS.get(pii_type, f'[{pii_type.upper()}]')
            matches = pattern.findall(text)
            if matches:
                self.redaction_stats[pii_type] += len(matches)
                text = pattern.sub(placeholder, text)
        return text

    def redact_dict(
        self,
        data: Any,
        string_fields: Optional[List[str]] = None,
    ) -> Any:
        """
        Recursively redact PII from any nested dict/list structure.

        Args:
            data:          The data to sanitise.
            string_fields: If set, only redact string values whose key is in
                           this list.  None = redact every string value.
        """
        return self._redact_value(data, string_fields, current_key='')

    def scan_for_pii(self, data: Any) -> Dict[str, List[str]]:
        """
        Audit *data* for PII without modifying it.

        Returns a dict of {pii_type: [matched_values, ...]}
        (keys with no matches are omitted).
        """
        findings: Dict[str, List[str]] = {k: [] for k in self.active_patterns}
        self._scan_value(data, findings)
        return {k: v for k, v in findings.items() if v}

    def redact_http_data(self, http_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convenience wrapper: redact PII from HTTP analysis results.

        Targets sensitive HTTP fields (auth headers, cookies, user-agents, paths).
        """
        sensitive_fields = {
            'user_agent', 'host', 'path', 'cookie', 'authorization',
            'set-cookie', 'referer', 'x-forwarded-for', 'x-real-ip',
        }
        redacted = dict(http_data)
        if 'requests' in redacted:
            redacted['requests'] = [
                self._redact_value(req, list(sensitive_fields))
                for req in redacted['requests']
            ]
        return redacted

    def get_stats(self) -> Dict[str, int]:
        """Return per-type counts of redacted items (only non-zero entries)."""
        return {k: v for k, v in self.redaction_stats.items() if v > 0}

    def reset_stats(self):
        """Reset redaction counters."""
        self.redaction_stats = {k: 0 for k in self.active_patterns}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _redact_value(
        self,
        value: Any,
        string_fields: Optional[List[str]],
        current_key: str,
    ) -> Any:
        if isinstance(value, str):
            if string_fields is None or current_key in string_fields:
                return self.redact_string(value)
            return value
        if isinstance(value, dict):
            return {
                k: self._redact_value(v, string_fields, k)
                for k, v in value.items()
            }
        if isinstance(value, list):
            return [
                self._redact_value(item, string_fields, current_key)
                for item in value
            ]
        return value

    def _scan_value(self, value: Any, findings: Dict[str, List[str]]):
        if isinstance(value, str):
            for pii_type, pattern in self.active_patterns.items():
                findings[pii_type].extend(pattern.findall(value))
        elif isinstance(value, dict):
            for v in value.values():
                self._scan_value(v, findings)
        elif isinstance(value, list):
            for item in value:
                self._scan_value(item, findings)
