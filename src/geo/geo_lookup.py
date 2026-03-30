"""
GeoIP Lookup Module

IP geolocation for network traffic analysis.
Supports MaxMind GeoIP2 database (preferred) and ip-api.com free API (fallback).
"""

import json
import logging
import socket
from functools import lru_cache
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    import urllib.request
    import urllib.error

try:
    import geoip2.database
    import geoip2.errors
    GEOIP2_AVAILABLE = True
except ImportError:
    GEOIP2_AVAILABLE = False


class GeoIPLookup:
    """
    IP geolocation using MaxMind GeoIP2 (local DB) or ip-api.com (free API fallback).

    Usage:
        geo = GeoIPLookup()                           # uses ip-api.com
        geo = GeoIPLookup(db_path='/path/GeoLite2-City.mmdb')  # uses local DB
        info = geo.lookup('8.8.8.8')
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path
        self._geoip_reader = None

        if GEOIP2_AVAILABLE and db_path:
            try:
                self._geoip_reader = geoip2.database.Reader(db_path)
                logger.info(f"GeoIP2 database loaded from {db_path}")
            except Exception as e:
                logger.warning(f"Could not load GeoIP2 database: {e}")

    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        try:
            import ipaddress
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    @lru_cache(maxsize=2048)
    def lookup(self, ip: str) -> Dict[str, Any]:
        """
        Look up geolocation for an IP address.

        Returns dict with: ip, country, country_code, region, city,
                           latitude, longitude, isp, org, is_private
        """
        if self._is_private_ip(ip):
            return {
                'ip': ip,
                'country': 'Private',
                'country_code': 'LAN',
                'region': 'Local Network',
                'city': 'Local',
                'latitude': None,
                'longitude': None,
                'isp': 'Local',
                'org': 'Private Network',
                'is_private': True,
            }

        if self._geoip_reader:
            try:
                response = self._geoip_reader.city(ip)
                return {
                    'ip': ip,
                    'country': response.country.name or 'Unknown',
                    'country_code': response.country.iso_code or 'XX',
                    'region': response.subdivisions.most_specific.name or 'Unknown',
                    'city': response.city.name or 'Unknown',
                    'latitude': response.location.latitude,
                    'longitude': response.location.longitude,
                    'isp': None,
                    'org': response.traits.organization,
                    'is_private': False,
                }
            except Exception as e:
                logger.debug(f"GeoIP2 lookup failed for {ip}: {e}")

        return self._lookup_ipapi(ip)

    def _lookup_ipapi(self, ip: str) -> Dict[str, Any]:
        """Look up IP via ip-api.com free API (45 req/min on free tier)."""
        default: Dict[str, Any] = {
            'ip': ip,
            'country': 'Unknown',
            'country_code': 'XX',
            'region': 'Unknown',
            'city': 'Unknown',
            'latitude': None,
            'longitude': None,
            'isp': 'Unknown',
            'org': 'Unknown',
            'is_private': False,
        }

        try:
            url = (
                f"http://ip-api.com/json/{ip}"
                "?fields=status,country,countryCode,regionName,city,lat,lon,isp,org"
            )
            if REQUESTS_AVAILABLE:
                resp = requests.get(url, timeout=5)
                data = resp.json()
            else:
                with urllib.request.urlopen(url, timeout=5) as r:
                    data = json.loads(r.read().decode())

            if data.get('status') == 'success':
                return {
                    'ip': ip,
                    'country': data.get('country', 'Unknown'),
                    'country_code': data.get('countryCode', 'XX'),
                    'region': data.get('regionName', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'latitude': data.get('lat'),
                    'longitude': data.get('lon'),
                    'isp': data.get('isp', 'Unknown'),
                    'org': data.get('org', 'Unknown'),
                    'is_private': False,
                }
        except Exception as e:
            logger.debug(f"ip-api.com lookup failed for {ip}: {e}")

        return default

    def batch_lookup(self, ips: List[str]) -> Dict[str, Dict[str, Any]]:
        """Look up geolocation for multiple IPs (deduplicates automatically)."""
        return {ip: self.lookup(ip) for ip in set(ips)}

    def enrich_conversations(
        self, conversations: Dict[str, int]
    ) -> List[Dict[str, Any]]:
        """
        Enrich IP conversation data with geolocation.

        Input:  {'192.168.1.1 -> 8.8.8.8': 150, ...}
        Output: [{'conversation': ..., 'count': ..., 'src_geo': {...}, 'dst_geo': {...}}, ...]
        """
        enriched = []
        for conversation, count in conversations.items():
            parts = conversation.split(' -> ')
            if len(parts) == 2:
                src_ip = parts[0].strip()
                dst_ip = parts[1].strip()
                enriched.append({
                    'conversation': conversation,
                    'count': count,
                    'src_geo': self.lookup(src_ip),
                    'dst_geo': self.lookup(dst_ip),
                })
        return enriched

    def format_location(self, geo: Dict[str, Any]) -> str:
        """Format geolocation as a human-readable string."""
        if geo.get('is_private'):
            return 'Private Network'
        parts = [geo.get('city', ''), geo.get('region', ''), geo.get('country', '')]
        return ', '.join(p for p in parts if p and p != 'Unknown')

    def close(self):
        """Close any open database connections."""
        if self._geoip_reader:
            self._geoip_reader.close()
            self._geoip_reader = None
