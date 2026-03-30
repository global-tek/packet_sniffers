"""
Machine Learning Traffic Classifier

Rule-based and ML-based classification of network traffic by type.
Anomaly detection via Isolation Forest.
"""

import logging
from collections import Counter
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False

try:
    from sklearn.ensemble import RandomForestClassifier, IsolationForest
    from sklearn.preprocessing import StandardScaler
    from sklearn.metrics import classification_report
    import joblib
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


# Well-known port → traffic category mapping
TRAFFIC_CATEGORIES: Dict[str, List[int]] = {
    'web':       [80, 443, 8080, 8443, 8000, 8888],
    'dns':       [53],
    'email':     [25, 110, 143, 465, 587, 993, 995],
    'ftp':       [20, 21],
    'ssh':       [22],
    'telnet':    [23],
    'database':  [1433, 1521, 3306, 5432, 6379, 27017],
    'rdp':       [3389],
    'voip':      [5060, 5061],
    'streaming': [1935, 8554],
    'p2p':       [6881, 6882, 6883, 51413],
    'ldap':      [389, 636],
    'smb':       [139, 445],
    'ntp':       [123],
    'snmp':      [161, 162],
    'syslog':    [514],
}

# Reverse lookup: port → category
_PORT_TO_CATEGORY: Dict[int, str] = {
    port: cat
    for cat, ports in TRAFFIC_CATEGORIES.items()
    for port in ports
}


class TrafficClassifier:
    """
    Classifies network traffic by type using rule-based heuristics (always)
    and a trained ML model (optional).

    Without sklearn: uses port-based rule heuristics only.
    With sklearn + training data: augments with RandomForest + IsolationForest anomaly detection.
    """

    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path
        self.classifier: Optional[RandomForestClassifier] = None
        self.anomaly_detector: Optional[IsolationForest] = None
        self.scaler: Optional[StandardScaler] = None
        self._is_trained = False

        if model_path and SKLEARN_AVAILABLE:
            self._load_model(model_path)

    # ------------------------------------------------------------------
    # Feature engineering
    # ------------------------------------------------------------------

    def extract_features(self, packet_info: Dict[str, Any]) -> Optional[List[float]]:
        """
        Extract a fixed-length numeric feature vector from packet metadata.

        Features: [src_port, dst_port, protocol, pkt_len,
                   is_private_src, is_private_dst,
                   is_web, is_dns, is_ssh, is_email, is_voip, is_database]
        """
        if not NUMPY_AVAILABLE:
            return None

        try:
            import ipaddress

            src_port = float(packet_info.get('src_port') or 0)
            dst_port = float(packet_info.get('dst_port') or 0)
            protocol = float(packet_info.get('protocol') or 0)
            pkt_len  = float(packet_info.get('length') or 0)

            def _is_private(ip: str) -> float:
                try:
                    return 1.0 if ipaddress.ip_address(ip).is_private else 0.0
                except ValueError:
                    return 0.0

            is_private_src = _is_private(packet_info.get('src_ip', ''))
            is_private_dst = _is_private(packet_info.get('dst_ip', ''))

            dst = int(dst_port)
            is_web      = 1.0 if dst in TRAFFIC_CATEGORIES['web']      else 0.0
            is_dns      = 1.0 if dst in TRAFFIC_CATEGORIES['dns']       else 0.0
            is_ssh      = 1.0 if dst in TRAFFIC_CATEGORIES['ssh']       else 0.0
            is_email    = 1.0 if dst in TRAFFIC_CATEGORIES['email']     else 0.0
            is_voip     = 1.0 if dst in TRAFFIC_CATEGORIES['voip']      else 0.0
            is_database = 1.0 if dst in TRAFFIC_CATEGORIES['database']  else 0.0

            return [src_port, dst_port, protocol, pkt_len,
                    is_private_src, is_private_dst,
                    is_web, is_dns, is_ssh, is_email, is_voip, is_database]

        except Exception as e:
            logger.debug(f"Feature extraction failed: {e}")
            return None

    # ------------------------------------------------------------------
    # Classification
    # ------------------------------------------------------------------

    def rule_based_classify(self, packet_info: Dict[str, Any]) -> str:
        """Fast port-based rule heuristic. Works without any ML dependencies."""
        dst_port = int(packet_info.get('dst_port') or 0)
        src_port = int(packet_info.get('src_port') or 0)

        cat = _PORT_TO_CATEGORY.get(dst_port) or _PORT_TO_CATEGORY.get(src_port)
        if cat:
            return cat

        protocol = int(packet_info.get('protocol') or 0)
        if protocol == 1:
            return 'icmp'
        if protocol == 17:
            return 'udp_other'
        return 'unknown'

    def classify_packet(self, packet_info: Dict[str, Any]) -> Dict[str, Any]:
        """Classify a single packet. Returns rule_based + optional ML results."""
        result: Dict[str, Any] = {
            'rule_based': self.rule_based_classify(packet_info),
            'ml_based': None,
            'anomaly_score': None,
            'is_anomaly': False,
        }

        if SKLEARN_AVAILABLE and NUMPY_AVAILABLE and self._is_trained:
            features = self.extract_features(packet_info)
            if features:
                try:
                    X = np.array(features).reshape(1, -1)
                    X_s = self.scaler.transform(X)
                    result['ml_based'] = self.classifier.predict(X_s)[0]
                    if self.anomaly_detector:
                        score = self.anomaly_detector.decision_function(X_s)[0]
                        result['anomaly_score'] = float(score)
                        result['is_anomaly'] = (
                            self.anomaly_detector.predict(X_s)[0] == -1
                        )
                except Exception as e:
                    logger.debug(f"ML classify failed: {e}")

        return result

    def classify_traffic_batch(
        self, packets: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Classify a batch of packets and return aggregate statistics.

        Returns: category_distribution, anomaly count, and top anomalies.
        """
        category_counts: Counter = Counter()
        anomalies: List[Dict[str, Any]] = []

        for packet in packets:
            result = self.classify_packet(packet)
            label = result['ml_based'] or result['rule_based']
            category_counts[label] += 1

            if result['is_anomaly']:
                anomalies.append({
                    'packet': packet,
                    'anomaly_score': result['anomaly_score'],
                })

        return {
            'total_packets': len(packets),
            'category_distribution': dict(category_counts),
            'anomalies_detected': len(anomalies),
            'anomalies': anomalies[:20],
            'ml_available': SKLEARN_AVAILABLE and self._is_trained,
        }

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    def train(
        self,
        packets: List[Dict[str, Any]],
        labels: Optional[List[str]] = None,
    ) -> bool:
        """
        Train the ML classifier on packet data.

        If labels is None, uses rule-based classification for self-supervised labels.
        Returns True on success.
        """
        if not (SKLEARN_AVAILABLE and NUMPY_AVAILABLE):
            logger.warning("scikit-learn / numpy not available — cannot train.")
            return False

        features_list: List[List[float]] = []
        label_list: List[str] = []

        for i, packet in enumerate(packets):
            feat = self.extract_features(packet)
            if feat is None:
                continue
            features_list.append(feat)
            if labels and i < len(labels):
                label_list.append(labels[i])
            else:
                label_list.append(self.rule_based_classify(packet))

        if len(features_list) < 10:
            logger.warning("Insufficient samples to train (need ≥10).")
            return False

        X = np.array(features_list)

        self.scaler = StandardScaler()
        X_s = self.scaler.fit_transform(X)

        self.classifier = RandomForestClassifier(
            n_estimators=100, random_state=42, n_jobs=-1
        )
        self.classifier.fit(X_s, label_list)

        self.anomaly_detector = IsolationForest(
            contamination=0.05, random_state=42, n_jobs=-1
        )
        self.anomaly_detector.fit(X_s)

        self._is_trained = True
        unique_cats = len(set(label_list))
        logger.info(
            f"Classifier trained: {len(features_list)} samples, "
            f"{unique_cats} categories"
        )
        return True

    def save_model(self, path: str):
        """Persist trained model to disk."""
        if not (SKLEARN_AVAILABLE and self._is_trained):
            logger.warning("No trained model to save.")
            return
        try:
            joblib.dump(
                {
                    'classifier': self.classifier,
                    'anomaly_detector': self.anomaly_detector,
                    'scaler': self.scaler,
                },
                path,
            )
            logger.info(f"Model saved to {path}")
        except Exception as e:
            logger.error(f"Error saving model: {e}")

    def _load_model(self, path: str):
        """Load a previously saved model from disk."""
        try:
            data = joblib.load(path)
            self.classifier = data['classifier']
            self.anomaly_detector = data['anomaly_detector']
            self.scaler = data['scaler']
            self._is_trained = True
            logger.info(f"Model loaded from {path}")
        except Exception as e:
            logger.warning(f"Could not load model from {path}: {e}")

    def get_feature_importance(self) -> Optional[Dict[str, float]]:
        """Return feature importances from the trained RandomForest."""
        if not (self._is_trained and self.classifier):
            return None
        names = [
            'src_port', 'dst_port', 'protocol', 'pkt_len',
            'is_private_src', 'is_private_dst',
            'is_web', 'is_dns', 'is_ssh', 'is_email', 'is_voip', 'is_database',
        ]
        importances = self.classifier.feature_importances_
        return dict(sorted(zip(names, importances), key=lambda x: x[1], reverse=True))
