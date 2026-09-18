"""Seed rich demo cybersecurity telemetry into SentinelAI SQLite database."""

import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta
import random

repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root / "apps" / "api"))
sys.path.insert(0, str(repo_root / "packages" / "models"))
sys.path.insert(0, str(repo_root / "packages" / "features"))
sys.path.insert(0, str(repo_root / "packages" / "detection"))
sys.path.insert(0, str(repo_root / "packages" / "ai_agent"))

from app.db.base import Base
from app.db.session import engine, SessionLocal
from app.models.flow import FlowModel, FlowFeatureModel
from app.models.detection import DetectionModel, DetectionEvidenceModel
from app.models.alert import (
    SecurityAlertModel,
    AlertSignalModel,
    AlertEvidenceModel,
    AlertEntityModel,
    AlertLifecycleHistoryModel,
)

def seed_database():
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()

    # Clear existing demo rows if any
    session.query(AlertLifecycleHistoryModel).delete()
    session.query(AlertEntityModel).delete()
    session.query(AlertEvidenceModel).delete()
    session.query(AlertSignalModel).delete()
    session.query(SecurityAlertModel).delete()
    session.query(DetectionEvidenceModel).delete()
    session.query(DetectionModel).delete()
    session.query(FlowFeatureModel).delete()
    session.query(FlowModel).delete()
    session.commit()

    now = datetime.now(timezone.utc)

    # 1. Populate Flows
    flows = []
    scenarios = [
        # (src_ip, dst_ip, src_p, dst_p, proto, pkts, bytes, dur)
        ("192.168.1.105", "10.0.0.15", 48291, 80, "TCP", 240, 184500, 4.2),
        ("185.220.101.5", "10.0.0.2", 51200, 22, "TCP", 1450, 92000, 15.6),
        ("45.33.32.156", "10.0.0.1", 39102, 443, "TCP", 85000, 128000000, 60.0),
        ("10.0.0.44", "198.51.100.22", 60102, 53, "UDP", 450, 68000, 120.0),
        ("172.16.0.88", "10.0.0.8", 41234, 445, "TCP", 1200, 84000, 8.5),
        ("192.168.1.50", "10.0.0.10", 38901, 8080, "TCP", 35, 2400, 0.4),
        ("192.168.1.60", "10.0.0.12", 40123, 3389, "TCP", 980, 62000, 12.0),
        ("103.21.244.0", "10.0.0.5", 55432, 80, "TCP", 54000, 78000000, 45.0),
        ("192.168.1.75", "10.0.0.25", 42000, 443, "TCP", 82, 12400, 1.8),
        ("192.168.1.99", "10.0.0.30", 49800, 8443, "TCP", 150, 18500, 3.1),
    ]

    for i, (sip, dip, sp, dp, proto, pkts, bts, dur) in enumerate(scenarios):
        flow_id = f"flow-{1000 + i}"
        start_t = now - timedelta(minutes=random.randint(5, 120))
        end_t = start_t + timedelta(seconds=dur)
        f = FlowModel(
            flow_id=flow_id,
            start_time=start_t,
            end_time=end_t,
            duration=dur,
            src_ip=sip,
            dst_ip=dip,
            src_port=sp,
            dst_port=dp,
            protocol=proto,
            packet_count=pkts,
            byte_count=bts,
            packets_fwd=int(pkts * 0.6),
            packets_bwd=int(pkts * 0.4),
            bytes_fwd=int(bts * 0.7),
            bytes_bwd=int(bts * 0.3),
            is_bidirectional=True,
            metadata_json={"interface": "eth0", "tap_mode": "passive", "vlan": 10},
        )
        flows.append(f)
        session.add(f)

    session.commit()

    # 2. Populate Detections
    detections_data = [
        ("det-101", "flow-1002", "DDOS", "CRITICAL", 0.98, "SynFloodDetector",
         "Sustained SYN flood volumetric attack exceeding 85,000 pps without completing 3-way handshakes."),
        ("det-102", "flow-1001", "BRUTE_FORCE", "HIGH", 0.92, "SSHBruteForceDetector",
         "Rapid repeated SSH connection attempts with high entropy handshake failures."),
        ("det-103", "flow-1003", "DATA_EXFILTRATION", "CRITICAL", 0.95, "DNSTunnelDetector",
         "Anomalous high-entropy DNS query sequence indicating DNS tunneling data exfiltration."),
        ("det-104", "flow-1004", "PORT_SCAN", "MEDIUM", 0.85, "PortScanSweepDetector",
         "Horizontal reconnaissance sweep scanning SMB/445 across multiple internal subnets."),
        ("det-105", "flow-1006", "BRUTE_FORCE", "HIGH", 0.89, "RDPAuthFailureDetector",
         "Bursty RDP connection spikes targeting administrative endpoint."),
        ("det-106", "flow-1007", "DDOS", "HIGH", 0.91, "HttpFloodDetector",
         "High rate HTTP GET flood against public gateway saturating connection pool."),
    ]

    for det_id, flw_id, threat, sev, conf, det_name, expl in detections_data:
        d = DetectionModel(
            detection_id=det_id,
            flow_id=flw_id,
            threat_type=threat,
            severity=sev,
            confidence=conf,
            is_threat=True,
            detector_name=det_name,
            explanation=expl,
            context_json={"sensor_id": "sensor-alpha-01", "site": "Headquarters-DC"},
            timestamp=now - timedelta(minutes=random.randint(10, 80)),
        )
        session.add(d)

        ev = DetectionEvidenceModel(
            detection_id=det_id,
            feature_name="packet_rate_pps",
            observed_value=85420.0 if threat == "DDOS" else 142.5,
            threshold=120.0,
            score=0.88,
            contribution=0.88,
            description="Packet rate significantly above baseline threshold",
        )
        session.add(ev)

    session.commit()

    # 3. Populate Security Alerts
    alerts_data = [
        {
            "alert_id": "ALT-2026-001",
            "threat_class": "DDOS",
            "severity": "CRITICAL",
            "status": "NEW",
            "confidence": 0.98,
            "risk_score": 96.5,
            "risk_level": "CRITICAL",
            "title": "Volumetric TCP SYN Flood targeting Core API Gateway",
            "description": "Massive packet burst detected from external source saturating ingress bandwidth without completing TCP handshakes.",
            "explanation": "Detector identified 85,000 packets/sec over 60s window with 99.4% SYN-only flags and zero application data exchange. Passive flow analysis confirms denial-of-service condition.",
            "flow_ids": ["flow-1002"],
            "mitre_attack": [{
                "tactic": "Impact",
                "tactic_id": "TA0040",
                "technique": "Network Denial of Service",
                "technique_id": "T1498.001"
            }],
            "entities": [
                ("IP", "45.33.32.156", "ATTACKER"),
                ("IP", "10.0.0.1", "VICTIM"),
                ("ENDPOINT", "api-gw.prod.internal", "TARGET")
            ],
            "signals": [
                ("det-101", "flow-1002", "DDOS", "CRITICAL", 0.98, "SynFloodDetector")
            ]
        },
        {
            "alert_id": "ALT-2026-002",
            "threat_class": "DATA_EXFILTRATION",
            "severity": "CRITICAL",
            "status": "IN_PROGRESS",
            "confidence": 0.95,
            "risk_score": 92.0,
            "risk_level": "CRITICAL",
            "title": "DNS Tunneling Covert Channel Exfiltration Detected",
            "description": "Continuous high-frequency DNS query bursts with Shannon entropy > 4.6 encoding sensitive payload fragments.",
            "explanation": "Bi-directional passive DNS telemetry revealed 450 sequential TXT queries to non-standard nameservers. Payload entropy analysis matches known iodine/dnscat2 patterns.",
            "flow_ids": ["flow-1003"],
            "mitre_attack": [{
                "tactic": "Exfiltration",
                "tactic_id": "TA0010",
                "technique": "Exfiltration Over Alternative Protocol",
                "technique_id": "T1048.003"
            }],
            "entities": [
                ("IP", "10.0.0.44", "COMPROMISED_HOST"),
                ("IP", "198.51.100.22", "C2_SERVER"),
                ("DOMAIN", "data-sync-cloud.xyz", "C2_DOMAIN")
            ],
            "signals": [
                ("det-103", "flow-1004", "DATA_EXFILTRATION", "CRITICAL", 0.95, "DNSTunnelDetector")
            ]
        },
        {
            "alert_id": "ALT-2026-003",
            "threat_class": "BRUTE_FORCE",
            "severity": "HIGH",
            "status": "NEW",
            "confidence": 0.92,
            "risk_score": 78.4,
            "risk_level": "HIGH",
            "title": "Distributed SSH Credential Stuffing Campaign",
            "description": "Over 1,450 failed authentication flows in 15 seconds against production bastion host.",
            "explanation": "Multiple TCP resets and short session durations observed on port 22. Behavior aligns with dictionary attacks targeting default administrative credentials.",
            "flow_ids": ["flow-1001"],
            "mitre_attack": [{
                "tactic": "Credential Access",
                "tactic_id": "TA0006",
                "technique": "Brute Force: Password Guessing",
                "technique_id": "T1110.001"
            }],
            "entities": [
                ("IP", "185.220.101.5", "ATTACKER"),
                ("IP", "10.0.0.2", "VICTIM")
            ],
            "signals": [
                ("det-102", "flow-1001", "BRUTE_FORCE", "HIGH", 0.92, "SSHBruteForceDetector")
            ]
        },
        {
            "alert_id": "ALT-2026-004",
            "threat_class": "PORT_SCAN",
            "severity": "MEDIUM",
            "status": "ACKNOWLEDGED",
            "confidence": 0.85,
            "risk_score": 58.0,
            "risk_level": "MEDIUM",
            "title": "Internal Lateral Movement Reconnaissance (SMB Sweep)",
            "description": "Sequential port probes targeting SMB (port 445) across internal subnet range.",
            "explanation": "Host 172.16.0.88 observed initiating single-SYN packets across 48 internal IP addresses within 8.5 seconds.",
            "flow_ids": ["flow-1004"],
            "mitre_attack": [{
                "tactic": "Discovery",
                "tactic_id": "TA0007",
                "technique": "Network Service Discovery",
                "technique_id": "T1046"
            }],
            "entities": [
                ("IP", "172.16.0.88", "SCANNER"),
                ("SUBNET", "10.0.0.0/24", "TARGET_RANGE")
            ],
            "signals": [
                ("det-104", "flow-1004", "PORT_SCAN", "MEDIUM", 0.85, "PortScanSweepDetector")
            ]
        },
        {
            "alert_id": "ALT-2026-005",
            "threat_class": "BRUTE_FORCE",
            "severity": "HIGH",
            "status": "RESOLVED",
            "confidence": 0.89,
            "risk_score": 72.5,
            "risk_level": "HIGH",
            "title": "RDP Brute Force against Finance Terminal Server",
            "description": "Burst of 980 connections within 12 seconds targeting RDP service on port 3389.",
            "explanation": "Traffic signatures match automated credential brute-forcing with randomized source ports and short TCP teardown intervals.",
            "flow_ids": ["flow-1006"],
            "mitre_attack": [{
                "tactic": "Credential Access",
                "tactic_id": "TA0006",
                "technique": "Brute Force: Password Spraying",
                "technique_id": "T1110.003"
            }],
            "entities": [
                ("IP", "192.168.1.60", "ATTACKER"),
                ("IP", "10.0.0.12", "VICTIM")
            ],
            "signals": [
                ("det-105", "flow-1006", "BRUTE_FORCE", "HIGH", 0.89, "RDPAuthFailureDetector")
            ]
        },
    ]

    for item in alerts_data:
        first_s = now - timedelta(minutes=random.randint(15, 60))
        last_s = now - timedelta(minutes=random.randint(1, 10))

        alert = SecurityAlertModel(
            alert_id=item["alert_id"],
            threat_class=item["threat_class"],
            severity=item["severity"],
            status=item["status"],
            confidence=item["confidence"],
            risk_score=item["risk_score"],
            risk_level=item["risk_level"],
            title=item["title"],
            description=item["description"],
            explanation=item["explanation"],
            flow_ids=item["flow_ids"],
            mitre_attack=item["mitre_attack"],
            first_seen=first_s,
            last_seen=last_s,
            risk_breakdown={
                "asset_criticality": 0.9 if item["severity"] == "CRITICAL" else 0.7,
                "threat_confidence": item["confidence"],
                "data_sensitivity": 0.85 if item["threat_class"] == "DATA_EXFILTRATION" else 0.5,
            }
        )
        session.add(alert)

        for sig_det_id, sig_flow_id, sig_threat, sig_sev, sig_conf, sig_det in item["signals"]:
            sig = AlertSignalModel(
                alert_id=item["alert_id"],
                detection_id=sig_det_id,
                flow_id=sig_flow_id,
                threat_type=sig_threat,
                severity=sig_sev,
                confidence=sig_conf,
                detector_type=sig_det,
                timestamp=first_s,
            )
            session.add(sig)

        for ent_type, ent_id, ent_role in item["entities"]:
            ent = AlertEntityModel(
                alert_id=item["alert_id"],
                entity_type=ent_type,
                identifier=ent_id,
                role=ent_role,
                confidence=0.95,
            )
            session.add(ent)

        ev = AlertEvidenceModel(
            alert_id=item["alert_id"],
            evidence_type="TELEMETRY_ANOMALY",
            description=f"Passive sensor anomaly detection correlated across {len(item['flow_ids'])} flow records.",
            raw_values={"confidence": item["confidence"], "risk": item["risk_score"]},
            confidence=item["confidence"],
            weight=1.0,
        )
        session.add(ev)

        hist = AlertLifecycleHistoryModel(
            alert_id=item["alert_id"],
            previous_status="CREATED",
            new_status=item["status"],
            changed_at=first_s,
            changed_by="system-correlator",
        )
        session.add(hist)

    session.commit()
    session.close()
    print("Successfully seeded SentinelAI SOC demonstration telemetry!")

if __name__ == "__main__":
    seed_database()
