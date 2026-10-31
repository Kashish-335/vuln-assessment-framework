"""
SQLAlchemy data models for Vulnerability Assessment Scans, Findings, and WAF Events.
"""
from datetime import datetime, timezone
import json
from sqlalchemy import Column, Integer, String, Text, Float, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from core.database import Base

def utc_now():
    return datetime.now(timezone.utc)

class Scan(Base):
    __tablename__ = 'scans'

    id = Column(Integer, primary_key=True, autoincrement=True)
    target_url = Column(String(500), nullable=False)
    target_ip = Column(String(100), nullable=False)
    target_host = Column(String(255), nullable=False)
    target_port = Column(Integer, default=80)
    status = Column(String(50), default='pending')  # pending, running, completed, failed
    phase = Column(String(50), default='initializing')  # initializing, nmap, spider, active_scan, processing, completed
    progress = Column(Integer, default=0)  # 0 to 100 percentage
    scan_mode = Column(String(50), default='direct')  # direct, waf_protected
    authorized = Column(Boolean, default=False)
    
    started_at = Column(DateTime, default=utc_now)
    completed_at = Column(DateTime, nullable=True)
    
    # Reconnaissance data
    nmap_results = Column(Text, default='{}')
    
    # Aggregated metrics
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)
    total_findings = Column(Integer, default=0)
    
    error_message = Column(Text, nullable=True)

    # Relationships
    findings = relationship('Finding', back_populates='scan', cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id': self.id,
            'target_url': self.target_url,
            'target_ip': self.target_ip,
            'target_host': self.target_host,
            'target_port': self.target_port,
            'status': self.status,
            'phase': self.phase,
            'progress': self.progress,
            'scan_mode': self.scan_mode,
            'authorized': self.authorized,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'high_count': self.high_count,
            'medium_count': self.medium_count,
            'low_count': self.low_count,
            'info_count': self.info_count,
            'total_findings': self.total_findings,
            'error_message': self.error_message,
            'nmap_results': json.loads(self.nmap_results) if self.nmap_results else {}
        }

class Finding(Base):
    __tablename__ = 'findings'

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey('scans.id'), nullable=False)
    
    title = Column(String(300), nullable=False)
    severity = Column(String(50), default='Informational')  # High, Medium, Low, Informational
    confidence = Column(String(50), default='Medium')  # High, Medium, Low
    owasp_category = Column(String(150), default='A05:2021-Security Misconfiguration')
    cwe_id = Column(String(50), default='CWE-16')
    
    url = Column(Text, nullable=True)
    method = Column(String(20), default='GET')
    parameter = Column(String(200), default='N/A')
    attack_payload = Column(Text, default='')
    evidence = Column(Text, default='')
    description = Column(Text, default='')
    remediation = Column(Text, default='')
    cvss_score = Column(Float, default=0.0)
    reference_links = Column(Text, default='')

    scan = relationship('Scan', back_populates='findings')

    def to_dict(self):
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'title': self.title,
            'severity': self.severity,
            'confidence': self.confidence,
            'owasp_category': self.owasp_category,
            'cwe_id': self.cwe_id,
            'url': self.url,
            'method': self.method,
            'parameter': self.parameter,
            'attack_payload': self.attack_payload,
            'evidence': self.evidence,
            'description': self.description,
            'remediation': self.remediation,
            'cvss_score': self.cvss_score,
            'reference_links': self.reference_links
        }

class WafEvent(Base):
    __tablename__ = 'waf_events'

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=utc_now)
    client_ip = Column(String(100), nullable=False)
    attack_type = Column(String(100), nullable=False)  # SQLi, XSS, PathTraversal, CommandInjection, RateLimit
    rule_id = Column(String(100), nullable=False)
    rule_description = Column(String(300), nullable=True)
    matched_pattern = Column(Text, nullable=True)
    http_method = Column(String(20), default='GET')
    request_url = Column(Text, nullable=False)
    location = Column(String(50), default='query')  # query, body, header, cookie, ip
    payload_snippet = Column(Text, nullable=True)
    user_agent = Column(Text, nullable=True)
    action = Column(String(50), default='BLOCKED_403')

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'client_ip': self.client_ip,
            'attack_type': self.attack_type,
            'rule_id': self.rule_id,
            'rule_description': self.rule_description,
            'matched_pattern': self.matched_pattern,
            'http_method': self.http_method,
            'request_url': self.request_url,
            'location': self.location,
            'payload_snippet': self.payload_snippet,
            'user_agent': self.user_agent,
            'action': self.action
        }
