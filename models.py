"""
Database Models for QR Code Scam Prevention System
"""
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class ScanHistory(db.Model):
    """Records every QR code scan performed by users."""
    __tablename__ = 'scan_history'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    scan_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    qr_data = db.Column(db.Text, nullable=False)
    data_type = db.Column(db.String(50), nullable=False)          # 'upi', 'url', 'text', 'unknown'
    risk_level = db.Column(db.String(20), nullable=False)          # 'safe', 'suspicious', 'scam'
    fraud_score = db.Column(db.Float, default=0.0)
    details = db.Column(db.Text)                                   # JSON string of detection details
    ip_address = db.Column(db.String(45))
    filename = db.Column(db.String(255))

    def to_dict(self):
        return {
            'id': self.id,
            'scan_date': self.scan_date.strftime('%Y-%m-%d %H:%M:%S'),
            'qr_data': self.qr_data,
            'data_type': self.data_type,
            'risk_level': self.risk_level,
            'fraud_score': self.fraud_score,
            'details': self.details,
            'filename': self.filename
        }


class BlacklistedPattern(db.Model):
    """Known fraudulent UPI IDs, domains, and patterns."""
    __tablename__ = 'blacklisted_patterns'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    pattern_type = db.Column(db.String(50), nullable=False)        # 'upi_id', 'domain', 'url_pattern'
    pattern_value = db.Column(db.String(500), nullable=False)
    description = db.Column(db.String(500))
    severity = db.Column(db.String(20), default='high')            # 'low', 'medium', 'high'
    reported_count = db.Column(db.Integer, default=1)
    added_date = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

    def to_dict(self):
        return {
            'id': self.id,
            'pattern_type': self.pattern_type,
            'pattern_value': self.pattern_value,
            'description': self.description,
            'severity': self.severity,
            'reported_count': self.reported_count,
            'added_date': self.added_date.strftime('%Y-%m-%d %H:%M:%S'),
            'is_active': self.is_active
        }


class WhitelistedPattern(db.Model):
    """Known safe / trusted UPI IDs, domains, and merchants."""
    __tablename__ = 'whitelisted_patterns'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    pattern_type = db.Column(db.String(50), nullable=False)        # 'upi_id', 'domain', 'merchant'
    pattern_value = db.Column(db.String(500), nullable=False)
    description = db.Column(db.String(500))
    verified = db.Column(db.Boolean, default=True)
    added_date = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'pattern_type': self.pattern_type,
            'pattern_value': self.pattern_value,
            'description': self.description,
            'verified': self.verified
        }


class ScamReport(db.Model):
    """User-submitted scam reports."""
    __tablename__ = 'scam_reports'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    report_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    qr_data = db.Column(db.Text, nullable=False)
    reporter_description = db.Column(db.Text)
    status = db.Column(db.String(20), default='pending')           # 'pending', 'verified', 'dismissed'
    scan_id = db.Column(db.Integer, db.ForeignKey('scan_history.id'), nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'report_date': self.report_date.strftime('%Y-%m-%d %H:%M:%S'),
            'qr_data': self.qr_data,
            'reporter_description': self.reporter_description,
            'status': self.status
        }
