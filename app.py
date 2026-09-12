"""
QR Code Scam Prevention System
Main Flask Application

Usage:
    python app.py

Technologies: Python, Flask, SQLAlchemy, Pyzbar, Pillow
"""
import os
import json
import uuid
from datetime import datetime

from flask import (Flask, render_template, request, redirect,
                   url_for, flash, jsonify)
from werkzeug.utils import secure_filename

from config import config
from models import db, ScanHistory, BlacklistedPattern, WhitelistedPattern, ScamReport
from qr_decoder import decode_qr_image, decode_qr_text
from detection import analyze_qr_data


def create_app(config_name='default'):
    """Application factory."""
    app = Flask(__name__)
    app.config.from_object(config[config_name])

    # Ensure upload folder exists
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    # Initialize extensions
    db.init_app(app)

    # Create tables & seed data
    with app.app_context():
        db.create_all()
        seed_database()

    register_routes(app)
    return app


def seed_database():
    """Seed the database with default blacklisted and whitelisted patterns."""
    # Only seed if tables are empty
    if BlacklistedPattern.query.first() is not None:
        return

    blacklisted = [
        # Known scam UPI IDs (examples)
        BlacklistedPattern(pattern_type='upi_id', pattern_value='scammer@ybl',
                           description='Known scam UPI ID', severity='high'),
        BlacklistedPattern(pattern_type='upi_id', pattern_value='fakepay@paytm',
                           description='Reported fake payment UPI', severity='high'),
        BlacklistedPattern(pattern_type='upi_id', pattern_value='fraud123@okaxis',
                           description='Reported fraud UPI', severity='high'),
        BlacklistedPattern(pattern_type='upi_id', pattern_value='luckywinner@upi',
                           description='Lottery scam UPI', severity='high'),
        BlacklistedPattern(pattern_type='upi_id', pattern_value='prizeclaim@ybl',
                           description='Prize claim scam', severity='high'),

        # Known phishing domains
        BlacklistedPattern(pattern_type='domain', pattern_value='paytem-verify.com',
                           description='Paytm phishing domain', severity='high'),
        BlacklistedPattern(pattern_type='domain', pattern_value='phonepay-login.xyz',
                           description='PhonePe phishing domain', severity='high'),
        BlacklistedPattern(pattern_type='domain', pattern_value='sbi-update-kyc.tk',
                           description='SBI KYC phishing', severity='high'),
        BlacklistedPattern(pattern_type='domain', pattern_value='free-recharge.ml',
                           description='Free recharge scam', severity='high'),
        BlacklistedPattern(pattern_type='domain', pattern_value='googIepay-offer.click',
                           description='Google Pay phishing (using I instead of l)', severity='high'),
    ]

    whitelisted = [
        WhitelistedPattern(pattern_type='upi_id', pattern_value='paytm@paytm',
                           description='Official Paytm', verified=True),
        WhitelistedPattern(pattern_type='upi_id', pattern_value='phonepe@ybl',
                           description='Official PhonePe', verified=True),
        WhitelistedPattern(pattern_type='domain', pattern_value='paytm.com',
                           description='Official Paytm website', verified=True),
        WhitelistedPattern(pattern_type='domain', pattern_value='phonepe.com',
                           description='Official PhonePe website', verified=True),
        WhitelistedPattern(pattern_type='domain', pattern_value='npci.org.in',
                           description='National Payments Corporation of India', verified=True),
        WhitelistedPattern(pattern_type='domain', pattern_value='sbi.co.in',
                           description='State Bank of India', verified=True),
        WhitelistedPattern(pattern_type='domain', pattern_value='hdfcbank.com',
                           description='HDFC Bank', verified=True),
        WhitelistedPattern(pattern_type='domain', pattern_value='icicibank.com',
                           description='ICICI Bank', verified=True),
    ]

    db.session.add_all(blacklisted + whitelisted)
    db.session.commit()


def allowed_file(filename):
    """Check if file extension is allowed."""
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp'}


def register_routes(app):
    """Register all application routes."""

    # ---- Page Routes ----

    @app.route('/')
    def index():
        """Homepage."""
        # Get stats
        total_scans = ScanHistory.query.count()
        scams_detected = ScanHistory.query.filter_by(risk_level='scam').count()
        suspicious_detected = ScanHistory.query.filter_by(risk_level='suspicious').count()
        safe_scans = ScanHistory.query.filter_by(risk_level='safe').count()

        stats = {
            'total_scans': total_scans,
            'scams_detected': scams_detected,
            'suspicious_detected': suspicious_detected,
            'safe_scans': safe_scans
        }
        return render_template('index.html', stats=stats)

    @app.route('/scanner')
    def scanner():
        """QR Code Scanner page."""
        return render_template('scanner.html')

    @app.route('/history')
    def history():
        """Scan history page."""
        page = request.args.get('page', 1, type=int)
        per_page = 15
        scans = ScanHistory.query.order_by(
            ScanHistory.scan_date.desc()
        ).paginate(page=page, per_page=per_page, error_out=False)
        return render_template('history.html', scans=scans)

    @app.route('/dashboard')
    def dashboard():
        """Dashboard with statistics."""
        total_scans = ScanHistory.query.count()
        scams_detected = ScanHistory.query.filter_by(risk_level='scam').count()
        suspicious_detected = ScanHistory.query.filter_by(risk_level='suspicious').count()
        safe_scans = ScanHistory.query.filter_by(risk_level='safe').count()
        blacklisted_count = BlacklistedPattern.query.filter_by(is_active=True).count()
        whitelisted_count = WhitelistedPattern.query.count()

        # Recent scans
        recent_scans = ScanHistory.query.order_by(
            ScanHistory.scan_date.desc()
        ).limit(10).all()

        stats = {
            'total_scans': total_scans,
            'scams_detected': scams_detected,
            'suspicious_detected': suspicious_detected,
            'safe_scans': safe_scans,
            'blacklisted_count': blacklisted_count,
            'whitelisted_count': whitelisted_count,
        }
        return render_template('dashboard.html', stats=stats, recent_scans=recent_scans)

    # ---- API Routes ----

    @app.route('/api/scan/upload', methods=['POST'])
    def api_scan_upload():
        """API: Scan an uploaded QR code image."""
        if 'qr_image' not in request.files:
            return jsonify({'success': False, 'error': 'No file uploaded.'}), 400

        file = request.files['qr_image']
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected.'}), 400

        if not allowed_file(file.filename):
            return jsonify({'success': False, 'error': 'Invalid file type. Allowed: PNG, JPG, JPEG, GIF, BMP, WEBP'}), 400

        # Save file
        filename = f"{uuid.uuid4().hex}_{secure_filename(file.filename)}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        # Decode QR
        decode_result = decode_qr_image(filepath)

        if not decode_result['success']:
            return jsonify({
                'success': False,
                'error': decode_result['error']
            }), 400

        # Run fraud detection
        blacklist = [b.to_dict() for b in BlacklistedPattern.query.filter_by(is_active=True).all()]
        whitelist = [w.to_dict() for w in WhitelistedPattern.query.all()]

        analysis = analyze_qr_data(
            decode_result['data'],
            decode_result['data_type'],
            decode_result['parsed'],
            blacklist,
            whitelist
        )

        # Save to database
        scan_record = ScanHistory(
            qr_data=decode_result['data'],
            data_type=decode_result['data_type'],
            risk_level=analysis['risk_level'],
            fraud_score=analysis['fraud_score'],
            details=json.dumps(analysis),
            ip_address=request.remote_addr,
            filename=filename
        )
        db.session.add(scan_record)
        db.session.commit()

        return jsonify({
            'success': True,
            'scan_id': scan_record.id,
            'qr_data': decode_result['data'],
            'data_type': decode_result['data_type'],
            'parsed': decode_result['parsed'],
            'analysis': analysis
        })

    @app.route('/api/scan/text', methods=['POST'])
    def api_scan_text():
        """API: Analyze QR code data entered as text."""
        data = request.get_json()
        if not data or not data.get('qr_text'):
            return jsonify({'success': False, 'error': 'No QR data provided.'}), 400

        qr_text = data['qr_text'].strip()

        # Decode / classify
        decode_result = decode_qr_text(qr_text)

        if not decode_result['success']:
            return jsonify({
                'success': False,
                'error': decode_result['error']
            }), 400

        # Run fraud detection
        blacklist = [b.to_dict() for b in BlacklistedPattern.query.filter_by(is_active=True).all()]
        whitelist = [w.to_dict() for w in WhitelistedPattern.query.all()]

        analysis = analyze_qr_data(
            decode_result['data'],
            decode_result['data_type'],
            decode_result['parsed'],
            blacklist,
            whitelist
        )

        # Save to database
        scan_record = ScanHistory(
            qr_data=decode_result['data'],
            data_type=decode_result['data_type'],
            risk_level=analysis['risk_level'],
            fraud_score=analysis['fraud_score'],
            details=json.dumps(analysis),
            ip_address=request.remote_addr
        )
        db.session.add(scan_record)
        db.session.commit()

        return jsonify({
            'success': True,
            'scan_id': scan_record.id,
            'qr_data': decode_result['data'],
            'data_type': decode_result['data_type'],
            'parsed': decode_result['parsed'],
            'analysis': analysis
        })

    @app.route('/api/report', methods=['POST'])
    def api_report_scam():
        """API: Submit a scam report."""
        data = request.get_json()
        if not data or not data.get('qr_data'):
            return jsonify({'success': False, 'error': 'No data provided.'}), 400

        report = ScamReport(
            qr_data=data['qr_data'],
            reporter_description=data.get('description', ''),
            scan_id=data.get('scan_id')
        )
        db.session.add(report)
        db.session.commit()

        return jsonify({'success': True, 'message': 'Scam report submitted successfully.'})

    @app.route('/api/stats')
    def api_stats():
        """API: Get platform statistics."""
        total_scans = ScanHistory.query.count()
        scams_detected = ScanHistory.query.filter_by(risk_level='scam').count()
        suspicious = ScanHistory.query.filter_by(risk_level='suspicious').count()
        safe = ScanHistory.query.filter_by(risk_level='safe').count()

        return jsonify({
            'total_scans': total_scans,
            'scams_detected': scams_detected,
            'suspicious': suspicious,
            'safe': safe,
            'blacklisted_patterns': BlacklistedPattern.query.filter_by(is_active=True).count(),
            'whitelisted_patterns': WhitelistedPattern.query.count()
        })

    @app.route('/api/history')
    def api_history():
        """API: Get scan history."""
        limit = request.args.get('limit', 20, type=int)
        scans = ScanHistory.query.order_by(
            ScanHistory.scan_date.desc()
        ).limit(limit).all()
        return jsonify({'scans': [s.to_dict() for s in scans]})


# ---- Entry Point ----
app = create_app('development')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
