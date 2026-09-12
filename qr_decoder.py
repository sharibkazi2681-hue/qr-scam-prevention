"""
QR Code Decoding Module
Handles decoding of QR codes from uploaded images.
Uses OpenCV and Pillow libraries.
"""

import re
from urllib.parse import urlparse, parse_qs
from PIL import Image
import cv2


def decode_qr_image(image_path):
    """
    Decode a QR code from an image file.
    """

    try:
        img = cv2.imread(image_path)

        if img is None:
            return {
                'success': False,
                'data': None,
                'data_type': 'unknown',
                'parsed': {},
                'error': 'Could not read the uploaded image.'
            }

        detector = cv2.QRCodeDetector()

        data, points, _ = detector.detectAndDecode(img)

        if not data:
            return {
                'success': False,
                'data': None,
                'data_type': 'unknown',
                'parsed': {},
                'error': 'No QR code found in the image. Please upload a clear QR code image.'
            }

        qr_data = data.strip()
        data_type, parsed = classify_and_parse(qr_data)

        return {
            'success': True,
            'data': qr_data,
            'data_type': data_type,
            'parsed': parsed,
            'error': None
        }

    except Exception as e:
        return {
            'success': False,
            'data': None,
            'data_type': 'unknown',
            'parsed': {},
            'error': f'Error processing image: {str(e)}'
        }


def decode_qr_text(text_data):
    """
    Process raw text data.
    """

    if not text_data or not text_data.strip():
        return {
            'success': False,
            'data': None,
            'data_type': 'unknown',
            'parsed': {},
            'error': 'No data provided.'
        }

    qr_data = text_data.strip()
    data_type, parsed = classify_and_parse(qr_data)

    return {
        'success': True,
        'data': qr_data,
        'data_type': data_type,
        'parsed': parsed,
        'error': None
    }


def classify_and_parse(data):
    """
    Classify QR data as UPI, URL, or plain text.
    """

    if data.lower().startswith('upi://'):
        return 'upi', parse_upi_link(data)

    url_pattern = re.compile(
        r'^https?://'
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'
        r'localhost|'
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        r'(?::\d+)?'
        r'(?:/?|[/?]\S+)$',
        re.IGNORECASE
    )

    if url_pattern.match(data):
        return 'url', parse_url(data)

    if re.match(r'^www\.\S+\.\S+', data, re.IGNORECASE):
        return 'url', parse_url('http://' + data)

    return 'text', {'raw_text': data}


def parse_upi_link(upi_string):
    """
    Parse a UPI deep link.
    """

    parsed = {}

    try:
        result = urlparse(upi_string)
        params = parse_qs(result.query)

        parsed['payee_address'] = params.get('pa', [None])[0]
        parsed['payee_name'] = params.get('pn', [None])[0]
        parsed['amount'] = params.get('am', [None])[0]
        parsed['currency'] = params.get('cu', ['INR'])[0]
        parsed['transaction_note'] = params.get('tn', [None])[0]
        parsed['merchant_code'] = params.get('mc', [None])[0]
        parsed['transaction_ref'] = params.get('tr', [None])[0]
        parsed['mode'] = params.get('mode', [None])[0]
        parsed['raw_query'] = result.query

    except Exception:
        parsed['raw_text'] = upi_string

    return parsed


def parse_url(url_string):
    """
    Parse a URL and extract components.
    """

    parsed = {}

    try:
        result = urlparse(url_string)

        parsed['scheme'] = result.scheme
        parsed['domain'] = result.netloc
        parsed['path'] = result.path
        parsed['query'] = result.query
        parsed['fragment'] = result.fragment
        parsed['full_url'] = url_string

        domain_parts = result.netloc.split('.')

        if len(domain_parts) >= 2:
            parsed['tld'] = domain_parts[-1].split(':')[0]
        else:
            parsed['tld'] = ''

        ip_pattern = re.compile(
            r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        )

        parsed['is_ip_address'] = bool(
            ip_pattern.match(result.netloc)
        )

    except Exception:
        parsed['raw_text'] = url_string

    return parsed