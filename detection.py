"""
Rule-Based Fraud Detection Engine
QR Code Scam Prevention System

This module implements the core fraud scoring algorithm.
Each rule checks a specific pattern and contributes to the overall fraud score.
"""
import re
from urllib.parse import urlparse


# ============================================================
# Trusted & Suspicious Pattern Databases (in-memory defaults)
# These are supplemented by the MySQL/SQLite database at runtime.
# ============================================================

TRUSTED_UPI_SUFFIXES = [
    '@ybl', '@paytm', '@okaxis', '@okhdfcbank', '@okicici',
    '@oksbi', '@upi', '@apl', '@axisbank', '@ibl',
    '@sbi', '@hdfcbank', '@icici', '@pnb', '@boi',
    '@unionbank', '@kotak', '@indus', '@federal', '@rbl',
    '@citi', '@sc', '@hsbc', '@dbs', '@yes',
]

SUSPICIOUS_UPI_KEYWORDS = [
    'lucky', 'winner', 'prize', 'cash', 'reward', 'free',
    'offer', 'bonus', 'gift', 'lottery', 'test',
    'temp', 'fake', 'scam', 'hack', 'phish',
    'money', 'earn', 'income', 'click', 'hurry',
]

TRUSTED_DOMAINS = [
    'google.com', 'paytm.com', 'phonepe.com', 'gpay.com',
    'npci.org.in', 'sbi.co.in', 'hdfcbank.com', 'icicibank.com',
    'axisbank.com', 'kotak.com', 'yesbank.in', 'rbi.org.in',
    'amazon.in', 'flipkart.com', 'swiggy.com', 'zomato.com',
    'ola.com', 'uber.com', 'irctc.co.in', 'gov.in',
    'microsoft.com', 'apple.com', 'github.com',
]

SUSPICIOUS_TLDS = [
    '.xyz', '.tk', '.ml', '.ga', '.cf', '.gq',
    '.top', '.work', '.click', '.buzz', '.surf',
    '.win', '.bid', '.loan', '.racing', '.party',
    '.review', '.stream', '.download', '.date', '.faith',
]

URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd',
    'ow.ly', 'buff.ly', 'adf.ly', 'cutt.ly', 'rb.gy',
    'shorturl.at', 'tiny.cc', 'lnkd.in', 's.id', 'clck.ru',
]

BRAND_MISSPELLINGS = {
    'paytm': ['paytem', 'paytim', 'payetm', 'paytam', 'paytml', 'paytmm'],
    'phonepe': ['phonepay', 'phonpe', 'phon3pe', 'fonepe', 'fonepay', 'phoneepy'],
    'googlepay': ['googIepay', 'g00glepay', 'googelpay', 'goooglepay', 'googleepay'],
    'gpay': ['g-pay', 'gpey', 'gpaay', 'gpai'],
    'amazon': ['amaz0n', 'amazan', 'arnazon', 'amazom', 'amazone'],
    'flipkart': ['flipkard', 'fl1pkart', 'flipcart', 'filpkart'],
    'swiggy': ['sw1ggy', 'swigy', 'swigggy', 'swiqgy'],
    'zomato': ['z0mato', 'zometo', 'zomat0', 'zornato'],
    'sbi': ['sb1', 's8i', 'sbii'],
    'hdfc': ['hdfcc', 'hdlc', 'hd1c'],
    'icici': ['ic1ci', 'icic1', 'icicci'],
}


# ============================================================
# Rule-Based Detection Functions
# ============================================================

def analyze_qr_data(qr_data, data_type, parsed_data, blacklist=None, whitelist=None):
    """
    Main analysis function. Runs all applicable rules and returns a fraud report.

    Args:
        qr_data (str): Raw QR code data.
        data_type (str): 'upi', 'url', or 'text'.
        parsed_data (dict): Parsed data from qr_decoder.
        blacklist (list): Database blacklisted patterns (optional).
        whitelist (list): Database whitelisted patterns (optional).

    Returns:
        dict: {
            'risk_level': 'safe' | 'suspicious' | 'scam',
            'fraud_score': float (0-100),
            'rules_triggered': list of rule results,
            'summary': str,
            'recommendation': str
        }
    """
    rules_triggered = []
    total_score = 0.0

    if data_type == 'upi':
        rules_triggered = run_upi_rules(parsed_data, qr_data, blacklist, whitelist)
    elif data_type == 'url':
        rules_triggered = run_url_rules(parsed_data, qr_data, blacklist, whitelist)
    elif data_type == 'text':
        rules_triggered = run_text_rules(qr_data, blacklist)

    # Calculate total fraud score
    for rule in rules_triggered:
        total_score += rule['score']

    # Cap at 100
    total_score = min(total_score, 100.0)

    # Classify risk level
    if total_score <= 20:
        risk_level = 'safe'
        summary = 'This QR code appears to be safe. No significant fraud indicators detected.'
        recommendation = 'You can proceed with caution. Always verify the recipient before making payments.'
    elif total_score <= 55:
        risk_level = 'suspicious'
        summary = 'This QR code shows some suspicious patterns. Exercise caution before proceeding.'
        recommendation = 'Verify the merchant/recipient details independently. Do not make payments if unsure.'
    else:
        risk_level = 'scam'
        summary = 'WARNING: This QR code has high fraud indicators. It is likely a scam!'
        recommendation = 'DO NOT proceed with this QR code. Do not make any payment. Report this to your bank or cyber crime helpline (1930).'

    return {
        'risk_level': risk_level,
        'fraud_score': round(total_score, 1),
        'rules_triggered': rules_triggered,
        'summary': summary,
        'recommendation': recommendation,
        'data_type': data_type,
        'total_rules_checked': len(rules_triggered)
    }


# ============================================================
# UPI-Specific Rules
# ============================================================

def run_upi_rules(parsed, raw_data, blacklist=None, whitelist=None):
    """Run all UPI-specific fraud detection rules."""
    rules = []
    pa = (parsed.get('payee_address') or '').lower()
    pn = (parsed.get('payee_name') or '').lower()
    amount = parsed.get('amount')
    note = (parsed.get('transaction_note') or '').lower()

    # Rule 1: Check if UPI ID is in blacklist
    if blacklist:
        for entry in blacklist:
            if entry['pattern_type'] == 'upi_id' and entry['pattern_value'].lower() in pa:
                rules.append({
                    'rule': 'Blacklisted UPI ID',
                    'description': f'The UPI ID matches a known blacklisted pattern: {entry["pattern_value"]}',
                    'status': 'fail',
                    'score': 40
                })
                break

    # Rule 2: Check if UPI ID is in whitelist
    is_whitelisted = False
    if whitelist:
        for entry in whitelist:
            if entry['pattern_type'] == 'upi_id' and entry['pattern_value'].lower() == pa:
                is_whitelisted = True
                rules.append({
                    'rule': 'Verified UPI ID',
                    'description': f'This UPI ID is a verified trusted entity: {entry.get("description", pa)}',
                    'status': 'pass',
                    'score': -10
                })
                break

    # Rule 3: Check UPI suffix
    has_known_suffix = any(pa.endswith(suffix) for suffix in TRUSTED_UPI_SUFFIXES)
    if pa and not has_known_suffix:
        rules.append({
            'rule': 'Unknown UPI Suffix',
            'description': f'The UPI ID uses an unrecognized bank/app suffix.',
            'status': 'fail',
            'score': 15
        })
    elif pa and has_known_suffix:
        rules.append({
            'rule': 'Valid UPI Suffix',
            'description': f'The UPI ID uses a recognized bank/app suffix.',
            'status': 'pass',
            'score': 0
        })

    # Rule 4: Suspicious keywords in UPI ID
    for keyword in SUSPICIOUS_UPI_KEYWORDS:
        if keyword in pa:
            rules.append({
                'rule': 'Suspicious Keyword in UPI ID',
                'description': f'The UPI ID contains suspicious keyword: "{keyword}"',
                'status': 'fail',
                'score': 15
            })
            break

    # Rule 5: Suspicious keywords in payee name
    for keyword in SUSPICIOUS_UPI_KEYWORDS:
        if pn and keyword in pn:
            rules.append({
                'rule': 'Suspicious Payee Name',
                'description': f'The payee name contains suspicious keyword: "{keyword}"',
                'status': 'warn',
                'score': 10
            })
            break

    # Rule 6: Brand misspelling in UPI ID or payee name
    for brand, misspellings in BRAND_MISSPELLINGS.items():
        for mis in misspellings:
            if mis in pa or mis in pn:
                rules.append({
                    'rule': 'Brand Name Misspelling',
                    'description': f'Possible misspelling of "{brand}" detected: "{mis}" — a common phishing technique.',
                    'status': 'fail',
                    'score': 25
                })
                break
        else:
            continue
        break

    # Rule 7: Check for unusually high amount
    if amount:
        try:
            amt_value = float(amount)
            if amt_value >= 10000:
                rules.append({
                    'rule': 'High Payment Amount',
                    'description': f'The QR code requests a payment of ₹{amt_value:,.2f}, which is unusually high.',
                    'status': 'warn',
                    'score': 10
                })
            elif amt_value > 0:
                rules.append({
                    'rule': 'Payment Amount',
                    'description': f'Payment amount: ₹{amt_value:,.2f}',
                    'status': 'pass',
                    'score': 0
                })
        except ValueError:
            rules.append({
                'rule': 'Invalid Amount Format',
                'description': 'The payment amount is not a valid number.',
                'status': 'fail',
                'score': 15
            })

    # Rule 8: Check for suspicious transaction note
    urgency_words = ['urgent', 'hurry', 'immediately', 'fast', 'quick', 'now', 'last chance', 'limited']
    for word in urgency_words:
        if word in note:
            rules.append({
                'rule': 'Urgency Language in Note',
                'description': f'The transaction note uses urgency language: "{word}" — a common social engineering tactic.',
                'status': 'warn',
                'score': 10
            })
            break

    # Rule 9: Missing payee name
    if not pn:
        rules.append({
            'rule': 'Missing Payee Name',
            'description': 'No payee name is specified in the QR code. Legitimate merchants usually include their name.',
            'status': 'warn',
            'score': 8
        })
    else:
        rules.append({
            'rule': 'Payee Name Present',
            'description': f'Payee name: {parsed.get("payee_name", "N/A")}',
            'status': 'pass',
            'score': 0
        })

    # Rule 10: Random/numeric UPI ID pattern
    if pa:
        username_part = pa.split('@')[0] if '@' in pa else pa
        digit_ratio = sum(c.isdigit() for c in username_part) / max(len(username_part), 1)
        if digit_ratio > 0.7 and len(username_part) > 6:
            rules.append({
                'rule': 'Random/Numeric UPI ID',
                'description': 'The UPI ID appears to be randomly generated with many digits — typical of throwaway accounts.',
                'status': 'fail',
                'score': 15
            })

    return rules


# ============================================================
# URL-Specific Rules
# ============================================================

def run_url_rules(parsed, raw_data, blacklist=None, whitelist=None):
    """Run all URL-specific fraud detection rules."""
    rules = []
    domain = (parsed.get('domain') or '').lower()
    scheme = (parsed.get('scheme') or '').lower()
    path = (parsed.get('path') or '').lower()
    tld = (parsed.get('tld') or '').lower()
    full_url = (parsed.get('full_url') or raw_data).lower()
    is_ip = parsed.get('is_ip_address', False)

    # Rule 1: Check if domain is blacklisted
    if blacklist:
        for entry in blacklist:
            if entry['pattern_type'] == 'domain' and entry['pattern_value'].lower() in domain:
                rules.append({
                    'rule': 'Blacklisted Domain',
                    'description': f'The domain matches a known blacklisted pattern: {entry["pattern_value"]}',
                    'status': 'fail',
                    'score': 40
                })
                break

    # Rule 2: Check if domain is whitelisted / trusted
    is_trusted = any(domain.endswith(td) for td in TRUSTED_DOMAINS)
    if whitelist:
        for entry in whitelist:
            if entry['pattern_type'] == 'domain' and entry['pattern_value'].lower() in domain:
                is_trusted = True
                break

    if is_trusted:
        rules.append({
            'rule': 'Trusted Domain',
            'description': f'The domain "{domain}" is a known trusted website.',
            'status': 'pass',
            'score': -5
        })

    # Rule 3: HTTPS check
    if scheme == 'http':
        rules.append({
            'rule': 'No HTTPS Encryption',
            'description': 'The URL uses HTTP instead of HTTPS. This means data is not encrypted.',
            'status': 'fail',
            'score': 15
        })
    elif scheme == 'https':
        rules.append({
            'rule': 'HTTPS Encryption',
            'description': 'The URL uses HTTPS encryption.',
            'status': 'pass',
            'score': 0
        })

    # Rule 4: Suspicious TLD
    for stld in SUSPICIOUS_TLDS:
        if f'.{tld}' == stld or domain.endswith(stld):
            rules.append({
                'rule': 'Suspicious TLD',
                'description': f'The domain uses a suspicious top-level domain ({stld}) often associated with fraud.',
                'status': 'fail',
                'score': 20
            })
            break

    # Rule 5: IP address instead of domain
    if is_ip:
        rules.append({
            'rule': 'IP Address URL',
            'description': 'The URL uses an IP address instead of a domain name — a red flag for phishing.',
            'status': 'fail',
            'score': 25
        })

    # Rule 6: URL shortener
    for shortener in URL_SHORTENERS:
        if shortener in domain:
            rules.append({
                'rule': 'URL Shortener Detected',
                'description': f'The URL uses a shortener ({shortener}) which hides the actual destination.',
                'status': 'warn',
                'score': 15
            })
            break

    # Rule 7: Excessive subdomains
    subdomain_count = len(domain.split('.')) - 2  # minus TLD and main domain
    if subdomain_count >= 3:
        rules.append({
            'rule': 'Excessive Subdomains',
            'description': f'The URL has {subdomain_count} subdomains — often used to mimic legitimate sites.',
            'status': 'fail',
            'score': 15
        })

    # Rule 8: Brand misspelling in domain
    for brand, misspellings in BRAND_MISSPELLINGS.items():
        for mis in misspellings:
            if mis in domain:
                rules.append({
                    'rule': 'Brand Misspelling in Domain',
                    'description': f'The domain contains a misspelling of "{brand}": "{mis}" — likely a phishing site.',
                    'status': 'fail',
                    'score': 30
                })
                break
        else:
            continue
        break

    # Rule 9: Very long URL
    if len(full_url) > 200:
        rules.append({
            'rule': 'Excessively Long URL',
            'description': 'The URL is unusually long, which can be used to hide malicious parameters.',
            'status': 'warn',
            'score': 10
        })

    # Rule 10: Contains suspicious path keywords
    suspicious_paths = ['login', 'signin', 'verify', 'account', 'secure', 'update', 'confirm',
                        'banking', 'wallet', 'password', 'otp', 'kyc']
    for sp in suspicious_paths:
        if sp in path:
            rules.append({
                'rule': 'Suspicious Path Keywords',
                'description': f'The URL path contains "{sp}" — commonly used in phishing pages.',
                'status': 'warn',
                'score': 10
            })
            break

    # Rule 11: Contains @ symbol (URL obfuscation)
    if '@' in full_url and not full_url.startswith('mailto:'):
        rules.append({
            'rule': 'URL Obfuscation (@)',
            'description': 'The URL contains an @ symbol, which can trick browsers into navigating to a different site.',
            'status': 'fail',
            'score': 25
        })

    return rules


# ============================================================
# Text-Specific Rules
# ============================================================

def run_text_rules(raw_data, blacklist=None):
    """Run rules for plain text QR content."""
    rules = []
    text = raw_data.lower()

    # Rule 1: Check blacklist
    if blacklist:
        for entry in blacklist:
            if entry['pattern_value'].lower() in text:
                rules.append({
                    'rule': 'Blacklisted Content',
                    'description': f'The content matches a known blacklisted pattern.',
                    'status': 'fail',
                    'score': 35
                })
                break

    # Rule 2: Contains phone number requesting call/SMS
    phone_pattern = re.compile(r'(?:call|sms|text|whatsapp|contact)\s*[\:\-]?\s*[\+]?\d{10,}', re.IGNORECASE)
    if phone_pattern.search(raw_data):
        rules.append({
            'rule': 'Phone Number Request',
            'description': 'The QR code asks you to call or message a phone number — be cautious.',
            'status': 'warn',
            'score': 15
        })

    # Rule 3: Urgency / pressure language
    urgency_words = ['urgent', 'hurry', 'act now', 'limited time', 'immediately',
                     'expires', 'last chance', 'don\'t miss', 'claim now', 'winner']
    for word in urgency_words:
        if word in text:
            rules.append({
                'rule': 'Urgency Language',
                'description': f'The content uses pressure tactics ("{word}") — a common scam indicator.',
                'status': 'fail',
                'score': 20
            })
            break

    # Rule 4: Money-related promises
    money_words = ['prize', 'lottery', 'cashback', 'reward', 'free money', 'won', 'winner',
                   'jackpot', 'earning', 'income', 'guaranteed']
    for word in money_words:
        if word in text:
            rules.append({
                'rule': 'Money Promises',
                'description': f'The content promises financial rewards ("{word}") — likely a scam.',
                'status': 'fail',
                'score': 25
            })
            break

    # Rule 5: Appears to be regular text
    if not rules:
        rules.append({
            'rule': 'Plain Text Content',
            'description': 'The QR code contains plain text. No fraud patterns detected, but verify the source.',
            'status': 'pass',
            'score': 5
        })

    return rules
