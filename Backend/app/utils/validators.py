"""
Validation Utilities
Input validation and data sanitization
"""

import re
import ipaddress
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlparse
import email_validator
from email_validator import validate_email as validate_email_format, EmailNotValidError

def validate_ip_address(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def validate_ipv4_address(ip: str) -> bool:
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ValueError:
        return False

def validate_ipv6_address(ip: str) -> bool:
    try:
        ipaddress.IPv6Address(ip)
        return True
    except ValueError:
        return False

def validate_domain(domain: str) -> bool:
    if not domain or len(domain) > 253:
        return False
    
    domain_pattern = re.compile(
        r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    
    return bool(domain_pattern.match(domain))

def validate_email(email: str) -> bool:
    try:
        validate_email_format(email)
        return True
    except EmailNotValidError:
        return False

def validate_port(port: Union[int, str]) -> bool:
    try:
        port_num = int(port)
        return 1 <= port_num <= 65535
    except (ValueError, TypeError):
        return False

def validate_url(url: str) -> bool:
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False

def validate_json(data: str) -> bool:
    try:
        import json
        json.loads(data)
        return True
    except (json.JSONDecodeError, TypeError):
        return False

def validate_length(text: str, min_length: int = 0, max_length: int = None) -> bool:
    if not isinstance(text, str):
        return False
    
    if len(text) < min_length:
        return False
    
    if max_length is not None and len(text) > max_length:
        return False
    
    return True

def validate_alphanumeric(text: str, allow_spaces: bool = False) -> bool:
    if allow_spaces:
        pattern = r'^[a-zA-Z0-9 ]+$'
    else:
        pattern = r'^[a-zA-Z0-9]+$'
    
    return bool(re.match(pattern, text))

def validate_hexadecimal(text: str) -> bool:
    pattern = r'^[0-9a-fA-F]+$'
    return bool(re.match(pattern, text))

def validate_mac_address(mac: str) -> bool:
    pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
    return bool(re.match(pattern, mac))

def validate_timestamp(timestamp: str, format: str = "%Y-%m-%d %H:%M:%S") -> bool:
    try:
        from datetime import datetime
        datetime.strptime(timestamp, format)
        return True
    except (ValueError, TypeError):
        return False

def validate_uuid(uuid_string: str) -> bool:
    pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    return bool(re.match(pattern, uuid_string.lower()))

def validate_file_extension(filename: str, allowed_extensions: List[str]) -> bool:
    from pathlib import Path
    extension = Path(filename).suffix.lower()
    return extension in allowed_extensions

def validate_file_size(file_size: int, max_size_mb: int) -> bool:
    max_size_bytes = max_size_mb * 1024 * 1024
    return file_size <= max_size_bytes

def validate_phone_number(phone: str) -> bool:
    pattern = r'^\+?1?\d{9,15}$'
    return bool(re.match(pattern, phone))

def validate_credit_card(card_number: str) -> bool:
    card_number = card_number.replace(' ', '').replace('-', '')
    
    if not card_number.isdigit():
        return False
    
    if len(card_number) < 13 or len(card_number) > 19:
        return False
    
    return _luhn_check(card_number)

def _luhn_check(card_number: str) -> bool:
    def digits_of(n):
        return [int(d) for d in str(n)]
    
    digits = digits_of(card_number)
    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]
    
    checksum = sum(odd_digits)
    
    for d in even_digits:
        checksum += sum(digits_of(d * 2))
    
    return checksum % 10 == 0

def validate_password_strength(password: str) -> Dict[str, Any]:
    checks = {
        'length': len(password) >= 8,
        'uppercase': bool(re.search(r'[A-Z]', password)),
        'lowercase': bool(re.search(r'[a-z]', password)),
        'digit': bool(re.search(r'\d', password)),
        'special': bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password)),
        'no_common': password.lower() not in _get_common_passwords()
    }
    
    score = sum(checks.values())
    strength = 'very_weak' if score <= 2 else 'weak' if score <= 3 else 'medium' if score <= 4 else 'strong' if score <= 5 else 'very_strong'
    
    return {
        'is_valid': all(checks.values()),
        'score': score,
        'strength': strength,
        'checks': checks
    }

def _get_common_passwords() -> set:
    return {
        'password', '123456', 'password123', 'admin', 'qwerty',
        'letmein', 'welcome', 'monkey', 'dragon', 'master'
    }

def validate_cidr(cidr: str) -> bool:
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False

def validate_asn(asn: str) -> bool:
    pattern = r'^AS\d+$'
    return bool(re.match(pattern, asn.upper()))

def validate_country_code(code: str) -> bool:
    if not code or len(code) != 2:
        return False
    
    pattern = r'^[A-Z]{2}$'
    return bool(re.match(pattern, code.upper()))

def validate_latitude(lat: float) -> bool:
    return -90.0 <= lat <= 90.0

def validate_longitude(lon: float) -> bool:
    return -180.0 <= lon <= 180.0

def validate_threat_level(level: str) -> bool:
    valid_levels = ['low', 'medium', 'high', 'critical']
    return level.lower() in valid_levels

def validate_honeypot_type(honeypot_type: str) -> bool:
    valid_types = ['ssh', 'web', 'ftp', 'url_trap']
    return honeypot_type.lower() in valid_types

def validate_attack_method(method: str) -> bool:
    valid_methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH']
    return method.upper() in valid_methods

class ValidationError(Exception):
    def __init__(self, message: str, field: str = None):
        self.message = message
        self.field = field
        super().__init__(self.message)

def validate_attack_event(data: Dict[str, Any]) -> List[ValidationError]:
    errors = []
    
    if not validate_ip_address(data.get('source_ip', '')):
        errors.append(ValidationError('Invalid source IP address', 'source_ip'))
    
    if not validate_port(data.get('source_port', 0)):
        errors.append(ValidationError('Invalid source port', 'source_port'))
    
    if not validate_port(data.get('destination_port', 0)):
        errors.append(ValidationError('Invalid destination port', 'destination_port'))
    
    if not validate_honeypot_type(data.get('honeypot_type', '')):
        errors.append(ValidationError('Invalid honeypot type', 'honeypot_type'))
    
    if data.get('country') and not validate_country_code(data.get('country')):
        errors.append(ValidationError('Invalid country code', 'country'))
    
    return errors

def validate_user_data(data: Dict[str, Any]) -> List[ValidationError]:
    errors = []
    
    if not validate_length(data.get('username', ''), min_length=3, max_length=50):
        errors.append(ValidationError('Username must be between 3 and 50 characters', 'username'))
    
    if not validate_alphanumeric(data.get('username', '')):
        errors.append(ValidationError('Username can only contain letters and numbers', 'username'))
    
    if not validate_email(data.get('email', '')):
        errors.append(ValidationError('Invalid email address', 'email'))
    
    password_validation = validate_password_strength(data.get('password', ''))
    if not password_validation['is_valid']:
        errors.append(ValidationError('Password does not meet security requirements', 'password'))
    
    return errors