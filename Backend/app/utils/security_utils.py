"""
Security Utilities
Cryptographic functions and security helpers
"""

import hashlib
import hmac
import base64
import secrets
import string
from typing import Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from app.core.config import settings

def sanitize_input(input_string: str, max_length: int = 1000) -> str:
    if not input_string:
        return ""
    
    dangerous_patterns = [
        r'<script.*?>.*?</script>',
        r'javascript:',
        r'onload=',
        r'onerror=',
        r'eval\(',
        r'exec\(',
        r'system\(',
        r'union.*select',
        r'select.*from',
        r'drop.*table',
        r'insert.*into',
        r'<.*>'
    ]
    
    sanitized = input_string
    
    for pattern in dangerous_patterns:
        sanitized = re.sub(pattern, '', sanitized, flags=re.IGNORECASE)
    
    sanitized = sanitized.replace('\\', '\\\\').replace('"', '\\"').replace("'", "\\'")
    
    if max_length and len(sanitized) > max_length:
        sanitized = sanitized[:max_length]
    
    return sanitized.strip()

def generate_secure_hash(data: str, salt: str = None) -> Dict[str, str]:
    if salt is None:
        salt = generate_random_string(32)
    
    hash_input = f"{data}{salt}".encode('utf-8')
    hash_value = hashlib.sha256(hash_input).hexdigest()
    
    return {
        'hash': hash_value,
        'salt': salt
    }

def verify_hash(data: str, hash_value: str, salt: str) -> bool:
    new_hash = generate_secure_hash(data, salt)
    return hmac.compare_digest(new_hash['hash'], hash_value)

def generate_fernet_key() -> str:
    return Fernet.generate_key().decode('utf-8')

class DataEncryptor:
    def __init__(self, key: str = None):
        if key is None:
            key = getattr(settings, 'encryption_key', None)
        
        if not key:
            raise ValueError("Encryption key is required")
        
        self.fernet = Fernet(key.encode('utf-8'))

    def encrypt_data(self, data: str) -> str:
        if not data:
            return ""
        
        encrypted_data = self.fernet.encrypt(data.encode('utf-8'))
        return base64.urlsafe_b64encode(encrypted_data).decode('utf-8')

    def decrypt_data(self, encrypted_data: str) -> str:
        if not encrypted_data:
            return ""
        
        try:
            decoded_data = base64.urlsafe_b64decode(encrypted_data.encode('utf-8'))
            decrypted_data = self.fernet.decrypt(decoded_data)
            return decrypted_data.decode('utf-8')
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")

def encrypt_data(data: str, key: str = None) -> str:
    encryptor = DataEncryptor(key)
    return encryptor.encrypt_data(data)

def decrypt_data(encrypted_data: str, key: str = None) -> str:
    encryptor = DataEncryptor(key)
    return encryptor.decrypt_data(encrypted_data)

def generate_secure_random_string(length: int = 32, charset: str = None) -> str:
    if charset is None:
        charset = string.ascii_letters + string.digits + "!@#$%^&*"
    
    return ''.join(secrets.choice(charset) for _ in range(length))

def generate_secure_token() -> str:
    return secrets.token_urlsafe(32)

def generate_api_key(prefix: str = "hp") -> str:
    random_part = secrets.token_urlsafe(32)
    return f"{prefix}_{random_part}"

def generate_session_id() -> str:
    return secrets.token_hex(32)

def constant_time_compare(val1: str, val2: str) -> bool:
    return hmac.compare_digest(val1, val2)

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(32)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return f"{base64.urlsafe_b64encode(salt).decode()}:{key.decode()}"

def verify_password(password: str, hashed_password: str) -> bool:
    try:
        salt_b64, key_b64 = hashed_password.split(':')
        salt = base64.urlsafe_b64decode(salt_b64)
        stored_key = base64.urlsafe_b64decode(key_b64)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        new_key = kdf.derive(password.encode())
        return constant_time_compare(stored_key, new_key)
    except Exception:
        return False

def generate_csrf_token() -> str:
    return secrets.token_hex(32)

def validate_csrf_token(token: str, expected_token: str) -> bool:
    return constant_time_compare(token, expected_token)

def mask_sensitive_data(data: str, visible_chars: int = 4) -> str:
    if not data or len(data) <= visible_chars:
        return "*" * 8
    
    visible_part = data[:visible_chars]
    masked_part = "*" * (len(data) - visible_chars)
    return visible_part + masked_part

def mask_ip_address(ip: str) -> str:
    if not validate_ip_address(ip):
        return "***.***.***.***"
    
    parts = ip.split('.')
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.***.***"
    else:
        return "***.***.***.***"

def mask_email(email: str) -> str:
    if not validate_email(email):
        return "***@***.***"
    
    local_part, domain = email.split('@')
    
    if len(local_part) <= 2:
        masked_local = local_part[0] + "*"
    else:
        masked_local = local_part[0] + "*" * (len(local_part) - 2) + local_part[-1]
    
    domain_parts = domain.split('.')
    if len(domain_parts) >= 2:
        masked_domain = domain_parts[0][0] + "*" + "." + domain_parts[-1]
    else:
        masked_domain = "*" * len(domain)
    
    return f"{masked_local}@{masked_domain}"

def calculate_data_hash(data: Any) -> str:
    if isinstance(data, (dict, list)):
        data_str = str(sorted(data.items())) if isinstance(data, dict) else str(data)
    else:
        data_str = str(data)
    
    return hashlib.sha256(data_str.encode('utf-8')).hexdigest()

def generate_hmac_signature(data: str, secret: str) -> str:
    return hmac.new(
        secret.encode('utf-8'),
        data.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()

def verify_hmac_signature(data: str, signature: str, secret: str) -> bool:
    expected_signature = generate_hmac_signature(data, secret)
    return constant_time_compare(signature, expected_signature)

class RateLimiter:
    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = {}

    def is_allowed(self, identifier: str) -> bool:
        current_time = int(datetime.utcnow().timestamp())
        window_start = current_time - self.window_seconds
        
        if identifier not in self.requests:
            self.requests[identifier] = []
        
        requests = self.requests[identifier]
        requests = [req_time for req_time in requests if req_time > window_start]
        
        if len(requests) >= self.max_requests:
            return False
        
        requests.append(current_time)
        self.requests[identifier] = requests
        return True

    def get_remaining_requests(self, identifier: str) -> int:
        current_time = int(datetime.utcnow().timestamp())
        window_start = current_time - self.window_seconds
        
        if identifier not in self.requests:
            return self.max_requests
        
        requests = self.requests[identifier]
        recent_requests = [req_time for req_time in requests if req_time > window_start]
        
        return max(0, self.max_requests - len(recent_requests))

def create_rate_limiter(max_requests: int = 100, window_seconds: int = 3600) -> RateLimiter:
    return RateLimiter(max_requests, window_seconds)

def escape_html(text: str) -> str:
    if not text:
        return ""
    
    escape_chars = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#x27;',
        '/': '&#x2F;'
    }
    
    escaped_text = text
    for char, replacement in escape_chars.items():
        escaped_text = escaped_text.replace(char, replacement)
    
    return escaped_text

def validate_file_upload(filename: str, content_type: str, max_size: int) -> bool:
    allowed_extensions = {'.txt', '.log', '.json', '.csv', '.xml'}
    allowed_mime_types = {
        'text/plain',
        'application/json', 
        'text/csv',
        'application/xml',
        'text/xml'
    }
    
    from pathlib import Path
    file_extension = Path(filename).suffix.lower()
    
    if file_extension not in allowed_extensions:
        return False
    
    if content_type not in allowed_mime_types:
        return False
    
    return True

def generate_secure_filename(original_filename: str) -> str:
    from pathlib import Path
    import uuid
    
    extension = Path(original_filename).suffix
    secure_name = f"{uuid.uuid4()}{extension}"
    return secure_name