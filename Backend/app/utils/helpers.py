"""
Helper Functions
Common utility functions and helpers
"""

import uuid
import json
import hashlib
import random
import string
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union
from pathlib import Path
import ipaddress

def generate_id(prefix: str = "event") -> str:
    timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
    return f"{prefix}_{timestamp}_{random_suffix}"

def generate_uuid() -> str:
    return str(uuid.uuid4())

def format_timestamp(timestamp: datetime, format_str: str = "%Y-%m-%d %H:%M:%S") -> str:
    if not timestamp:
        return ""
    return timestamp.strftime(format_str)

def parse_timestamp(timestamp_str: str, format_str: str = "%Y-%m-%d %H:%M:%S") -> Optional[datetime]:
    try:
        return datetime.strptime(timestamp_str, format_str)
    except (ValueError, TypeError):
        return None

def calculate_percentage(part: float, whole: float, decimal_places: int = 2) -> float:
    if whole == 0:
        return 0.0
    percentage = (part / whole) * 100
    return round(percentage, decimal_places)

def format_bytes(size_bytes: int) -> str:
    if size_bytes == 0:
        return "0B"
    
    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1
    
    return f"{size_bytes:.2f} {size_names[i]}"

def safe_json_loads(json_string: str, default: Any = None) -> Any:
    try:
        return json.loads(json_string)
    except (json.JSONDecodeError, TypeError):
        return default

def safe_json_dumps(data: Any, default: Any = None) -> str:
    try:
        return json.dumps(data, default=default, ensure_ascii=False)
    except (TypeError, ValueError):
        return "{}"

def flatten_dict(nested_dict: Dict[str, Any], parent_key: str = '', separator: str = '.') -> Dict[str, Any]:
    items = []
    for key, value in nested_dict.items():
        new_key = f"{parent_key}{separator}{key}" if parent_key else key
        if isinstance(value, dict):
            items.extend(flatten_dict(value, new_key, separator=separator).items())
        else:
            items.append((new_key, value))
    return dict(items)

def chunk_list(lst: List[Any], chunk_size: int) -> List[List[Any]]:
    return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]

def get_nested_value(data: Dict[str, Any], key_path: str, default: Any = None, separator: str = '.') -> Any:
    keys = key_path.split(separator)
    current = data
    
    for key in keys:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return default
    
    return current

def set_nested_value(data: Dict[str, Any], key_path: str, value: Any, separator: str = '.') -> Dict[str, Any]:
    keys = key_path.split(separator)
    current = data
    
    for i, key in enumerate(keys[:-1]):
        if key not in current or not isinstance(current[key], dict):
            current[key] = {}
        current = current[key]
    
    current[keys[-1]] = value
    return data

def filter_dict(data: Dict[str, Any], keys_to_keep: List[str]) -> Dict[str, Any]:
    return {key: data[key] for key in keys_to_keep if key in data}

def exclude_dict_keys(data: Dict[str, Any], keys_to_exclude: List[str]) -> Dict[str, Any]:
    return {key: value for key, value in data.items() if key not in keys_to_exclude}

def merge_dicts(dict1: Dict[str, Any], dict2: Dict[str, Any]) -> Dict[str, Any]:
    result = dict1.copy()
    
    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = merge_dicts(result[key], value)
        else:
            result[key] = value
    
    return result

def human_readable_duration(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds} seconds"
    elif seconds < 3600:
        minutes = seconds // 60
        return f"{minutes} minutes"
    elif seconds < 86400:
        hours = seconds // 3600
        return f"{hours} hours"
    else:
        days = seconds // 86400
        return f"{days} days"

def generate_random_string(length: int = 8, charset: str = None) -> str:
    if charset is None:
        charset = string.ascii_letters + string.digits
    
    return ''.join(random.choices(charset, k=length))

def is_valid_json(data: str) -> bool:
    try:
        json.loads(data)
        return True
    except (json.JSONDecodeError, TypeError):
        return False

def truncate_string(text: str, max_length: int, suffix: str = "...") -> str:
    if len(text) <= max_length:
        return text
    
    return text[:max_length - len(suffix)] + suffix

def get_file_extension(filename: str) -> str:
    return Path(filename).suffix.lower()

def create_directory(path: Union[str, Path]) -> bool:
    try:
        Path(path).mkdir(parents=True, exist_ok=True)
        return True
    except (OSError, PermissionError):
        return False

def get_current_timestamp() -> str:
    return datetime.utcnow().isoformat()

def get_timestamp_days_ago(days: int) -> str:
    past_date = datetime.utcnow() - timedelta(days=days)
    return past_date.isoformat()

def calculate_age(from_date: datetime, to_date: datetime = None) -> timedelta:
    if to_date is None:
        to_date = datetime.utcnow()
    
    return to_date - from_date

def normalize_ip_address(ip: str) -> str:
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return ip

def is_private_ip(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False

def get_class_methods(cls: type) -> List[str]:
    return [method for method in dir(cls) if not method.startswith('_') and callable(getattr(cls, method))]

def retry_on_exception(max_retries: int = 3, delay: float = 1.0, exceptions: tuple = (Exception,)):
    def decorator(func):
        def wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    if attempt < max_retries - 1:
                        import time
                        time.sleep(delay * (2 ** attempt))
            raise last_exception
        return wrapper
    return decorator

class Timer:
    def __init__(self):
        self.start_time = None
        self.end_time = None
    
    def start(self):
        self.start_time = datetime.utcnow()
        return self
    
    def stop(self):
        self.end_time = datetime.utcnow()
        return self
    
    def elapsed(self) -> float:
        if self.start_time is None:
            return 0.0
        
        end_time = self.end_time or datetime.utcnow()
        return (end_time - self.start_time).total_seconds()
    
    def __enter__(self):
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()