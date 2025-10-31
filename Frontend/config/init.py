import os
import json
from typing import Dict, Any

class Config:
    def __init__(self):
        self.environment = os.getenv('HONEYPOT_ENV', 'development')
        self.config_data = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        config_files = {
            'default': 'default.json',
            'environment': f'{self.environment}.json',
            'ml': 'ml_config.json',
            'security': 'security_config.json'
        }
        
        config = {}
        
        for config_type, filename in config_files.items():
            filepath = os.path.join(os.path.dirname(__file__), filename)
            if os.path.exists(filepath):
                with open(filepath, 'r') as f:
                    config[config_type] = json.load(f)
        
        return config
    
    def get(self, key: str, default=None):
        keys = key.split('.')
        value = self.config_data
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def get_ml_config(self):
        return self.config_data.get('ml', {})
    
    def get_security_config(self):
        return self.config_data.get('security', {})
    
    def get_database_config(self):
        return self.get('default.database', {})

config = Config()