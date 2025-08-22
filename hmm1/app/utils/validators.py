# ==========================================
# app/utils/validators.py
"""
Input validation utilities for the authentication system
"""
import re
import logging
from typing import List, Dict, Any, Optional
import json

logger = logging.getLogger(__name__)

def validate_email(email: str) -> bool:
    """Validate email format"""
    if not email or not isinstance(email, str):
        return False
    
    # Basic email regex pattern
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    
    # Check format
    if not re.match(pattern, email):
        return False
    
    # Check length
    if len(email) > 254:  # RFC 5321 limit
        return False
    
    # Check local part length
    local_part = email.split('@')[0]
    if len(local_part) > 64:  # RFC 5321 limit
        return False
    
    return True

def validate_password(password: str) -> bool:
    """Validate password strength"""
    if not password or not isinstance(password, str):
        return False
    
    # Minimum length
    if len(password) < 8:
        return False
    
    # Maximum length (prevent DoS)
    if len(password) > 128:
        return False
    
    # Must contain at least one uppercase letter
    if not re.search(r'[A-Z]', password):
        return False
    
    # Must contain at least one lowercase letter
    if not re.search(r'[a-z]', password):
        return False
    
    # Must contain at least one digit
    if not re.search(r'\d', password):
        return False
    
    return True

def validate_username(username: str) -> bool:
    """Validate username format"""
    if not username or not isinstance(username, str):
        return False
    
    # Length check
    if len(username) < 3 or len(username) > 30:
        return False
    
    # Character check (alphanumeric, underscore, hyphen only)
    if not re.match(r'^[a-zA-Z0-9_-]+$', username):
        return False
    
    # Cannot start with number
    if username[0].isdigit():
        return False
    
    return True

def validate_behavioral_data(keystroke_events: List[Dict], mouse_events: List[Dict]) -> bool:
    """Validate behavioral data structure and content"""
    try:
        # Check if at least one type of event exists
        if not keystroke_events and not mouse_events:
            return False
        
        # Validate keystroke events
        if keystroke_events:
            if not isinstance(keystroke_events, list):
                return False
            
            if len(keystroke_events) > 1000:  # Reasonable limit
                return False
            
            for event in keystroke_events:
                if not isinstance(event, dict):
                    return False
                
                # Required fields
                required_fields = ['type', 'key', 'timestamp']
                if not all(field in event for field in required_fields):
                    return False
                
                # Validate event type
                if event['type'] not in ['keydown', 'keyup']:
                    return False
                
                # Validate timestamp
                if not isinstance(event['timestamp'], (int, float)):
                    return False
                
                # Validate key
                if not isinstance(event['key'], str) or len(event['key']) > 50:
                    return False
        
        # Validate mouse events
        if mouse_events:
            if not isinstance(mouse_events, list):
                return False
            
            if len(mouse_events) > 5000:  # Reasonable limit
                return False
            
            for event in mouse_events:
                if not isinstance(event, dict):
                    return False
                
                # Required fields
                required_fields = ['type', 'timestamp']
                if not all(field in event for field in required_fields):
                    return False
                
                # Validate event type
                valid_types = ['mousemove', 'click', 'mousedown', 'mouseup', 'wheel']
                if event['type'] not in valid_types:
                    return False
                
                # Validate timestamp
                if not isinstance(event['timestamp'], (int, float)):
                    return False
                
                # Validate coordinates for movement events
                if event['type'] in ['mousemove', 'click', 'mousedown', 'mouseup']:
                    if 'clientX' in event:
                        if not isinstance(event['clientX'], (int, float)) or not (0 <= event['clientX'] <= 10000):
                            return False
                    if 'clientY' in event:
                        if not isinstance(event['clientY'], (int, float)) or not (0 <= event['clientY'] <= 10000):
                            return False
        
        return True
        
    except Exception as e:
        logger.error(f"Behavioral data validation error: {e}")
        return False

def validate_session_id(session_id: str) -> bool:
    """Validate session ID format"""
    if not session_id or not isinstance(session_id, str):
        return False
    
    # Check length (should be around 32-64 characters for secure tokens)
    if len(session_id) < 16 or len(session_id) > 128:
        return False
    
    # Should contain only alphanumeric characters and some special chars
    if not re.match(r'^[a-zA-Z0-9_-]+$', session_id):
        return False
    
    return True

def validate_challenge_text(text: str, min_length: int = 10, max_length: int = 2000) -> bool:
    """Validate challenge text input"""
    if not text or not isinstance(text, str):
        return False
    
    # Length check
    if len(text) < min_length or len(text) > max_length:
        return False
    
    # Check for potentially malicious content
    suspicious_patterns = [
        r'<script',
        r'javascript:',
        r'vbscript:',
        r'onload=',
        r'onerror=',
        r'eval\(',
        r'document\.cookie'
    ]
    
    text_lower = text.lower()
    for pattern in suspicious_patterns:
        if re.search(pattern, text_lower):
            return False
    
    return True

def validate_json_data(data: Any, max_depth: int = 10, max_size: int = 1000000) -> bool:
    """Validate JSON data structure and size"""
    try:
        # Convert to JSON string to check size
        json_str = json.dumps(data)
        if len(json_str) > max_size:
            return False
        
        # Check depth to prevent stack overflow
        def check_depth(obj, current_depth=0):
            if current_depth > max_depth:
                return False
            
            if isinstance(obj, dict):
                return all(check_depth(v, current_depth + 1) for v in obj.values())
            elif isinstance(obj, list):
                return all(check_depth(item, current_depth + 1) for item in obj)
            
            return True
        
        return check_depth(data)
        
    except Exception as e:
        logger.error(f"JSON validation error: {e}")
        return False

def validate_ip_address(ip_address: str) -> bool:
    """Validate IP address format"""
    if not ip_address or not isinstance(ip_address, str):
        return False
    
    # IPv4 pattern
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    
    # IPv6 pattern (simplified)
    ipv6_pattern = r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
    
    if re.match(ipv4_pattern, ip_address):
        # Validate IPv4 octets
        try:
            octets = ip_address.split('.')
            return all(0 <= int(octet) <= 255 for octet in octets)
        except ValueError:
            return False
    elif re.match(ipv6_pattern, ip_address):
        return True
    
    return False

def validate_file_upload(file_data: bytes, allowed_types: List[str] = None, max_size: int = 10485760) -> bool:
    """Validate file upload data"""
    if not file_data:
        return False
    
    # Check file size (default 10MB)
    if len(file_data) > max_size:
        return False
    
    # Check file type by magic bytes if specified
    if allowed_types:
        # Simple magic byte checking for common types
        magic_bytes = {
            'pdf': b'%PDF',
            'png': b'\x89PNG',
            'jpg': b'\xff\xd8\xff',
            'jpeg': b'\xff\xd8\xff',
            'gif': b'GIF8',
            'txt': None  # Text files don't have reliable magic bytes
        }
        
        if not any(file_data.startswith(magic_bytes.get(file_type, b'')) 
                  for file_type in allowed_types if magic_bytes.get(file_type)):
            return False
    
    return True

def sanitize_string(input_string: str, max_length: int = 1000) -> str:
    """Sanitize string input to prevent XSS and other attacks"""
    if not input_string:
        return ""
    
    # Truncate to max length
    sanitized = str(input_string)[:max_length]
    
    # Remove null bytes
    sanitized = sanitized.replace('\x00', '')
    
    # Escape HTML characters
    html_escape_table = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#x27;',
        '/': '&#x2F;'
    }
    
    for char, escape in html_escape_table.items():
        sanitized = sanitized.replace(char, escape)
    
    return sanitized

def validate_task_index(task_index: Any, max_tasks: int = 20) -> bool:
    """Validate calibration task index"""
    try:
        index = int(task_index)
        return 0 <= index < max_tasks
    except (ValueError, TypeError):
        return False

def validate_window_duration(duration: Any, min_duration: float = 1.0, max_duration: float = 300.0) -> bool:
    """Validate data collection window duration"""
    try:
        duration_float = float(duration)
        return min_duration <= duration_float <= max_duration
    except (ValueError, TypeError):
        return False

def validate_risk_score(score: Any) -> bool:
    """Validate risk score value"""
    try:
        score_float = float(score)
        return 0.0 <= score_float <= 1.0
    except (ValueError, TypeError):
        return False

def validate_challenge_type(challenge_type: str) -> bool:
    """Validate challenge type"""
    if not challenge_type or not isinstance(challenge_type, str):
        return False
    
    valid_types = ['verification', 'adaptive', 'high_risk', 'moderate_risk']
    return challenge_type in valid_types

def validate_user_agent(user_agent: str) -> bool:
    """Validate user agent string"""
    if not user_agent or not isinstance(user_agent, str):
        return False
    
    # Length check
    if len(user_agent) > 500:
        return False
    
    # Check for suspicious patterns
    suspicious_patterns = [
        r'<script',
        r'javascript:',
        r'vbscript:',
        r'\x00',  # Null bytes
        r'[\x01-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]'  # Control characters
    ]
    
    for pattern in suspicious_patterns:
        if re.search(pattern, user_agent, re.IGNORECASE):
            return False
    
    return True

def validate_feature_data(features: Dict[str, Any]) -> bool:
    """Validate extracted feature data"""
    if not isinstance(features, dict):
        return False
    
    # Check if we have reasonable number of features
    if len(features) > 100:  # Too many features
        return False
    
    for feature_name, value in features.items():
        # Feature name validation
        if not isinstance(feature_name, str) or len(feature_name) > 100:
            return False
        
        # Feature value validation
        if isinstance(value, (int, float)):
            # Check for reasonable numeric ranges
            if abs(value) > 1e10:  # Extremely large values
                return False
            # Check for NaN or infinity
            if isinstance(value, float):
                if value != value or value == float('inf') or value == float('-inf'):
                    return False
        elif isinstance(value, str):
            if len(value) > 1000:  # Very long strings
                return False
        else:
            # Only allow basic types
            if not isinstance(value, (bool, type(None))):
                return False
    
    return True

def validate_timestamp(timestamp: Any) -> bool:
    """Validate timestamp value"""
    try:
        ts = float(timestamp)
        # Check if timestamp is reasonable (not too far in past/future)
        # Assuming timestamps are in milliseconds since epoch
        min_timestamp = 946684800000  # Year 2000 in milliseconds
        max_timestamp = 4102444800000  # Year 2100 in milliseconds
        return min_timestamp <= ts <= max_timestamp
    except (ValueError, TypeError):
        return False

def validate_pagination_params(page: Any, per_page: Any, max_per_page: int = 100) -> tuple:
    """Validate pagination parameters and return sanitized values"""
    try:
        page_int = max(1, int(page))
    except (ValueError, TypeError):
        page_int = 1
    
    try:
        per_page_int = max(1, min(int(per_page), max_per_page))
    except (ValueError, TypeError):
        per_page_int = 20
    
    return page_int, per_page_int

def validate_search_query(query: str, max_length: int = 100) -> bool:
    """Validate search query"""
    if not query or not isinstance(query, str):
        return False
    
    # Length check
    if len(query) > max_length:
        return False
    
    # Check for SQL injection patterns
    sql_patterns = [
        r'union\s+select',
        r'drop\s+table',
        r'delete\s+from',
        r'insert\s+into',
        r'update\s+set',
        r'exec\s*\(',
        r'script\s*>',
        r'--',
        r'/\*',
        r'\*/',
        r'xp_'
    ]
    
    query_lower = query.lower()
    for pattern in sql_patterns:
        if re.search(pattern, query_lower):
            return False
    
    return True

def validate_enum_value(value: str, allowed_values: List[str]) -> bool:
    """Validate that a value is in a list of allowed values"""
    if not isinstance(value, str) or not isinstance(allowed_values, list):
        return False
    
    return value in allowed_values

def validate_date_range(start_date: str, end_date: str) -> bool:
    """Validate date range format and logic"""
    try:
        from datetime import datetime
        
        # Try to parse dates
        start = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
        end = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
        
        # End date should be after start date
        if end <= start:
            return False
        
        # Range shouldn't be too large (e.g., more than 1 year)
        max_days = 365
        if (end - start).days > max_days:
            return False
        
        return True
        
    except (ValueError, AttributeError):
        return False

def validate_ml_model_params(params: Dict[str, Any]) -> bool:
    """Validate machine learning model parameters"""
    if not isinstance(params, dict):
        return False
    
    # Common parameter validation
    for param_name, value in params.items():
        if not isinstance(param_name, str):
            return False
        
        # Check parameter name length
        if len(param_name) > 50:
            return False
        
        # Validate specific parameters
        if param_name in ['epochs', 'batch_size', 'max_iter']:
            if not isinstance(value, int) or value <= 0 or value > 10000:
                return False
        elif param_name in ['learning_rate', 'threshold', 'tolerance']:
            if not isinstance(value, (int, float)) or value <= 0 or value > 1:
                return False
        elif param_name in ['random_state', 'n_estimators']:
            if not isinstance(value, int) or value < 0:
                return False
    
    return True

# Export all validation functions
__all__ = [
    'validate_email',
    'validate_password', 
    'validate_username',
    'validate_behavioral_data',
    'validate_session_id',
    'validate_challenge_text',
    'validate_json_data',
    'validate_ip_address',
    'validate_file_upload',
    'sanitize_string',
    'validate_task_index',
    'validate_window_duration',
    'validate_risk_score',
    'validate_challenge_type',
    'validate_user_agent',
    'validate_feature_data',
    'validate_timestamp',
    'validate_pagination_params',
    'validate_search_query',
    'validate_enum_value',
    'validate_date_range',
    'validate_ml_model_params'
]