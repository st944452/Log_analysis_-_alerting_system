import streamlit as st
import json
import os
from datetime import datetime
from typing import Dict, Any

def initialize_session_state():
    """Initialize Streamlit session state variables"""
    
    # Initialize processed logs
    if 'processed_logs' not in st.session_state:
        st.session_state['processed_logs'] = []
    
    # Initialize alerts
    if 'alerts' not in st.session_state:
        st.session_state['alerts'] = []
    
    # Initialize alert rules
    if 'alert_rules' not in st.session_state:
        st.session_state['alert_rules'] = []
    
    # Initialize last scan time
    if 'last_scan_time' not in st.session_state:
        st.session_state['last_scan_time'] = 'Never'
    
    # Initialize monitoring settings
    if 'monitoring_enabled' not in st.session_state:
        st.session_state['monitoring_enabled'] = False
    
    # Initialize email settings
    if 'email_enabled' not in st.session_state:
        st.session_state['email_enabled'] = False
    
    if 'smtp_server' not in st.session_state:
        st.session_state['smtp_server'] = 'smtp.gmail.com'
    
    if 'smtp_port' not in st.session_state:
        st.session_state['smtp_port'] = 587
    
    if 'sender_email' not in st.session_state:
        st.session_state['sender_email'] = ''
    
    if 'sender_password' not in st.session_state:
        st.session_state['sender_password'] = ''
    
    if 'recipient_emails' not in st.session_state:
        st.session_state['recipient_emails'] = ''

def load_config() -> Dict[str, Any]:
    """Load application configuration"""
    config_file = 'config/settings.json'
    
    default_config = {
        'app_name': 'Log Analysis & Security Alerting Platform',
        'version': '1.0.0',
        'log_retention_days': 30,
        'max_log_file_size_mb': 100,
        'auto_analysis_enabled': True,
        'analysis_interval_minutes': 15,
        'default_alert_rules': [
            {
                'name': 'Failed Login Threshold',
                'pattern': r'(?i)(failed password|authentication failure)',
                'threshold': 5,
                'severity': 'medium'
            },
            {
                'name': 'SQL Injection Detection',
                'pattern': r'(?i)(union\s+select|select\s+.*\s+from)',
                'threshold': 1,
                'severity': 'high'
            }
        ]
    }
    
    try:
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                config = json.load(f)
                # Merge with defaults
                for key, value in default_config.items():
                    if key not in config:
                        config[key] = value
                return config
    except Exception as e:
        st.error(f"Error loading configuration: {str(e)}")
    
    return default_config

def save_config(config: Dict[str, Any]):
    """Save application configuration"""
    config_file = 'config/settings.json'
    
    try:
        # Ensure config directory exists
        os.makedirs('config', exist_ok=True)
        
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
        
        return True
    except Exception as e:
        st.error(f"Error saving configuration: {str(e)}")
        return False

def format_timestamp(timestamp_str: str) -> str:
    """Format timestamp for display"""
    try:
        if timestamp_str and timestamp_str != 'Never':
            dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            return dt.strftime('%Y-%m-%d %H:%M:%S')
    except ValueError:
        pass
    
    return timestamp_str

def validate_ip_address(ip: str) -> bool:
    """Validate IP address format"""
    import re
    
    # IPv4 pattern
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    
    if re.match(ipv4_pattern, ip):
        # Check if each octet is valid (0-255)
        octets = ip.split('.')
        return all(0 <= int(octet) <= 255 for octet in octets)
    
    return False

def sanitize_log_entry(log_entry: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize log entry to prevent XSS and other security issues"""
    import html
    
    sanitized = {}
    
    for key, value in log_entry.items():
        if isinstance(value, str):
            # HTML escape string values
            sanitized[key] = html.escape(value)
        elif isinstance(value, dict):
            # Recursively sanitize nested dictionaries
            sanitized[key] = sanitize_log_entry(value)
        else:
            # Keep other types as-is
            sanitized[key] = value
    
    return sanitized

def get_file_size_mb(file_path: str) -> float:
    """Get file size in MB"""
    try:
        if os.path.exists(file_path):
            size_bytes = os.path.getsize(file_path)
            return size_bytes / (1024 * 1024)
    except Exception:
        pass
    
    return 0.0

def cleanup_old_logs(logs: list, retention_days: int = 30) -> list:
    """Clean up logs older than retention period"""
    if not logs:
        return logs
    
    cutoff_date = datetime.now() - timedelta(days=retention_days)
    cleaned_logs = []
    
    for log in logs:
        try:
            log_time_str = log.get('parsed_time') or log.get('timestamp')
            if log_time_str:
                log_time = datetime.fromisoformat(log_time_str.replace('Z', '+00:00'))
                if log_time > cutoff_date:
                    cleaned_logs.append(log)
            else:
                # Keep logs without timestamps
                cleaned_logs.append(log)
        except (ValueError, TypeError):
            # Keep logs with invalid timestamps
            cleaned_logs.append(log)
    
    return cleaned_logs

def export_data_to_json(data: Any, filename: str = None) -> str:
    """Export data to JSON string"""
    if filename is None:
        filename = f"export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    try:
        return json.dumps(data, indent=2, default=str)
    except Exception as e:
        st.error(f"Error exporting data: {str(e)}")
        return "{}"

def get_log_level_color(level: str) -> str:
    """Get color for log level"""
    color_map = {
        'ERROR': '#dc3545',
        'WARN': '#ffc107', 
        'WARNING': '#ffc107',
        'INFO': '#17a2b8',
        'DEBUG': '#6c757d'
    }
    
    return color_map.get(level.upper(), '#6c757d')

def get_severity_color(severity: str) -> str:
    """Get color for alert severity"""
    color_map = {
        'critical': '#dc3545',
        'high': '#fd7e14',
        'medium': '#ffc107',
        'low': '#28a745'
    }
    
    return color_map.get(severity.lower(), '#6c757d')

def truncate_string(text: str, max_length: int = 50) -> str:
    """Truncate string to maximum length"""
    if len(text) <= max_length:
        return text
    
    return text[:max_length-3] + "..."

def is_private_ip(ip: str) -> bool:
    """Check if IP address is private/internal"""
    try:
        import ipaddress
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False

def get_ip_reputation_score(ip: str) -> int:
    """Get basic IP reputation score (0-10, higher is more suspicious)"""
    # This is a simplified version - in production you would integrate with threat intelligence APIs
    score = 0
    
    # Check if it's a private IP
    if is_private_ip(ip):
        return 0  # Private IPs are generally safe
    
    # Simple heuristics (these would be replaced with real threat intel)
    suspicious_ranges = [
        '192.168.',  # Should not appear as external IP
        '10.',       # Should not appear as external IP
        '172.16.',   # Should not appear as external IP
    ]
    
    for suspicious in suspicious_ranges:
        if ip.startswith(suspicious):
            score += 3
    
    # Check for common scanner IPs (simplified)
    if any(pattern in ip for pattern in ['127.', '0.0.0.0']):
        score += 5
    
    return min(score, 10)
