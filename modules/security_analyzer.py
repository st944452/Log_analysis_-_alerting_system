import re
import json
from datetime import datetime, timedelta
from typing import List, Dict, Any
from collections import defaultdict, Counter
import ipaddress

class SecurityAnalyzer:
    """Security analyzer for detecting incidents and threats in log data"""
    
    def __init__(self):
        # Load default security rules
        self.default_rules = self._load_default_rules()
        
        # Suspicious patterns
        self.suspicious_patterns = {
            'sql_injection': [
                r"(?i)(union\s+select|select\s+.*\s+from|insert\s+into|delete\s+from|drop\s+table)",
                r"(?i)(\'\s*or\s*\'\s*=\s*\'|\'\s*or\s*1\s*=\s*1|admin\'\s*--)",
                r"(?i)(exec\s*\(|execute\s*\(|sp_executesql)"
            ],
            'xss_attempts': [
                r"(?i)(<script|</script>|javascript:|onload=|onerror=)",
                r"(?i)(alert\s*\(|confirm\s*\(|prompt\s*\()",
                r"(?i)(<iframe|<object|<embed)"
            ],
            'path_traversal': [
                r"(\.\./|\.\.\\)",
                r"(/etc/passwd|/etc/shadow|/proc/self/environ)",
                r"(\\windows\\system32|\\winnt\\system32)"
            ],
            'command_injection': [
                r"(?i)(;\s*cat\s+|;\s*ls\s+|;\s*pwd|;\s*id\s*;)",
                r"(?i)(\|\s*nc\s+|\|\s*netcat\s+|\|\s*wget\s+|\|\s*curl\s+)",
                r"(?i)(&&\s*rm\s+|&&\s*del\s+|;\s*rm\s+|;\s*del\s+)"
            ],
            'brute_force': [
                r"(?i)(password.*incorrect|authentication.*failed|login.*failed)",
                r"(?i)(invalid.*credentials|access.*denied|unauthorized)",
                r"(?i)(too many.*attempts|account.*locked|rate.*limit)"
            ],
            'scanning_attempts': [
                r"(?i)(robots\.txt|\.htaccess|web\.config|wp-config\.php)",
                r"(?i)(admin|administrator|login|wp-admin|phpmyadmin)",
                r"(?i)(\.php\?|\.asp\?|\.jsp\?|\.cgi\?)"
            ]
        }
        
        # Known malicious user agents
        self.malicious_user_agents = [
            'sqlmap', 'nikto', 'nmap', 'masscan', 'zap', 'burp', 'w3af',
            'havij', 'acunetix', 'nessus', 'openvas', 'metasploit'
        ]
        
        # Known bot patterns
        self.bot_patterns = [
            r'(?i)(bot|crawler|spider|scraper)',
            r'(?i)(curl|wget|python-requests|http)',
            r'(?i)(scanner|automated|monitoring)'
        ]
    
    def analyze_logs(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze logs for security incidents"""
        incidents = []
        
        # Group logs by IP address for analysis
        ip_activities = defaultdict(list)
        
        for log in logs:
            ip = log.get('ip', 'unknown')
            if ip != 'unknown':
                ip_activities[ip].append(log)
        
        # Analyze each IP's activities
        for ip, activities in ip_activities.items():
            incidents.extend(self._analyze_ip_activities(ip, activities))
        
        # Analyze individual log entries
        for log in logs:
            incidents.extend(self._analyze_single_log(log))
        
        # Deduplicate and prioritize incidents
        incidents = self._deduplicate_incidents(incidents)
        
        return incidents
    
    def _analyze_ip_activities(self, ip: str, activities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze activities from a specific IP address"""
        incidents = []
        
        # Check for brute force attacks
        failed_attempts = [log for log in activities if self._is_failed_login(log)]
        if len(failed_attempts) >= 5:  # Threshold for brute force
            incidents.append({
                'id': f"bruteforce_{ip}_{datetime.now().timestamp()}",
                'type': 'brute_force_attack',
                'title': f'Brute Force Attack from {ip}',
                'description': f'Detected {len(failed_attempts)} failed login attempts from IP {ip}',
                'severity': 'high' if len(failed_attempts) >= 10 else 'medium',
                'source_ip': ip,
                'event_count': len(failed_attempts),
                'timestamp': datetime.now().isoformat(),
                'status': 'active'
            })
        
        # Check for scanning behavior
        unique_paths = set()
        for log in activities:
            path = log.get('path', '')
            if path:
                unique_paths.add(path)
        
        if len(unique_paths) >= 20:  # Many different paths accessed
            incidents.append({
                'id': f"scanning_{ip}_{datetime.now().timestamp()}",
                'type': 'port_scanning',
                'title': f'Scanning Activity from {ip}',
                'description': f'IP {ip} accessed {len(unique_paths)} different paths, indicating potential scanning',
                'severity': 'medium',
                'source_ip': ip,
                'event_count': len(unique_paths),
                'timestamp': datetime.now().isoformat(),
                'status': 'active'
            })
        
        # Check for high request volume
        if len(activities) >= 100:  # High request volume
            incidents.append({
                'id': f"highvolume_{ip}_{datetime.now().timestamp()}",
                'type': 'high_request_volume',
                'title': f'High Request Volume from {ip}',
                'description': f'IP {ip} made {len(activities)} requests, indicating potential DDoS or automated attack',
                'severity': 'high' if len(activities) >= 500 else 'medium',
                'source_ip': ip,
                'event_count': len(activities),
                'timestamp': datetime.now().isoformat(),
                'status': 'active'
            })
        
        # Check for error rates
        error_responses = [log for log in activities if self._is_error_response(log)]
        if len(error_responses) >= 10 and len(error_responses) / len(activities) > 0.3:
            incidents.append({
                'id': f"higherror_{ip}_{datetime.now().timestamp()}",
                'type': 'high_error_rate',
                'title': f'High Error Rate from {ip}',
                'description': f'IP {ip} generated {len(error_responses)} errors out of {len(activities)} requests',
                'severity': 'medium',
                'source_ip': ip,
                'event_count': len(error_responses),
                'timestamp': datetime.now().isoformat(),
                'status': 'active'
            })
        
        return incidents
    
    def _analyze_single_log(self, log: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze a single log entry for security threats"""
        incidents = []
        
        # Get relevant fields for analysis
        message = log.get('raw_message', '') or log.get('message', '')
        path = log.get('path', '')
        user_agent = log.get('user_agent', '')
        ip = log.get('ip', 'unknown')
        
        # Combine all text fields for pattern matching
        full_text = f"{message} {path} {user_agent}".lower()
        
        # Check for SQL injection attempts
        for pattern in self.suspicious_patterns['sql_injection']:
            if re.search(pattern, full_text):
                incidents.append({
                    'id': f"sqli_{ip}_{datetime.now().timestamp()}",
                    'type': 'sql_injection_attempt',
                    'title': f'SQL Injection Attempt from {ip}',
                    'description': f'Detected SQL injection pattern in request from {ip}',
                    'severity': 'high',
                    'source_ip': ip,
                    'event_count': 1,
                    'timestamp': datetime.now().isoformat(),
                    'status': 'active',
                    'details': {
                        'matched_pattern': pattern,
                        'log_entry': log
                    }
                })
                break
        
        # Check for XSS attempts
        for pattern in self.suspicious_patterns['xss_attempts']:
            if re.search(pattern, full_text):
                incidents.append({
                    'id': f"xss_{ip}_{datetime.now().timestamp()}",
                    'type': 'xss_attempt',
                    'title': f'XSS Attempt from {ip}',
                    'description': f'Detected cross-site scripting pattern in request from {ip}',
                    'severity': 'medium',
                    'source_ip': ip,
                    'event_count': 1,
                    'timestamp': datetime.now().isoformat(),
                    'status': 'active',
                    'details': {
                        'matched_pattern': pattern,
                        'log_entry': log
                    }
                })
                break
        
        # Check for path traversal
        for pattern in self.suspicious_patterns['path_traversal']:
            if re.search(pattern, full_text):
                incidents.append({
                    'id': f"traversal_{ip}_{datetime.now().timestamp()}",
                    'type': 'path_traversal_attempt',
                    'title': f'Path Traversal Attempt from {ip}',
                    'description': f'Detected path traversal pattern in request from {ip}',
                    'severity': 'high',
                    'source_ip': ip,
                    'event_count': 1,
                    'timestamp': datetime.now().isoformat(),
                    'status': 'active',
                    'details': {
                        'matched_pattern': pattern,
                        'log_entry': log
                    }
                })
                break
        
        # Check for command injection
        for pattern in self.suspicious_patterns['command_injection']:
            if re.search(pattern, full_text):
                incidents.append({
                    'id': f"cmdinj_{ip}_{datetime.now().timestamp()}",
                    'type': 'command_injection_attempt',
                    'title': f'Command Injection Attempt from {ip}',
                    'description': f'Detected command injection pattern in request from {ip}',
                    'severity': 'critical',
                    'source_ip': ip,
                    'event_count': 1,
                    'timestamp': datetime.now().isoformat(),
                    'status': 'active',
                    'details': {
                        'matched_pattern': pattern,
                        'log_entry': log
                    }
                })
                break
        
        # Check for malicious user agents
        if user_agent:
            for malicious_agent in self.malicious_user_agents:
                if malicious_agent.lower() in user_agent.lower():
                    incidents.append({
                        'id': f"malicious_ua_{ip}_{datetime.now().timestamp()}",
                        'type': 'malicious_user_agent',
                        'title': f'Malicious User Agent from {ip}',
                        'description': f'Detected known malicious user agent: {malicious_agent}',
                        'severity': 'medium',
                        'source_ip': ip,
                        'event_count': 1,
                        'timestamp': datetime.now().isoformat(),
                        'status': 'active',
                        'details': {
                            'user_agent': user_agent,
                            'detected_tool': malicious_agent
                        }
                    })
                    break
        
        # Check for suspicious status codes
        status = log.get('status', '')
        if status in ['401', '403', '404', '500']:
            # Don't create incidents for single occurrences, but flag for aggregation
            pass
        
        return incidents
    
    def _is_failed_login(self, log: Dict[str, Any]) -> bool:
        """Check if log entry indicates a failed login"""
        message = log.get('raw_message', '') or log.get('message', '')
        event_type = log.get('event_type', '')
        
        return (event_type == 'failed_login' or 
                'failed password' in message.lower() or
                'authentication failure' in message.lower() or
                'invalid user' in message.lower())
    
    def _is_error_response(self, log: Dict[str, Any]) -> bool:
        """Check if log entry indicates an error response"""
        status = log.get('status', '')
        level = log.get('level', '')
        
        return (status and int(status) >= 400 if status.isdigit() else False) or level == 'ERROR'
    
    def _deduplicate_incidents(self, incidents: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate incidents and merge similar ones"""
        # Simple deduplication based on type and source IP
        seen = set()
        deduplicated = []
        
        for incident in incidents:
            key = (incident['type'], incident['source_ip'])
            if key not in seen:
                seen.add(key)
                deduplicated.append(incident)
        
        return deduplicated
    
    def _load_default_rules(self) -> List[Dict[str, Any]]:
        """Load default security detection rules"""
        return [
            {
                'id': 'failed_login_threshold',
                'name': 'Failed Login Threshold',
                'pattern': r'(?i)(failed password|authentication failure)',
                'threshold': 5,
                'timeframe': 300,  # 5 minutes
                'severity': 'medium',
                'description': 'Multiple failed login attempts detected'
            },
            {
                'id': 'sql_injection_detection',
                'name': 'SQL Injection Detection',
                'pattern': r'(?i)(union\s+select|select\s+.*\s+from|\'\s*or\s*\'\s*=\s*\')',
                'threshold': 1,
                'timeframe': 60,
                'severity': 'high',
                'description': 'SQL injection attempt detected'
            },
            {
                'id': 'xss_detection',
                'name': 'XSS Detection',
                'pattern': r'(?i)(<script|javascript:|onload=)',
                'threshold': 1,
                'timeframe': 60,
                'severity': 'medium',
                'description': 'Cross-site scripting attempt detected'
            }
        ]
