import re
import json
import pandas as pd
from datetime import datetime
from typing import List, Dict, Any
import csv
from io import StringIO

class LogParser:
    """Log parser for various log formats including Apache, Nginx, system logs, and JSON logs"""
    
    def __init__(self):
        # Common log patterns
        self.patterns = {
            'apache_common': r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<timestamp>[^\]]+)\] "(?P<method>\w+) (?P<path>[^\s]+) (?P<protocol>[^"]+)" (?P<status>\d+) (?P<size>\d+|-)',
            'apache_combined': r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<timestamp>[^\]]+)\] "(?P<method>\w+) (?P<path>[^\s]+) (?P<protocol>[^"]+)" (?P<status>\d+) (?P<size>\d+|-) "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"',
            'nginx': r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<timestamp>[^\]]+)\] "(?P<method>\w+) (?P<path>[^\s]+) (?P<protocol>[^"]+)" (?P<status>\d+) (?P<size>\d+) "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"',
            'syslog': r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+) (?P<hostname>\S+) (?P<process>\S+): (?P<message>.*)',
            'auth_log': r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+) (?P<hostname>\S+) (?P<process>\S+)\[(?P<pid>\d+)\]: (?P<message>.*)',
            'failed_login': r'Failed password for (?P<user>\w+) from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)',
            'successful_login': r'Accepted password for (?P<user>\w+) from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)'
        }
    
    def parse_logs(self, content: str, filename: str) -> List[Dict[str, Any]]:
        """Parse logs based on content and filename"""
        parsed_logs = []
        
        # Determine log format based on filename and content
        if filename.endswith('.json'):
            parsed_logs = self._parse_json_logs(content)
        elif filename.endswith('.csv'):
            parsed_logs = self._parse_csv_logs(content)
        elif 'access.log' in filename or 'access_log' in filename:
            parsed_logs = self._parse_web_logs(content)
        elif 'auth.log' in filename or 'secure' in filename:
            parsed_logs = self._parse_auth_logs(content)
        elif 'syslog' in filename or 'messages' in filename:
            parsed_logs = self._parse_system_logs(content)
        else:
            # Try to auto-detect format
            parsed_logs = self._auto_parse_logs(content)
        
        # Add metadata to each log entry
        for log in parsed_logs:
            log['source_file'] = filename
            log['parsed_timestamp'] = datetime.now().isoformat()
            if 'timestamp' in log and not isinstance(log['timestamp'], str):
                log['timestamp'] = str(log['timestamp'])
        
        return parsed_logs
    
    def _parse_json_logs(self, content: str) -> List[Dict[str, Any]]:
        """Parse JSON format logs"""
        logs = []
        lines = content.strip().split('\n')
        
        for line_num, line in enumerate(lines, 1):
            if line.strip():
                try:
                    log_entry = json.loads(line)
                    log_entry['line_number'] = line_num
                    log_entry['format'] = 'json'
                    logs.append(log_entry)
                except json.JSONDecodeError as e:
                    # If not valid JSON, treat as raw log
                    logs.append({
                        'line_number': line_num,
                        'format': 'raw',
                        'raw_message': line,
                        'parse_error': str(e)
                    })
        
        return logs
    
    def _parse_csv_logs(self, content: str) -> List[Dict[str, Any]]:
        """Parse CSV format logs"""
        logs = []
        try:
            csv_reader = csv.DictReader(StringIO(content))
            for row_num, row in enumerate(csv_reader, 1):
                row['line_number'] = row_num
                row['format'] = 'csv'
                logs.append(row)
        except Exception as e:
            # Fallback to raw parsing
            logs = self._parse_raw_logs(content)
        
        return logs
    
    def _parse_web_logs(self, content: str) -> List[Dict[str, Any]]:
        """Parse web server logs (Apache/Nginx)"""
        logs = []
        lines = content.strip().split('\n')
        
        for line_num, line in enumerate(lines, 1):
            if line.strip():
                # Try Apache combined format first
                match = re.match(self.patterns['apache_combined'], line)
                if match:
                    log_entry = match.groupdict()
                    log_entry['format'] = 'apache_combined'
                else:
                    # Try Apache common format
                    match = re.match(self.patterns['apache_common'], line)
                    if match:
                        log_entry = match.groupdict()
                        log_entry['format'] = 'apache_common'
                    else:
                        # Try Nginx format
                        match = re.match(self.patterns['nginx'], line)
                        if match:
                            log_entry = match.groupdict()
                            log_entry['format'] = 'nginx'
                        else:
                            # Fallback to raw
                            log_entry = {
                                'format': 'raw',
                                'raw_message': line
                            }
                
                log_entry['line_number'] = line_num
                
                # Parse timestamp if present
                if 'timestamp' in log_entry:
                    log_entry['parsed_time'] = self._parse_timestamp(log_entry['timestamp'])
                
                # Categorize status codes
                if 'status' in log_entry:
                    status = int(log_entry['status']) if log_entry['status'].isdigit() else 0
                    if status >= 400:
                        log_entry['level'] = 'ERROR'
                    elif status >= 300:
                        log_entry['level'] = 'WARN'
                    else:
                        log_entry['level'] = 'INFO'
                
                logs.append(log_entry)
        
        return logs
    
    def _parse_auth_logs(self, content: str) -> List[Dict[str, Any]]:
        """Parse authentication logs"""
        logs = []
        lines = content.strip().split('\n')
        
        for line_num, line in enumerate(lines, 1):
            if line.strip():
                # Try auth log format
                match = re.match(self.patterns['auth_log'], line)
                if match:
                    log_entry = match.groupdict()
                    log_entry['format'] = 'auth_log'
                    
                    # Check for specific authentication events
                    message = log_entry.get('message', '')
                    
                    # Failed login detection
                    failed_match = re.search(self.patterns['failed_login'], message)
                    if failed_match:
                        log_entry.update(failed_match.groupdict())
                        log_entry['event_type'] = 'failed_login'
                        log_entry['level'] = 'WARN'
                    
                    # Successful login detection
                    success_match = re.search(self.patterns['successful_login'], message)
                    if success_match:
                        log_entry.update(success_match.groupdict())
                        log_entry['event_type'] = 'successful_login'
                        log_entry['level'] = 'INFO'
                    
                    # Other authentication events
                    if 'authentication failure' in message.lower():
                        log_entry['event_type'] = 'auth_failure'
                        log_entry['level'] = 'ERROR'
                    elif 'session opened' in message.lower():
                        log_entry['event_type'] = 'session_opened'
                        log_entry['level'] = 'INFO'
                    elif 'session closed' in message.lower():
                        log_entry['event_type'] = 'session_closed'
                        log_entry['level'] = 'INFO'
                
                else:
                    # Fallback to syslog format
                    match = re.match(self.patterns['syslog'], line)
                    if match:
                        log_entry = match.groupdict()
                        log_entry['format'] = 'syslog'
                    else:
                        log_entry = {
                            'format': 'raw',
                            'raw_message': line
                        }
                
                log_entry['line_number'] = line_num
                
                # Parse timestamp
                if 'timestamp' in log_entry:
                    log_entry['parsed_time'] = self._parse_timestamp(log_entry['timestamp'])
                
                logs.append(log_entry)
        
        return logs
    
    def _parse_system_logs(self, content: str) -> List[Dict[str, Any]]:
        """Parse system logs (syslog format)"""
        logs = []
        lines = content.strip().split('\n')
        
        for line_num, line in enumerate(lines, 1):
            if line.strip():
                match = re.match(self.patterns['syslog'], line)
                if match:
                    log_entry = match.groupdict()
                    log_entry['format'] = 'syslog'
                    
                    # Determine log level based on message content
                    message = log_entry.get('message', '').lower()
                    if any(word in message for word in ['error', 'failed', 'failure', 'critical']):
                        log_entry['level'] = 'ERROR'
                    elif any(word in message for word in ['warning', 'warn']):
                        log_entry['level'] = 'WARN'
                    elif any(word in message for word in ['debug']):
                        log_entry['level'] = 'DEBUG'
                    else:
                        log_entry['level'] = 'INFO'
                
                else:
                    log_entry = {
                        'format': 'raw',
                        'raw_message': line,
                        'level': 'INFO'
                    }
                
                log_entry['line_number'] = line_num
                
                # Parse timestamp
                if 'timestamp' in log_entry:
                    log_entry['parsed_time'] = self._parse_timestamp(log_entry['timestamp'])
                
                logs.append(log_entry)
        
        return logs
    
    def _auto_parse_logs(self, content: str) -> List[Dict[str, Any]]:
        """Auto-detect and parse log format"""
        logs = []
        lines = content.strip().split('\n')
        
        for line_num, line in enumerate(lines, 1):
            if line.strip():
                # Try all patterns
                matched = False
                for pattern_name, pattern in self.patterns.items():
                    match = re.match(pattern, line)
                    if match:
                        log_entry = match.groupdict()
                        log_entry['format'] = pattern_name
                        log_entry['line_number'] = line_num
                        
                        # Parse timestamp
                        if 'timestamp' in log_entry:
                            log_entry['parsed_time'] = self._parse_timestamp(log_entry['timestamp'])
                        
                        logs.append(log_entry)
                        matched = True
                        break
                
                if not matched:
                    # Fallback to raw parsing
                    logs.append({
                        'format': 'raw',
                        'raw_message': line,
                        'line_number': line_num,
                        'level': 'INFO'
                    })
        
        return logs
    
    def _parse_raw_logs(self, content: str) -> List[Dict[str, Any]]:
        """Parse logs as raw text"""
        logs = []
        lines = content.strip().split('\n')
        
        for line_num, line in enumerate(lines, 1):
            if line.strip():
                logs.append({
                    'format': 'raw',
                    'raw_message': line,
                    'line_number': line_num,
                    'level': 'INFO'
                })
        
        return logs
    
    def _parse_timestamp(self, timestamp_str: str) -> str:
        """Parse various timestamp formats"""
        timestamp_formats = [
            '%d/%b/%Y:%H:%M:%S %z',  # Apache format
            '%d/%b/%Y:%H:%M:%S',     # Apache without timezone
            '%b %d %H:%M:%S',        # Syslog format
            '%Y-%m-%d %H:%M:%S',     # Standard format
            '%Y-%m-%dT%H:%M:%S',     # ISO format
            '%Y-%m-%dT%H:%M:%SZ',    # ISO with Z
        ]
        
        for fmt in timestamp_formats:
            try:
                parsed_time = datetime.strptime(timestamp_str.strip(), fmt)
                return parsed_time.isoformat()
            except ValueError:
                continue
        
        # If no format matches, return original string
        return timestamp_str
