import smtplib
import json
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Dict, Any, List
import streamlit as st

class AlertManager:
    """Manages alert generation, storage, and notification"""
    
    def __init__(self):
        self.alerts_file = 'data/alerts.json'
        self.ensure_data_directory()
    
    def ensure_data_directory(self):
        """Ensure data directory exists"""
        os.makedirs('data', exist_ok=True)
    
    def send_email_alert(self, alert: Dict[str, Any]) -> bool:
        """Send email notification for an alert"""
        try:
            # Get email configuration from session state
            if not st.session_state.get('email_enabled', False):
                st.warning("Email notifications are not enabled")
                return False
            
            smtp_server = st.session_state.get('smtp_server', 'smtp.gmail.com')
            smtp_port = st.session_state.get('smtp_port', 587)
            sender_email = st.session_state.get('sender_email', '')
            sender_password = st.session_state.get('sender_password', '')
            recipient_emails = st.session_state.get('recipient_emails', '')
            
            if not all([sender_email, sender_password, recipient_emails]):
                st.error("Email configuration is incomplete")
                return False
            
            # Parse recipient emails
            recipients = [email.strip() for email in recipient_emails.split(',') if email.strip()]
            
            # Create email message
            msg = MIMEMultipart()
            msg['From'] = sender_email
            msg['To'] = ', '.join(recipients)
            msg['Subject'] = f"Security Alert: {alert.get('title', 'Unknown Alert')}"
            
            # Create email body
            body = self._create_email_body(alert)
            msg.attach(MIMEText(body, 'html'))
            
            # Send email
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(sender_email, sender_password)
            text = msg.as_string()
            server.sendmail(sender_email, recipients, text)
            server.quit()
            
            # Update alert to mark as emailed
            alert['email_sent'] = True
            alert['email_sent_time'] = datetime.now().isoformat()
            
            return True
            
        except Exception as e:
            st.error(f"Failed to send email alert: {str(e)}")
            return False
    
    def _create_email_body(self, alert: Dict[str, Any]) -> str:
        """Create HTML email body for alert"""
        severity_colors = {
            'critical': '#dc3545',
            'high': '#fd7e14',
            'medium': '#ffc107',
            'low': '#28a745'
        }
        
        severity = alert.get('severity', 'medium')
        color = severity_colors.get(severity, '#6c757d')
        
        body = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .alert-header {{ background-color: {color}; color: white; padding: 15px; border-radius: 5px; }}
                .alert-content {{ padding: 20px; border: 1px solid #ddd; border-radius: 5px; margin-top: 10px; }}
                .detail-item {{ margin: 10px 0; }}
                .label {{ font-weight: bold; }}
            </style>
        </head>
        <body>
            <div class="alert-header">
                <h2>🚨 Security Alert: {alert.get('title', 'Unknown Alert')}</h2>
            </div>
            
            <div class="alert-content">
                <div class="detail-item">
                    <span class="label">Severity:</span> {severity.upper()}
                </div>
                
                <div class="detail-item">
                    <span class="label">Alert Type:</span> {alert.get('type', 'Unknown')}
                </div>
                
                <div class="detail-item">
                    <span class="label">Source IP:</span> {alert.get('source_ip', 'Unknown')}
                </div>
                
                <div class="detail-item">
                    <span class="label">Event Count:</span> {alert.get('event_count', 1)}
                </div>
                
                <div class="detail-item">
                    <span class="label">Timestamp:</span> {alert.get('timestamp', 'Unknown')}
                </div>
                
                <div class="detail-item">
                    <span class="label">Description:</span>
                    <p>{alert.get('description', 'No description available')}</p>
                </div>
                
                {self._create_details_section(alert)}
            </div>
            
            <div style="margin-top: 20px; padding: 15px; background-color: #f8f9fa; border-radius: 5px;">
                <p><strong>Recommended Actions:</strong></p>
                <ul>
                    <li>Investigate the source IP address: {alert.get('source_ip', 'Unknown')}</li>
                    <li>Review related log entries for additional context</li>
                    <li>Consider blocking the IP if malicious activity is confirmed</li>
                    <li>Update security rules if this represents a new attack pattern</li>
                </ul>
            </div>
            
            <div style="margin-top: 20px; font-size: 12px; color: #6c757d;">
                <p>This alert was generated by the Log Analysis & Security Alerting Platform.</p>
                <p>Alert ID: {alert.get('id', 'Unknown')}</p>
            </div>
        </body>
        </html>
        """
        
        return body
    
    def _create_details_section(self, alert: Dict[str, Any]) -> str:
        """Create additional details section for email"""
        details = alert.get('details', {})
        if not details:
            return ""
        
        section = '<div class="detail-item"><span class="label">Additional Details:</span><ul>'
        
        for key, value in details.items():
            if isinstance(value, dict):
                continue  # Skip complex nested objects
            section += f'<li><strong>{key.replace("_", " ").title()}:</strong> {value}</li>'
        
        section += '</ul></div>'
        return section
    
    def save_alerts(self, alerts: List[Dict[str, Any]]):
        """Save alerts to file"""
        try:
            with open(self.alerts_file, 'w') as f:
                json.dump(alerts, f, indent=2)
        except Exception as e:
            st.error(f"Failed to save alerts: {str(e)}")
    
    def load_alerts(self) -> List[Dict[str, Any]]:
        """Load alerts from file"""
        try:
            if os.path.exists(self.alerts_file):
                with open(self.alerts_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            st.error(f"Failed to load alerts: {str(e)}")
        
        return []
    
    def create_alert(self, alert_type: str, title: str, description: str, 
                    severity: str = 'medium', source_ip: str = 'unknown',
                    event_count: int = 1, details: Dict[str, Any] = None) -> Dict[str, Any]:
        """Create a new alert"""
        alert = {
            'id': f"{alert_type}_{source_ip}_{datetime.now().timestamp()}",
            'type': alert_type,
            'title': title,
            'description': description,
            'severity': severity,
            'source_ip': source_ip,
            'event_count': event_count,
            'timestamp': datetime.now().isoformat(),
            'status': 'active',
            'created_time': datetime.now().isoformat(),
            'details': details or {}
        }
        
        return alert
    
    def update_alert_status(self, alert_id: str, status: str, alerts: List[Dict[str, Any]]) -> bool:
        """Update alert status"""
        for alert in alerts:
            if alert.get('id') == alert_id:
                alert['status'] = status
                alert['updated_time'] = datetime.now().isoformat()
                return True
        return False
    
    def get_alert_statistics(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Get alert statistics"""
        if not alerts:
            return {
                'total': 0,
                'by_severity': {},
                'by_type': {},
                'by_status': {},
                'recent_count': 0
            }
        
        # Count by severity
        severity_counts = {}
        for alert in alerts:
            severity = alert.get('severity', 'unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Count by type
        type_counts = {}
        for alert in alerts:
            alert_type = alert.get('type', 'unknown')
            type_counts[alert_type] = type_counts.get(alert_type, 0) + 1
        
        # Count by status
        status_counts = {}
        for alert in alerts:
            status = alert.get('status', 'unknown')
            status_counts[status] = status_counts.get(status, 0) + 1
        
        # Count recent alerts (last 24 hours)
        recent_count = 0
        cutoff_time = datetime.now() - timedelta(hours=24)
        for alert in alerts:
            try:
                alert_time = datetime.fromisoformat(alert.get('timestamp', ''))
                if alert_time > cutoff_time:
                    recent_count += 1
            except ValueError:
                pass
        
        return {
            'total': len(alerts),
            'by_severity': severity_counts,
            'by_type': type_counts,
            'by_status': status_counts,
            'recent_count': recent_count
        }
    
    def auto_acknowledge_alerts(self, alerts: List[Dict[str, Any]], 
                              max_age_hours: int = 24) -> int:
        """Auto-acknowledge old alerts"""
        acknowledged_count = 0
        cutoff_time = datetime.now() - timedelta(hours=max_age_hours)
        
        for alert in alerts:
            if alert.get('status') == 'active':
                try:
                    alert_time = datetime.fromisoformat(alert.get('timestamp', ''))
                    if alert_time < cutoff_time:
                        alert['status'] = 'auto_acknowledged'
                        alert['updated_time'] = datetime.now().isoformat()
                        acknowledged_count += 1
                except ValueError:
                    pass
        
        return acknowledged_count
