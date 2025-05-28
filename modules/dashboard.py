import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from datetime import datetime, timedelta
from typing import List, Dict, Any
from collections import Counter

class Dashboard:
    """Dashboard module for visualizing log analysis and security data"""
    
    def __init__(self):
        pass
    
    def render_charts(self):
        """Render all dashboard charts"""
        # Get data from session state
        logs = st.session_state.get('processed_logs', [])
        alerts = st.session_state.get('alerts', [])
        
        if not logs and not alerts:
            st.info("No data available for visualization. Please upload and process log files first.")
            return
        
        # Create tabs for different chart categories
        tab1, tab2, tab3, tab4 = st.tabs(["Log Overview", "Security Alerts", "Traffic Analysis", "Threat Intelligence"])
        
        with tab1:
            self.render_log_overview_charts(logs)
        
        with tab2:
            self.render_security_alert_charts(alerts)
        
        with tab3:
            self.render_traffic_analysis_charts(logs)
        
        with tab4:
            self.render_threat_intelligence_charts(logs, alerts)
    
    def render_log_overview_charts(self, logs: List[Dict[str, Any]]):
        """Render log overview charts"""
        if not logs:
            st.info("No log data available")
            return
        
        st.subheader("📊 Log Overview")
        
        # Convert logs to DataFrame
        df = pd.DataFrame(logs)
        
        # Log levels distribution
        col1, col2 = st.columns(2)
        
        with col1:
            if 'level' in df.columns:
                level_counts = df['level'].value_counts()
                fig_levels = px.pie(
                    values=level_counts.values,
                    names=level_counts.index,
                    title="Log Levels Distribution",
                    color_discrete_map={
                        'ERROR': '#dc3545',
                        'WARN': '#ffc107',
                        'INFO': '#17a2b8',
                        'DEBUG': '#6c757d'
                    }
                )
                st.plotly_chart(fig_levels, use_container_width=True)
            else:
                st.info("No log level information available")
        
        with col2:
            if 'format' in df.columns:
                format_counts = df['format'].value_counts()
                fig_formats = px.bar(
                    x=format_counts.index,
                    y=format_counts.values,
                    title="Log Formats",
                    labels={'x': 'Format', 'y': 'Count'}
                )
                st.plotly_chart(fig_formats, use_container_width=True)
            else:
                st.info("No log format information available")
        
        # Timeline of log entries
        if 'parsed_time' in df.columns:
            # Convert timestamps
            df['datetime'] = pd.to_datetime(df['parsed_time'], errors='coerce')
            df_with_time = df.dropna(subset=['datetime'])
            
            if not df_with_time.empty:
                # Group by hour
                df_with_time['hour'] = df_with_time['datetime'].dt.floor('H')
                hourly_counts = df_with_time.groupby('hour').size().reset_index(name='count')
                
                fig_timeline = px.line(
                    hourly_counts,
                    x='hour',
                    y='count',
                    title="Log Entries Over Time",
                    labels={'hour': 'Time', 'count': 'Number of Logs'}
                )
                st.plotly_chart(fig_timeline, use_container_width=True)
        
        # Top source files
        if 'source_file' in df.columns:
            file_counts = df['source_file'].value_counts().head(10)
            fig_files = px.bar(
                x=file_counts.values,
                y=file_counts.index,
                orientation='h',
                title="Top 10 Source Files",
                labels={'x': 'Number of Logs', 'y': 'Source File'}
            )
            st.plotly_chart(fig_files, use_container_width=True)
    
    def render_security_alert_charts(self, alerts: List[Dict[str, Any]]):
        """Render security alert charts"""
        if not alerts:
            st.info("No security alerts to display")
            return
        
        st.subheader("🚨 Security Alerts Analysis")
        
        # Convert alerts to DataFrame
        df = pd.DataFrame(alerts)
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Alerts by severity
            severity_counts = df['severity'].value_counts()
            colors = {
                'critical': '#dc3545',
                'high': '#fd7e14',
                'medium': '#ffc107',
                'low': '#28a745'
            }
            fig_severity = px.pie(
                values=severity_counts.values,
                names=severity_counts.index,
                title="Alerts by Severity",
                color_discrete_map=colors
            )
            st.plotly_chart(fig_severity, use_container_width=True)
        
        with col2:
            # Alerts by type
            type_counts = df['type'].value_counts().head(10)
            fig_types = px.bar(
                x=type_counts.values,
                y=type_counts.index,
                orientation='h',
                title="Alert Types",
                labels={'x': 'Count', 'y': 'Alert Type'}
            )
            st.plotly_chart(fig_types, use_container_width=True)
        
        # Alert timeline
        if 'timestamp' in df.columns:
            df['datetime'] = pd.to_datetime(df['timestamp'], errors='coerce')
            df_with_time = df.dropna(subset=['datetime'])
            
            if not df_with_time.empty:
                # Group by hour and severity
                df_with_time['hour'] = df_with_time['datetime'].dt.floor('H')
                hourly_severity = df_with_time.groupby(['hour', 'severity']).size().reset_index(name='count')
                
                fig_alert_timeline = px.line(
                    hourly_severity,
                    x='hour',
                    y='count',
                    color='severity',
                    title="Security Alerts Over Time",
                    labels={'hour': 'Time', 'count': 'Number of Alerts'},
                    color_discrete_map=colors
                )
                st.plotly_chart(fig_alert_timeline, use_container_width=True)
        
        # Top source IPs for alerts
        if 'source_ip' in df.columns:
            ip_counts = df['source_ip'].value_counts().head(10)
            fig_ips = px.bar(
                x=ip_counts.values,
                y=ip_counts.index,
                orientation='h',
                title="Top 10 Source IPs (Alerts)",
                labels={'x': 'Number of Alerts', 'y': 'Source IP'}
            )
            st.plotly_chart(fig_ips, use_container_width=True)
    
    def render_traffic_analysis_charts(self, logs: List[Dict[str, Any]]):
        """Render traffic analysis charts"""
        if not logs:
            st.info("No traffic data available")
            return
        
        st.subheader("🌐 Traffic Analysis")
        
        # Filter logs that have IP information
        web_logs = [log for log in logs if log.get('ip')]
        
        if not web_logs:
            st.info("No web traffic data available")
            return
        
        df = pd.DataFrame(web_logs)
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Top source IPs
            if 'ip' in df.columns:
                ip_counts = df['ip'].value_counts().head(15)
                fig_ips = px.bar(
                    x=ip_counts.values,
                    y=ip_counts.index,
                    orientation='h',
                    title="Top 15 Source IPs",
                    labels={'x': 'Request Count', 'y': 'IP Address'}
                )
                st.plotly_chart(fig_ips, use_container_width=True)
        
        with col2:
            # HTTP status codes
            if 'status' in df.columns:
                status_counts = df['status'].value_counts()
                
                # Color code status codes
                status_colors = {}
                for status in status_counts.index:
                    if status.startswith('2'):
                        status_colors[status] = '#28a745'  # Success - green
                    elif status.startswith('3'):
                        status_colors[status] = '#17a2b8'  # Redirect - blue
                    elif status.startswith('4'):
                        status_colors[status] = '#ffc107'  # Client error - yellow
                    elif status.startswith('5'):
                        status_colors[status] = '#dc3545'  # Server error - red
                    else:
                        status_colors[status] = '#6c757d'  # Unknown - gray
                
                fig_status = px.pie(
                    values=status_counts.values,
                    names=status_counts.index,
                    title="HTTP Status Codes",
                    color_discrete_map=status_colors
                )
                st.plotly_chart(fig_status, use_container_width=True)
        
        # Top requested paths
        if 'path' in df.columns:
            path_counts = df['path'].value_counts().head(15)
            fig_paths = px.bar(
                x=path_counts.values,
                y=path_counts.index,
                orientation='h',
                title="Top 15 Requested Paths",
                labels={'x': 'Request Count', 'y': 'Path'}
            )
            st.plotly_chart(fig_paths, use_container_width=True)
        
        # User agents analysis
        if 'user_agent' in df.columns:
            # Extract browser/bot information
            user_agents = df['user_agent'].dropna()
            
            # Simple categorization
            categories = {'Bot/Crawler': 0, 'Browser': 0, 'Unknown': 0, 'Tool': 0}
            
            for ua in user_agents:
                ua_lower = ua.lower()
                if any(bot in ua_lower for bot in ['bot', 'crawler', 'spider', 'scraper']):
                    categories['Bot/Crawler'] += 1
                elif any(browser in ua_lower for browser in ['chrome', 'firefox', 'safari', 'edge', 'opera']):
                    categories['Browser'] += 1
                elif any(tool in ua_lower for tool in ['curl', 'wget', 'python', 'java', 'go-http']):
                    categories['Tool'] += 1
                else:
                    categories['Unknown'] += 1
            
            if sum(categories.values()) > 0:
                fig_ua = px.pie(
                    values=list(categories.values()),
                    names=list(categories.keys()),
                    title="User Agent Categories"
                )
                st.plotly_chart(fig_ua, use_container_width=True)
    
    def render_threat_intelligence_charts(self, logs: List[Dict[str, Any]], alerts: List[Dict[str, Any]]):
        """Render threat intelligence charts"""
        st.subheader("🛡️ Threat Intelligence")
        
        # Geographic analysis of IPs (simplified)
        web_logs = [log for log in logs if log.get('ip')]
        
        if web_logs:
            df = pd.DataFrame(web_logs)
            
            # Count unique IPs
            unique_ips = df['ip'].nunique()
            total_requests = len(df)
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("Unique IP Addresses", unique_ips)
            
            with col2:
                st.metric("Total Requests", total_requests)
            
            with col3:
                avg_requests_per_ip = total_requests / unique_ips if unique_ips > 0 else 0
                st.metric("Avg Requests per IP", f"{avg_requests_per_ip:.2f}")
        
        # Alert trends
        if alerts:
            df_alerts = pd.DataFrame(alerts)
            
            # Time-based alert analysis
            if 'timestamp' in df_alerts.columns:
                df_alerts['datetime'] = pd.to_datetime(df_alerts['timestamp'], errors='coerce')
                df_alerts_with_time = df_alerts.dropna(subset=['datetime'])
                
                if not df_alerts_with_time.empty:
                    # Daily alert trend
                    df_alerts_with_time['date'] = df_alerts_with_time['datetime'].dt.date
                    daily_alerts = df_alerts_with_time.groupby('date').size().reset_index(name='count')
                    
                    fig_trend = px.line(
                        daily_alerts,
                        x='date',
                        y='count',
                        title="Daily Alert Trend",
                        labels={'date': 'Date', 'count': 'Number of Alerts'}
                    )
                    st.plotly_chart(fig_trend, use_container_width=True)
        
        # Attack pattern analysis
        attack_patterns = self._analyze_attack_patterns(logs, alerts)
        if attack_patterns:
            st.subheader("Attack Pattern Analysis")
            
            for pattern, count in attack_patterns.most_common(10):
                st.write(f"**{pattern}:** {count} occurrences")
        
        # Risk score calculation
        risk_score = self._calculate_risk_score(logs, alerts)
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Risk score gauge
            fig_risk = go.Figure(go.Indicator(
                mode="gauge+number+delta",
                value=risk_score,
                domain={'x': [0, 1], 'y': [0, 1]},
                title={'text': "Security Risk Score"},
                delta={'reference': 50},
                gauge={'axis': {'range': [None, 100]},
                       'bar': {'color': "darkblue"},
                       'steps': [
                           {'range': [0, 25], 'color': "lightgreen"},
                           {'range': [25, 50], 'color': "yellow"},
                           {'range': [50, 75], 'color': "orange"},
                           {'range': [75, 100], 'color': "red"}],
                       'threshold': {'line': {'color': "red", 'width': 4},
                                   'thickness': 0.75, 'value': 90}}))
            st.plotly_chart(fig_risk, use_container_width=True)
        
        with col2:
            # Risk factors
            st.subheader("Risk Factors")
            risk_factors = self._get_risk_factors(logs, alerts)
            for factor, score in risk_factors.items():
                st.write(f"**{factor}:** {score}/10")
    
    def _analyze_attack_patterns(self, logs: List[Dict[str, Any]], alerts: List[Dict[str, Any]]) -> Counter:
        """Analyze common attack patterns"""
        patterns = Counter()
        
        # Analyze from alerts
        for alert in alerts:
            alert_type = alert.get('type', 'unknown')
            patterns[alert_type] += 1
        
        # Analyze from logs
        for log in logs:
            message = (log.get('raw_message', '') or log.get('message', '')).lower()
            path = (log.get('path', '')).lower()
            
            # Check for common attack patterns
            if any(pattern in message + path for pattern in ['sql', 'union', 'select']):
                patterns['SQL Injection Attempt'] += 1
            
            if any(pattern in message + path for pattern in ['script', 'javascript', 'xss']):
                patterns['XSS Attempt'] += 1
            
            if any(pattern in message + path for pattern in ['../', '../', 'etc/passwd']):
                patterns['Path Traversal Attempt'] += 1
            
            if any(pattern in message + path for pattern in ['admin', 'wp-admin', 'administrator']):
                patterns['Admin Panel Access Attempt'] += 1
        
        return patterns
    
    def _calculate_risk_score(self, logs: List[Dict[str, Any]], alerts: List[Dict[str, Any]]) -> float:
        """Calculate overall security risk score (0-100)"""
        score = 0
        
        # Base score
        score += 10
        
        # Alert-based scoring
        if alerts:
            critical_alerts = len([a for a in alerts if a.get('severity') == 'critical'])
            high_alerts = len([a for a in alerts if a.get('severity') == 'high'])
            medium_alerts = len([a for a in alerts if a.get('severity') == 'medium'])
            
            score += min(critical_alerts * 20, 40)  # Max 40 for critical alerts
            score += min(high_alerts * 10, 30)     # Max 30 for high alerts
            score += min(medium_alerts * 5, 20)    # Max 20 for medium alerts
        
        # Log-based scoring
        if logs:
            error_logs = len([l for l in logs if l.get('level') == 'ERROR'])
            total_logs = len(logs)
            
            if total_logs > 0:
                error_rate = error_logs / total_logs
                score += min(error_rate * 50, 25)  # Max 25 for error rate
        
        return min(score, 100)
    
    def _get_risk_factors(self, logs: List[Dict[str, Any]], alerts: List[Dict[str, Any]]) -> Dict[str, int]:
        """Get individual risk factor scores"""
        factors = {
            'Failed Login Attempts': 0,
            'Malicious Traffic': 0,
            'Error Rate': 0,
            'Suspicious IPs': 0,
            'Attack Attempts': 0
        }
        
        if alerts:
            # Failed login attempts
            failed_logins = len([a for a in alerts if 'brute_force' in a.get('type', '')])
            factors['Failed Login Attempts'] = min(failed_logins, 10)
            
            # Attack attempts
            attacks = len([a for a in alerts if any(attack in a.get('type', '') 
                          for attack in ['injection', 'xss', 'traversal'])])
            factors['Attack Attempts'] = min(attacks, 10)
            
            # Suspicious IPs
            unique_malicious_ips = len(set(a.get('source_ip') for a in alerts))
            factors['Suspicious IPs'] = min(unique_malicious_ips, 10)
        
        if logs:
            # Error rate
            error_logs = len([l for l in logs if l.get('level') == 'ERROR'])
            total_logs = len(logs)
            if total_logs > 0:
                error_rate = (error_logs / total_logs) * 100
                factors['Error Rate'] = min(int(error_rate), 10)
        
        return factors
