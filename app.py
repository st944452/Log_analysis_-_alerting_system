import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import os
import json
from modules.log_parser import LogParser
from modules.security_analyzer import SecurityAnalyzer
from modules.alert_manager import AlertManager
from modules.dashboard import Dashboard
from modules.utils import initialize_session_state, load_config

# Page configuration
st.set_page_config(
    page_title="Log Analysis & Security Alerting Platform",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize session state and configuration
initialize_session_state()
config = load_config()

# Initialize components
log_parser = LogParser()
security_analyzer = SecurityAnalyzer()
alert_manager = AlertManager()
dashboard = Dashboard()

def main():
    st.title("🔒 Log Analysis & Security Alerting Platform")
    st.markdown("---")
    
    # Sidebar navigation
    st.sidebar.title("Navigation")
    page = st.sidebar.selectbox(
        "Select Page",
        ["Dashboard", "Log Upload & Analysis", "Security Monitoring", "Alert Management", "Settings"]
    )
    
    if page == "Dashboard":
        dashboard_page()
    elif page == "Log Upload & Analysis":
        log_analysis_page()
    elif page == "Security Monitoring":
        security_monitoring_page()
    elif page == "Alert Management":
        alert_management_page()
    elif page == "Settings":
        settings_page()

def dashboard_page():
    st.header("📊 Security Dashboard")
    
    # Display key metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        total_logs = len(st.session_state.get('processed_logs', []))
        st.metric("Total Logs Processed", total_logs)
    
    with col2:
        active_alerts = len([alert for alert in st.session_state.get('alerts', []) if alert.get('status') == 'active'])
        st.metric("Active Alerts", active_alerts)
    
    with col3:
        security_incidents = len([alert for alert in st.session_state.get('alerts', []) if alert.get('severity') in ['high', 'critical']])
        st.metric("Security Incidents", security_incidents)
    
    with col4:
        last_scan = st.session_state.get('last_scan_time', 'Never')
        st.metric("Last Scan", last_scan)
    
    # Display dashboard charts
    dashboard.render_charts()

def log_analysis_page():
    st.header("📄 Log Upload & Analysis")
    
    # File upload section
    st.subheader("Upload Log Files")
    uploaded_files = st.file_uploader(
        "Choose log files",
        accept_multiple_files=True,
        type=['log', 'txt', 'json', 'csv']
    )
    
    if uploaded_files:
        st.success(f"Uploaded {len(uploaded_files)} file(s)")
        
        # Process uploaded files
        if st.button("Process Log Files"):
            with st.spinner("Processing log files..."):
                all_parsed_logs = []
                
                for uploaded_file in uploaded_files:
                    try:
                        # Read file content
                        content = uploaded_file.read().decode('utf-8')
                        
                        # Parse logs based on file type and content
                        parsed_logs = log_parser.parse_logs(content, uploaded_file.name)
                        all_parsed_logs.extend(parsed_logs)
                        
                        st.success(f"Processed {uploaded_file.name}: {len(parsed_logs)} log entries")
                        
                    except Exception as e:
                        st.error(f"Error processing {uploaded_file.name}: {str(e)}")
                
                # Store processed logs in session state
                if all_parsed_logs:
                    st.session_state['processed_logs'] = all_parsed_logs
                    st.session_state['last_scan_time'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    
                    # Run security analysis
                    security_incidents = security_analyzer.analyze_logs(all_parsed_logs)
                    
                    if security_incidents:
                        st.session_state['alerts'].extend(security_incidents)
                        st.warning(f"Detected {len(security_incidents)} security incidents!")
                    
                    st.rerun()
    
    # Display parsed logs
    if st.session_state.get('processed_logs'):
        st.subheader("Parsed Log Entries")
        
        # Search and filter options
        col1, col2 = st.columns(2)
        with col1:
            search_term = st.text_input("Search logs", placeholder="Enter search term...")
        with col2:
            log_level_filter = st.selectbox("Filter by level", ["All", "ERROR", "WARN", "INFO", "DEBUG"])
        
        # Display logs
        logs_df = pd.DataFrame(st.session_state['processed_logs'])
        
        # Apply filters
        if search_term:
            logs_df = logs_df[logs_df.astype(str).apply(lambda x: x.str.contains(search_term, case=False, na=False)).any(axis=1)]
        
        if log_level_filter != "All":
            logs_df = logs_df[logs_df.get('level', '').str.upper() == log_level_filter]
        
        st.dataframe(logs_df, use_container_width=True)
        
        # Export functionality
        if st.button("Export Analysis Report"):
            report_data = {
                'timestamp': datetime.now().isoformat(),
                'total_logs': len(st.session_state['processed_logs']),
                'alerts': st.session_state.get('alerts', []),
                'logs_sample': st.session_state['processed_logs'][:100]  # First 100 logs
            }
            
            st.download_button(
                label="Download Report (JSON)",
                data=json.dumps(report_data, indent=2),
                file_name=f"log_analysis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json"
            )

def security_monitoring_page():
    st.header("🛡️ Security Monitoring")
    
    # Real-time monitoring toggle
    col1, col2 = st.columns(2)
    with col1:
        monitoring_enabled = st.toggle("Enable Real-time Monitoring", value=st.session_state.get('monitoring_enabled', False))
        st.session_state['monitoring_enabled'] = monitoring_enabled
    
    with col2:
        if st.button("Run Security Scan"):
            if st.session_state.get('processed_logs'):
                with st.spinner("Running security analysis..."):
                    incidents = security_analyzer.analyze_logs(st.session_state['processed_logs'])
                    if incidents:
                        st.session_state['alerts'].extend(incidents)
                        st.success(f"Security scan completed. Found {len(incidents)} incidents.")
                    else:
                        st.info("Security scan completed. No incidents detected.")
                    st.rerun()
            else:
                st.warning("No logs available for analysis. Please upload log files first.")
    
    # Display security alerts
    st.subheader("Security Alerts")
    alerts = st.session_state.get('alerts', [])
    
    if alerts:
        # Filter alerts by severity
        severity_filter = st.selectbox("Filter by severity", ["All", "critical", "high", "medium", "low"])
        
        filtered_alerts = alerts
        if severity_filter != "All":
            filtered_alerts = [alert for alert in alerts if alert.get('severity') == severity_filter]
        
        for alert in filtered_alerts:
            severity_color = {
                'critical': '🔴',
                'high': '🟠',
                'medium': '🟡',
                'low': '🟢'
            }.get(alert.get('severity', 'low'), '⚪')
            
            with st.expander(f"{severity_color} {alert.get('title', 'Security Alert')} - {alert.get('timestamp', '')}"):
                st.write(f"**Severity:** {alert.get('severity', 'Unknown')}")
                st.write(f"**Description:** {alert.get('description', 'No description available')}")
                st.write(f"**Source IP:** {alert.get('source_ip', 'Unknown')}")
                st.write(f"**Event Count:** {alert.get('event_count', 1)}")
                
                col1, col2 = st.columns(2)
                with col1:
                    if st.button(f"Acknowledge Alert", key=f"ack_{alert.get('id')}"):
                        alert['status'] = 'acknowledged'
                        st.success("Alert acknowledged")
                        st.rerun()
                
                with col2:
                    if st.button(f"Send Email Alert", key=f"email_{alert.get('id')}"):
                        alert_manager.send_email_alert(alert)
                        st.success("Email alert sent")
    else:
        st.info("No security alerts found.")

def alert_management_page():
    st.header("⚠️ Alert Management")
    
    # Alert rules configuration
    st.subheader("Alert Rules Configuration")
    
    with st.expander("Configure Alert Rules"):
        col1, col2 = st.columns(2)
        
        with col1:
            rule_name = st.text_input("Rule Name")
            rule_pattern = st.text_input("Pattern (regex)")
            rule_severity = st.selectbox("Severity", ["low", "medium", "high", "critical"])
        
        with col2:
            rule_description = st.text_area("Description")
            threshold = st.number_input("Threshold (events per hour)", min_value=1, value=5)
        
        if st.button("Add Alert Rule"):
            if rule_name and rule_pattern:
                new_rule = {
                    'id': f"rule_{datetime.now().timestamp()}",
                    'name': rule_name,
                    'pattern': rule_pattern,
                    'severity': rule_severity,
                    'description': rule_description,
                    'threshold': threshold,
                    'enabled': True
                }
                
                if 'alert_rules' not in st.session_state:
                    st.session_state['alert_rules'] = []
                
                st.session_state['alert_rules'].append(new_rule)
                st.success(f"Alert rule '{rule_name}' added successfully")
                st.rerun()
            else:
                st.error("Please provide rule name and pattern")
    
    # Display existing alert rules
    st.subheader("Existing Alert Rules")
    alert_rules = st.session_state.get('alert_rules', [])
    
    if alert_rules:
        for rule in alert_rules:
            with st.expander(f"Rule: {rule['name']} ({rule['severity']})"):
                st.write(f"**Pattern:** {rule['pattern']}")
                st.write(f"**Description:** {rule['description']}")
                st.write(f"**Threshold:** {rule['threshold']} events/hour")
                
                col1, col2 = st.columns(2)
                with col1:
                    enabled = st.checkbox("Enabled", value=rule['enabled'], key=f"enable_{rule['id']}")
                    rule['enabled'] = enabled
                
                with col2:
                    if st.button("Delete Rule", key=f"delete_{rule['id']}"):
                        st.session_state['alert_rules'] = [r for r in alert_rules if r['id'] != rule['id']]
                        st.success("Rule deleted")
                        st.rerun()
    else:
        st.info("No alert rules configured.")
    
    # Email notification settings
    st.subheader("Email Notification Settings")
    with st.expander("Configure Email Alerts"):
        email_enabled = st.checkbox("Enable Email Notifications", value=st.session_state.get('email_enabled', False))
        smtp_server = st.text_input("SMTP Server", value=st.session_state.get('smtp_server', 'smtp.gmail.com'))
        smtp_port = st.number_input("SMTP Port", value=st.session_state.get('smtp_port', 587))
        sender_email = st.text_input("Sender Email", value=st.session_state.get('sender_email', ''))
        sender_password = st.text_input("Sender Password", type="password")
        recipient_emails = st.text_area("Recipient Emails (comma-separated)", value=st.session_state.get('recipient_emails', ''))
        
        if st.button("Save Email Settings"):
            st.session_state.update({
                'email_enabled': email_enabled,
                'smtp_server': smtp_server,
                'smtp_port': smtp_port,
                'sender_email': sender_email,
                'sender_password': sender_password,
                'recipient_emails': recipient_emails
            })
            st.success("Email settings saved")

def settings_page():
    st.header("⚙️ Settings")
    
    # Log retention settings
    st.subheader("Log Retention Settings")
    retention_days = st.number_input("Log Retention Period (days)", min_value=1, max_value=365, value=30)
    max_log_size = st.number_input("Maximum Log File Size (MB)", min_value=1, max_value=1000, value=100)
    
    # Auto-analysis settings
    st.subheader("Auto-Analysis Settings")
    auto_analysis = st.checkbox("Enable Automatic Analysis", value=True)
    analysis_interval = st.selectbox("Analysis Interval", ["1 minute", "5 minutes", "15 minutes", "1 hour"])
    
    # Clear data options
    st.subheader("Data Management")
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("Clear All Logs"):
            st.session_state['processed_logs'] = []
            st.success("All logs cleared")
            st.rerun()
    
    with col2:
        if st.button("Clear All Alerts"):
            st.session_state['alerts'] = []
            st.success("All alerts cleared")
            st.rerun()
    
    # Export/Import configuration
    st.subheader("Configuration Management")
    
    if st.button("Export Configuration"):
        config_data = {
            'alert_rules': st.session_state.get('alert_rules', []),
            'email_settings': {
                'email_enabled': st.session_state.get('email_enabled', False),
                'smtp_server': st.session_state.get('smtp_server', ''),
                'smtp_port': st.session_state.get('smtp_port', 587),
                'sender_email': st.session_state.get('sender_email', ''),
                'recipient_emails': st.session_state.get('recipient_emails', '')
            }
        }
        
        st.download_button(
            label="Download Configuration",
            data=json.dumps(config_data, indent=2),
            file_name=f"log_analyzer_config_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json"
        )

if __name__ == "__main__":
    main()
