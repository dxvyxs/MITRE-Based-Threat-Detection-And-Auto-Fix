A comprehensive real-time security monitoring platform designed to detect, analyze, and respond to cyber threats across multiple attack vectors. This system provides continuous surveillance of file systems, network activity, and process behavior while correlating events using the MITRE ATT&CK framework.

The platform integrates multiple security monitoring layers into a unified threat detection system. It watches for suspicious file activities in critical directories, monitors process creation for malicious behavior patterns, tracks network connections for anomalous activity, and correlates all events to identify sophisticated attack campaigns. The system uses SQLite for centralized event storage and provides both console alerts and web-based visualization.

Components:

File System Monitor - Real-time monitoring of file creations, modifications, and movements in system-critical directories using watchdog. Detects suspicious file extensions, analyzes file hashes, and identifies malware drop locations.

Process Monitor - Tracks process creation and analyzes for suspicious characteristics including known malicious executables, suspicious execution locations, and suspicious command-line parameters.

Network Monitor - Watches established network connections and logs new outbound/inbound connections for analysis and correlation.

Event Correlator - Advanced correlation engine that identifies attack patterns across multiple events, maps to MITRE ATT&CK techniques, and suggests D3FEND countermeasures. Includes automated email alerts.

Security Dashboard - Flask-based web interface providing real-time visualization of security events, correlation alerts, and threat intelligence.

Installation & Setup:

Install required dependencies: `pip install watchdog psutil flask`

Start the file system monitor: `python filesystemmonitor.py` - begins monitoring critical system directories for suspicious file activities.

Start process monitoring: `python processmonitor.py` - initiates continuous process watching for malicious behavior patterns.

Start network monitoring: `python networkmonitor.py` - begins tracking network connections and logging established sessions.

Launch the security dashboard: `python live.py` - starts the web interface on http://localhost:5000 for real-time monitoring.

Start the correlation engine: `python eventcorrelator.py` - begins analyzing event patterns and generating security alerts.

Key Features:

Multi-Vector Detection - Combines file system, process, and network monitoring for comprehensive coverage.

MITRE ATT&CK Integration - Maps all detected activities to specific MITRE ATT&CK techniques for standardized threat intelligence.

Real-time Correlation - Identifies attack patterns across multiple events and time windows to detect sophisticated campaigns.

Automated Countermeasures - Suggests and can execute D3FEND countermeasures based on detected attack techniques.

Centralized Dashboard - Web-based interface for security operations with real-time event streaming and alert management.

Email Notifications - Automated alerting system for critical security events and correlation findings.

Detection Capabilities:

The system detects suspicious file extensions (.exe, .bat, .ps1, .scr, etc.) in sensitive locations, identifies processes running from temporary directories, flags encoded PowerShell commands, monitors for DLL injection attempts, tracks network connections to unknown endpoints, and correlates multiple low-severity events into high-confidence attack patterns.

Usage Notes:

Run each monitoring component in separate terminals for comprehensive coverage. The system creates and uses `threat_detection.db` for all event storage. Ensure proper permissions for monitoring system directories. The web dashboard provides the best overview of security posture while individual monitors give detailed real-time alerts. Correlation engine works best when all monitoring components are active.
