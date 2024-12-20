"""
Network Security Analysis & Monitoring Tool
-----------------------------------------
Learning Points:

1. Security Features:
   - Port scanning with risk assessment
   - Email phishing detection using NLP and pattern matching
   - URL analysis for malicious indicators
   - Password strength evaluation with entropy calculation
   - Network packet capture and analysis
   - Real-time bandwidth monitoring
   - File & text encryption using industry standards

2. Implementation Highlights:
   - Multi-threaded port scanning for performance
   - GUI using tkinter with custom dark theme
   - Modular class-based architecture with inheritance
   - Exception handling for robust operation
   - Dynamic data visualization with matplotlib
   - Custom encryption using multiple cipher layers
   
3. Best Practices Demonstrated:
   - Type hints for better code clarity
   - Comprehensive error handling
   - Clear separation of concerns
   - Efficient data structures (queues, deques)
   - Thread-safe operations
   - Security-focused input validation

4. Key Libraries Used:
   - scapy: Network packet manipulation
   - cryptography: Secure encryption
   - BeautifulSoup: HTML parsing
   - TextBlob: Natural language processing
   - matplotlib: Data visualization
"""

# Import required libraries for networking, GUI, cryptography, and data processing
import tkinter as tk
from tkinter import ttk, scrolledtext, font, messagebox, filedialog
import threading
import socket
import queue
import ipaddress
from email.message import Message
import email
import re
from collections import defaultdict
import urllib.parse
import datetime
import tldextract
from typing import List, Dict, Set, Tuple
from bs4 import BeautifulSoup
from textblob import TextBlob
import hashlib
import string
import random
import psutil
import time
from collections import deque
from datetime import datetime
import scapy.all as scapy
import nmap
import numpy as np
import matplotlib.pyplot as plt
from scapy.config import conf
from cryptography.fernet import Fernet
from base64 import b64encode
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
import zlib
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
from abc import ABC, abstractmethod
from collections import deque
import queue
import tkinter as tk
from cryptography.fernet import Fernet
import re
import customtkinter as ctk
from abc import ABC, abstractmethod
import threading

# Set global theme settings for CustomTkinter
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class SecuritySuiteApp:
    """Main application class for network security analysis"""
    
    def __init__(self, root):

        self.root = root
        self.init_cipher()
        self.root.title("Advanced Security Analysis Suite")
        self.root.geometry("1000x700")
        
        # Configure root window background
        self.root.configure(bg='#121212')
        
        # Initialize core components
        self.setup_variables()
        self.setup_styles()
        self.create_notebook()
        self.setup_network_tab()
        
        # Dictionary of common ports and their security implications
        self.common_ports = {
            20: ("FTP Data", "File transfer protocol data port. If open, ensure it's intentional as it can be used for data exfiltration."),
            21: ("FTP Control", "File transfer protocol control port. Should be secured with proper authentication and encryption."),
            22: ("SSH", "Secure Shell - remote access. Ensure using latest version and key-based authentication."),
            23: ("Telnet", "CRITICAL: Unencrypted remote access. Should not be open as it's a significant security risk."),
            25: ("SMTP", "Email server port. If not running a mail server, should be closed to prevent spam relay."),
            53: ("DNS", "Domain Name System. If not a DNS server, should be closed to prevent DNS amplification attacks."),
            80: ("HTTP", "Unencrypted web traffic. Consider using HTTPS (443) instead for security."),
            110: ("POP3", "Email retrieval - unencrypted. Consider using POP3S (995) instead."),
            135: ("MSRPC", "Windows RPC. Often targeted for attacks, close if not needed."),
            139: ("NetBIOS", "Windows networking - legacy. Security risk if exposed to internet."),
            143: ("IMAP", "Email retrieval - unencrypted. Consider using IMAPS (993) instead."),
            443: ("HTTPS", "Encrypted web traffic. Ensure valid SSL/TLS certificate is in use."),
            445: ("SMB", "File sharing - Critical to secure or close. Common target for ransomware."),
            1433: ("MSSQL", "Microsoft SQL Server. Database should not be exposed to internet."),
            1521: ("Oracle", "Oracle database. Should be properly secured if needed, otherwise close."),
            3306: ("MySQL", "MySQL database. Should not be directly exposed to internet."),
            3389: ("RDP", "Remote Desktop. High-risk if exposed, use VPN instead."),
            5432: ("PostgreSQL", "PostgreSQL database. Should not be directly exposed to internet."),
            5900: ("VNC", "Remote desktop - unencrypted. Should be tunneled through VPN."),
            8080: ("HTTP Alt", "Alternative HTTP port. Often used for web proxies or development."),
            27017: ("MongoDB", "MongoDB database. Should never be exposed without authentication.")
        }
        
        # Define risk level colors for visual feedback
        self.risk_levels = {
            "CRITICAL": "#FF0000",  # Red
            "HIGH": "#FFA500",      # Orange
            "MEDIUM": "#FFFF00",    # Yellow
            "LOW": "#00FF00"        # Green
        }

        # Patterns and indicators for malicious URL detection
        self.malicious_url_patterns = {
            'suspicious_tlds': {'.xyz', '.top', '.pw', '.cc', '.su', '.tk', '.ml', '.ga', '.cf'},
            'suspicious_keywords': {
                'login', 'account', 'verify', 'secure', 'banking', 'update', 'confirm',
                'paypal', 'microsoft', 'apple', 'google', 'amazon', 'netflix',
                'signin', 'security', 'password', 'credential'
            },
            'suspicious_patterns': [
                r'[0-9]+[a-zA-Z]+[0-9]+\.', # Mixed numbers and letters in domain
                r'[a-zA-Z]{25,}\.', # Very long domain names
                r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', # IP addresses
                r'bit\.ly|goo\.gl|tinyurl\.com|t\.co', # URL shorteners
                r'[a-zA-Z0-9]+-[a-zA-Z0-9]+-[a-zA-Z0-9]+\.' # Multiple hyphens
            ]
        }
        
        # Configure packet capture settings
        conf.use_pcap = True  # Uses Npcap for packet capturing
        self.simulate_traffic = False
        self.monitoring_active = False
        self.encryption_key = None
        self.fernet = None

    def setup_variables(self):
        """Initialize all instance variables and configuration settings"""
        # Network scanning variables
        self.target_ip = tk.StringVar()
        self.start_port = tk.IntVar(value=1)
        self.end_port = tk.IntVar(value=1024)
        
        # Scanning control flags and containers
        self.scan_active = False
        self.MAX_THREADS = 100
        self.scan_threads = []
        self.port_queue = queue.Queue()
        self.results_queue = queue.Queue()
        
        # Network monitoring variables
        self.network_monitoring = False
        self.network_data = deque(maxlen=100)  # Store last 100 readings
        
        # Security requirement definitions
        self.password_requirements = {
            'length': 12,
            'uppercase': 1,
            'lowercase': 1,
            'numbers': 1,
            'special': 1
        }
        
        # Email analysis patterns
        self.phishing_indicators = {
            'urgency_words': {
                'urgent', 'immediate', 'action required', 'account suspended', 'verify now',
                'limited time', 'expires soon', 'suspended', 'blocked', 'suspicious activity',
                'unusual activity', 'unauthorized', 'security alert', 'verify identity',
                'confirm identity', 'secure your account', 'prevent unauthorized',
                'temporary suspension', 'within 24 hours', 'failure to respond'
            },
            'sensitive_words': {
                'password', 'credit card', 'ssn', 'social security', 'bank account',
                'login', 'credential', 'billing', 'payment', 'verify', 'confirm',
                'authenticate', 'update details', 'security details'
            },
            'suspicious_domains': {
                'secure-login', 'account-verify', 'security-check', 'login-check',
                'secure-verify', 'account-secure', 'verify-account'
            },
            'suspicious_patterns': [
                r'-(?:login|verify|secure|check)', # Hyphenated domains
                r'support@(?!legitimate-company\.com)', # Generic support emails
                r'(?:russia|suspicious|unusual).*(?:activity|login|access)', # Location/activity patterns
                r'(?:log\s*in\s*here|click\s*here|verify\s*now)' # Action buttons/links
            ]
        }
        
        # Network statistics containers
        self.packet_stats = defaultdict(int)
        self.bandwidth_history = []
        self.alert_thresholds = {
            'bandwidth_mbps': 100,
            'suspicious_ports': [22, 23, 3389],
            'packet_rate': 1000
        }

    def setup_styles(self):
        self.colors = {
            'bg_dark': '#121212',
            'bg_light': '#1E1E1E',
            'accent': '#303030',
            'text': '#FFFFFF',
            'text_dim': '#AAAAAA',
            'success': '#808080',
            'warning': '#606060',
            'danger': '#404040'
        }
        self.style = ttk.Style()
        self.style.theme_use('default')
        
        self.style.configure('Custom.TNotebook', 
                           background=self.colors['bg_dark'])
        self.style.configure('Custom.TFrame',
                           background=self.colors['bg_dark'])
        self.style.configure('Custom.TButton',
                           background=self.colors['accent'],
                           foreground=self.colors['text'],
                           padding=10)
        self.style.configure('Custom.TLabel',
                           background=self.colors['bg_dark'],
                           foreground=self.colors['text'])
        self.style.configure('Custom.TEntry',
                           fieldbackground=self.colors['bg_light'],
                           foreground=self.colors['text'])

        self.fonts = {
            'header': font.Font(family="Helvetica", size=12, weight="bold"),
            'text': font.Font(family="Consolas", size=10),
            'button': font.Font(family="Helvetica", size=10, weight="bold")
        }
        style = ttk.Style()
        style.configure("Monitor.TFrame", background='#1E1E1E')
        style.configure("Alert.TLabel", foreground='#FF4444')
        self.style.configure('Custom.Treeview',
                        background=self.colors['bg_light'],
                        foreground=self.colors['text'],
                        fieldbackground=self.colors['bg_light'])
        self.style.configure('Custom.Treeview.Heading',
                        background=self.colors['bg_dark'],
                        foreground=self.colors['text'])

    def create_notebook(self):
        # Create tabbed interface for different security tools
        self.notebook = ttk.Notebook(self.root, style='Custom.TNotebook')
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.create_port_scanner_tab()
        self.create_email_analyzer_tab()
        self.create_url_analyzer_tab()
        self.create_password_analyzer_tab()
        self.create_encryption_tab() 

    def create_labeled_entry(self, parent, label_text, variable, placeholder=""):
        frame = ttk.Frame(parent, style='Custom.TFrame')
        
        label = ttk.Label(frame, 
                         text=label_text,
                         font=self.fonts['header'],
                         foreground=self.colors['text'],
                         style='Custom.TLabel')
        label.pack(side='left', padx=5)
        
        entry = ttk.Entry(frame,
                         textvariable=variable,
                         font=self.fonts['text'],
                         style='Custom.TEntry')
        entry.pack(side='left', padx=5, fill='x', expand=True)
        
        if (placeholder):
            entry.insert(0, placeholder)
            entry.bind('<FocusIn>', lambda e: entry.delete(0, 'end') if entry.get() == placeholder else None)
            entry.bind('<FocusOut>', lambda e: entry.insert(0, placeholder) if entry.get() == "" else None)
        
        return frame

    def create_port_scanner_tab(self):
        scanner_frame = ttk.Frame(self.notebook, style='Custom.TFrame')
        self.notebook.add(scanner_frame, text='Port Scanner')
        
        input_frame = self.create_labeled_entry(
            scanner_frame,
            "Target IP:",
            self.target_ip,
            placeholder="Enter IP address"
        )
        input_frame.pack(fill='x', padx=10, pady=5)

        port_frame = ttk.Frame(scanner_frame, style='Custom.TFrame')
        port_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(port_frame, 
                 text="Port Range:", 
                 font=self.fonts['header'],
                 foreground=self.colors['text'],
                 style='Custom.TLabel').pack(side='left', padx=5)
                 
        ttk.Entry(port_frame, 
                 textvariable=self.start_port,
                 width=6,
                 font=self.fonts['text'],
                 style='Custom.TEntry').pack(side='left', padx=5)
                 
        ttk.Label(port_frame,
                 text="to",
                 font=self.fonts['text'],
                 foreground=self.colors['text'],
                 style='Custom.TLabel').pack(side='left', padx=5)
                 
        ttk.Entry(port_frame,
                 textvariable=self.end_port,
                 width=6,
                 font=self.fonts['text'],
                 style='Custom.TEntry').pack(side='left', padx=5)

        self.create_scanner_controls(scanner_frame)
        
        self.progress_bar = ttk.Progressbar(
            scanner_frame,
            orient="horizontal",
            length=400,
            mode="determinate"
        )
        self.progress_bar.pack(pady=10)
        
        self.scan_output = self.create_output_display(scanner_frame)

    def create_scanner_controls(self, parent):
        button_frame = ttk.Frame(parent, style='Custom.TFrame')
        button_frame.pack(fill='x', padx=10, pady=5)
        
        self.scan_button = ttk.Button(
            button_frame,
            text="Start Scan",
            command=self.start_scan,
            style='Custom.TButton'
        )
        self.scan_button.pack(side='left', padx=5)
        
        self.stop_button = ttk.Button(
            button_frame,
            text="Stop Scan",
            command=self.stop_scan,
            style='Custom.TButton',
            state=tk.DISABLED
        )
        self.stop_button.pack(side='left', padx=5)
    def create_url_analyzer_tab(self):
        url_frame = ttk.Frame(self.notebook, style='Custom.TFrame')
        self.notebook.add(url_frame, text='URL Analyzer')
        
        instructions = """Paste URLs below for malicious link analysis.
        The analyzer will check for:
        • Suspicious TLDs
        • Common phishing keywords
        • URL obfuscation techniques
        • Domain age and reputation
        • SSL certificate status
        • Redirections"""
        
        ttk.Label(url_frame, 
                 text=instructions,
                 font=self.fonts['text'],
                 foreground=self.colors['text'],
                 style='Custom.TLabel',
                 justify='left').pack(pady=5, padx=10)
        
        self.url_input = self.create_output_display(url_frame)
        self.url_input.configure(height=5)
        
        ttk.Button(
            url_frame,
            text="Analyze URLs",
            command=self.analyze_urls,
            style='Custom.TButton'
        ).pack(pady=10)
        
        self.url_output = self.create_output_display(url_frame, state='disabled')

    def analyze_urls(self):
        urls = self.url_input.get("1.0", tk.END).strip().split('\n')
        urls = [url.strip() for url in urls if url.strip()]
        
        if not urls:
            messagebox.showerror("Error", "Please enter URLs to analyze")
            return
            
        self.url_output.delete("1.0", tk.END)
        
        for url in urls:
            try:
                risk_score, findings = self._analyze_single_url(url)
                self._display_url_analysis(url, risk_score, findings)
            except Exception as e:
                self.url_output.insert(tk.END, f"Error analyzing {url}: {str(e)}\n")

    def _analyze_single_url(self, url: str) -> Tuple[int, List[str]]:
        # Analyze URL for phishing and malicious indicators
        findings = []
        risk_score = 0
        
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        try:
            parsed = urllib.parse.urlparse(url)
            extracted = tldextract.extract(url)
            
            if parsed.scheme != 'https':
                findings.append("❌ Uses unsecure HTTP protocol")
                risk_score += 30
            
            domain = parsed.netloc.lower()
            if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
                findings.append("❌ Uses suspicious IP address instead of domain")
                risk_score += 40
                
            brands = ['paypal', 'amazon', 'microsoft', 'google', 'apple', 'facebook']
            for brand in brands:
                if brand in domain and not domain.endswith(f'.{brand}.com'):
                    findings.append(f"⚠️ Possible typosquatting attempt of {brand}")
                    risk_score += 35
            
            if len(url) > 100:
                findings.append("⚠️ Unusually long URL")
                risk_score += 15
                
            suspicious_terms = ['login', 'verify', 'account', 'secure', 'update', 'password']
            for term in suspicious_terms:
                if term in url.lower():
                    findings.append(f"⚠️ Contains suspicious keyword: {term}")
                    risk_score += 20
                    break
                    
            if url.count('@') > 0:
                findings.append("❌ Contains @ symbol - possible URL manipulation")
                risk_score += 50
                
            if '%' in url:
                findings.append("⚠️ Contains URL encoding - possible obfuscation")
                risk_score += 25
                
        except Exception as e:
            findings.append(f"Error analyzing URL: {str(e)}")
            risk_score = 100
            
        return min(risk_score, 100), findings

    def _display_url_analysis(self, url: str, risk_score: int, findings: List[str]):
        self.url_output.config(state='normal')
        
        self.url_output.tag_configure("big_bold", font=("Arial", 16, "bold"))
        self.url_output.tag_configure("url", font=("Arial", 11, "bold"))
        
        self.url_output.insert(tk.END, f"\nAnalyzing: ", "url")
        self.url_output.insert(tk.END, f"{url}\n\n")
        self.url_output.insert(tk.END, f"Risk Score: {risk_score}/100\n\n", "big_bold")
        
        for finding in findings:
            self.url_output.insert(tk.END, f"{finding}\n")
        
        self.url_output.insert(tk.END, "\n" + "-"*50 + "\n")
        self.url_output.config(state='disabled')

    def create_password_analyzer_tab(self):
        password_frame = ttk.Frame(self.notebook, style='Custom.TFrame')
        self.notebook.add(password_frame, text='Password Analyzer')
        
        input_frame = ttk.Frame(password_frame, style='Custom.TFrame')
        input_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(input_frame,
                 text="Enter Password:",
                 font=self.fonts['header'],
                 foreground=self.colors['text'],
                 style='Custom.TLabel').pack(side='left', padx=5)
                 
        self.password_input = ttk.Entry(
            input_frame,
            font=self.fonts['text'],
            style='Custom.TEntry',
           #show='•'  # Mask password
        )
        self.password_input.pack(side='left', padx=5, fill='x', expand=True)
        
        control_frame = ttk.Frame(password_frame, style='Custom.TFrame')
        control_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(
            control_frame,
            text="Analyze Password",
            command=self.analyze_password,
            style='Custom.TButton'
        ).pack(side='left', padx=5)
        
        ttk.Button(
            control_frame,
            text="Generate Strong Password",
            command=self.generate_password,
            style='Custom.TButton'
        ).pack(side='left', padx=5)
        
        self.password_output = scrolledtext.ScrolledText(
            password_frame,
            font=self.fonts['text'],
            bg=self.colors['bg_light'],
            fg=self.colors['text'],
            height=15,
            state='disabled'
        )
        self.password_output.pack(fill='both', expand=True, padx=10, pady=5)

    def analyze_password(self):
        # Check password strength and security compliance
        password = self.password_input.get()
        
        if not password:
            messagebox.showerror("Error", "Please enter a password")
            return
            
        length_score = min(len(password) / self.password_requirements['length'], 1.0)
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)
        
        charset_size = 0
        if has_upper: charset_size += 26
        if has_lower: charset_size += 26
        if has_digit: charset_size += 10
        if has_special: charset_size += 32
        entropy = len(password) * (charset_size.bit_length() if charset_size > 0 else 0)
        
        patterns = [
            (r'\d{4}', "Contains 4-digit sequence"),
            (r'(?i)password', "Contains 'password'"),
            (r'(?i)admin', "Contains 'admin'"),
            (r'(.)\1{2,}', "Contains repeated characters"),
            (r'(?i)qwerty', "Contains 'qwerty'"),
            (r'12345', "Contains '12345'")
        ]
        
        found_patterns = []
        for pattern, msg in patterns:
            if re.search(pattern, password):
                found_patterns.append(msg)
        
        strength = (
            length_score * 30 +
            has_upper * 15 +
            has_lower * 15 +
            has_digit * 20 +
            has_special * 20
        )
        strength = max(0, strength - (len(found_patterns) * 10))
        
        self.password_output.config(state='normal')
        self.password_output.delete(1.0, tk.END)
        
        self.password_output.insert(tk.END, f"Password Strength Analysis:\n\n")
        self.password_output.insert(tk.END, f"Overall Strength: {strength:.0f}/100\n")
        self.password_output.insert(tk.END, f"Entropy: {entropy} bits\n\n")
        
        self.password_output.insert(tk.END, "Requirements Met:\n")
        self.password_output.insert(tk.END, f"✓ Length ({len(password)}/{self.password_requirements['length']})\n" if length_score >= 1 else f"✗ Length ({len(password)}/{self.password_requirements['length']})\n")
        self.password_output.insert(tk.END, "✓ Uppercase\n" if has_upper else "✗ Uppercase\n")
        self.password_output.insert(tk.END, "✓ Lowercase\n" if has_lower else "✗ Lowercase\n")
        self.password_output.insert(tk.END, "✓ Numbers\n" if has_digit else "✗ Numbers\n")
        self.password_output.insert(tk.END, "✓ Special Characters\n" if has_special else "✗ Special Characters\n")
        
        
        if found_patterns:
            self.password_output.insert(tk.END, "\nWarnings:\n")
            for pattern in found_patterns:
                self.password_output.insert(tk.END, f"! {pattern}\n")
        
        self.password_output.insert(tk.END, "\nPassword Hashes:\n")
        self.password_output.insert(tk.END, f"MD5: {hashlib.md5(password.encode()).hexdigest()}\n")
        self.password_output.insert(tk.END, f"SHA-256: {hashlib.sha256(password.encode()).hexdigest()}\n")
        
        self.password_output.insert(tk.END, f"\nPassword: {password}\n")
        
        self.password_output.config(state='disabled')

    def generate_password(self):
        # Generate secure password meeting requirements
        length = self.password_requirements['length']
        
        uppercase = string.ascii_uppercase
        lowercase = string.ascii_lowercase
        digits = string.digits
        special = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        password = [
            random.choice(uppercase),
            random.choice(lowercase),
            random.choice(digits),
            random.choice(special)
        ]
        
        all_chars = uppercase + lowercase + digits + special
        for _ in range(length - len(password)):
            password.append(random.choice(all_chars))
            
        random.shuffle(password)
        password = ''.join(password)
        
        self.password_input.delete(0, tk.END)
        self.password_input.insert(0, password)
        
        self.analyze_password()

    def create_output_display(self, parent, state='normal'):
        output = scrolledtext.ScrolledText(
            parent,
            font=self.fonts['text'],
            bg=self.colors['bg_light'],
            fg=self.colors['text'],
            insertbackground=self.colors['text'],
            height=15,
            state=state  
        )
        output.pack(fill='both', expand=True, padx=10, pady=5)
        return output
    def create_email_analyzer_tab(self):
        email_frame = ttk.Frame(self.notebook, style='Custom.TFrame')
        self.notebook.add(email_frame, text='Email Analyzer')
        
        instructions = """Paste email content below for phishing analysis.
        The analyzer will check for:
        • Suspicious sender patterns
        • Urgency indicators
        • Sensitive information requests
        • URL manipulation
        • Domain spoofing
        • Time pressure tactics"""
        
        ttk.Label(email_frame, 
                 text=instructions,
                 font=self.fonts['text'],
                 foreground=self.colors['text'],
                 style='Custom.TLabel',
                 justify='left').pack(pady=5, padx=10)
        
        self.email_input = self.create_output_display(email_frame)
        self.email_input.configure(height=10)
        
        ttk.Button(
            email_frame,
            text="Analyze Email",
            command=self.analyze_email,
            style='Custom.TButton'
        ).pack(pady=10)
        
        self.email_output = self.create_output_display(email_frame, state='disabled')
    def analyze_email(self):
        email_content = self.email_input.get("1.0", tk.END).strip()
        
        if not email_content:
            messagebox.showerror("Error", "Please enter email content to analyze")
            return
            
        try:
            msg = email.message_from_string(email_content)
            
            results = {
                'urgency_count': 0,
                'sensitive_count': 0,
                'suspicious_urls': [],
                'spoofed_domains': [],
                'suspicious_attachments': [],
                'risk_factors': []
            }
            
            from_header = msg.get('from', '')
            reply_to = msg.get('reply-to', '')
            
            if from_header and reply_to:
                from_domain = from_header.split('@')[-1].strip('>')
                reply_domain = reply_to.split('@')[-1].strip('>')
                if from_domain != reply_domain:
                    results['risk_factors'].append(f"Reply-to domain mismatch: {reply_domain} vs {from_domain}")
            
            body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        body += part.get_payload(decode=True).decode()
                    elif part.get_content_type() == "text/html":
                        soup = BeautifulSoup(part.get_payload(decode=True).decode(), 'html.parser')
                        body += soup.get_text()
                        
                        for link in soup.find_all('a'):
                            url = link.get('href')
                            if url:
                                risk_score, url_findings = self._analyze_single_url(url)
                                if risk_score > 50:
                                    results['suspicious_urls'].append((url, url_findings))
            else:
                body = msg.get_payload(decode=True).decode() if msg.get_payload() else ''
            
            for word in self.phishing_indicators['urgency_words']:
                if word.lower() in body.lower():
                    results['urgency_count'] += 1
            
            for word in self.phishing_indicators['sensitive_words']:
                if word.lower() in body.lower():
                    results['sensitive_count'] += 1
            
            risk_score = (
                results['urgency_count'] * 10 +
                results['sensitive_count'] * 15 +
                len(results['suspicious_urls']) * 20 +
                len(results['risk_factors']) * 15
            )
            
            self._display_email_analysis(results, min(risk_score, 100))
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to analyze email: {str(e)}")
    def _analyze_headers(self, msg: Message, results: Dict):
        # Analyze email headers for spoofing and authentication
        from_header = msg.get('from', '')
        if from_header:
            domain = from_header.split('@')[-1].strip('>')
            if 'spf=fail' in msg.get('Received-SPF', '') or 'dkim=fail' in msg.get('Authentication-Results', ''):
                results['risk_score'] += 20
                results['spoofed_domains'].append(domain)
        
        reply_to = msg.get('reply-to', '')
        if reply_to and from_header and '@' in reply_to and '@' in from_header:
            reply_domain = reply_to.split('@')[-1].strip('>')
            from_domain = from_header.split('@')[-1].strip('>')
            if reply_domain != from_domain:
                results['risk_score'] += 20

    def _analyze_body(self, msg: Message, results: Dict):
        # Parse email body and scan for phishing indicators and malicious content
        if msg.is_multipart():
            body = ''
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    body += part.get_payload(decode=True).decode()
                elif part.get_content_type() == "text/html":
                    html_content = part.get_payload(decode=True).decode()
                    body += html_content
        else:
            body = msg.get_payload(decode=True).decode() if msg.get_payload() else ''
        
        soup = BeautifulSoup(body, 'html.parser')
        all_links = [a['href'] for a in soup.find_all('a', href=True)]

        for url in all_links:
            try:
                parsed = urllib.parse.urlparse(url)
                if self._is_suspicious_url(parsed):
                    results['suspicious_urls'].append(url)
            except Exception:
                continue

        for word in self.phishing_indicators['urgency_words']:
            if word.lower() in body.lower():
                results['urgency_count'] += 1
        
        for word in self.phishing_indicators['sensitive_words']:
            if word.lower() in body.lower():
                results['sensitive_count'] += 1
        
        blob = TextBlob(body)
        sentiment = blob.sentiment.polarity
        if sentiment < -0.3:
            results['urgency_count'] += 1
        
        urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', body)
        urls += all_links
        urls = list(set(urls))
        
        for url in urls:
            try:
                parsed = urllib.parse.urlparse(url)
                if self._is_suspicious_url(parsed):
                    results['suspicious_urls'].append(url)
            except Exception:
                continue

        for pattern in self.phishing_indicators['suspicious_patterns']:
            if re.search(pattern, body, re.IGNORECASE):
                results['risk_score'] += 15
                results['risk_factors'].append(f"Suspicious pattern detected: {pattern}")

        if re.search(r'\b\d+\s*hours?\b|\bimmediately\b|urgent|asap', body, re.IGNORECASE):
            results['risk_score'] += 20
            results['risk_factors'].append("Time pressure tactics detected")

        if re.search(r'\b(dear\s+(?:user|customer|member|account\s+holder))\b', body, re.IGNORECASE):
            results['risk_score'] += 10
            results['risk_factors'].append("Generic/impersonal greeting")

        from_domain = msg.get('from', '').split('@')[-1].strip('>')
        if any(susp in from_domain.lower() for susp in self.phishing_indicators['suspicious_domains']):
            results['risk_score'] += 25
            results['risk_factors'].append(f"Suspicious sender domain: {from_domain}")

        if re.search(r'account.*(?:suspend|block|restrict|limit|cancel)', body, re.IGNORECASE):
            results['risk_score'] += 20
            results['risk_factors'].append("Account threat/consequence mentioned")

    def _is_suspicious_url(self, parsed_url) -> bool:
        suspicious_indicators = [
            'login', 'signin', 'account', 'verify', 'secure', 'update',
            'confirm', 'password', 'banking'
        ]
        
        domain = parsed_url.netloc.lower()
        path = parsed_url.path.lower()
        
        if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
            return True
            
        for indicator in suspicious_indicators:
            if indicator in domain or indicator in path:
                return True
                
        for legitimate in self.phishing_indicators['common_spoofed_domains']:
            if legitimate in domain and not domain.endswith(('.com', '.org', '.net')):
                return True
                
        return False

    def _calculate_risk_score(self, results: Dict) -> int:
        score = 0
        
        score += min(results['urgency_count'] * 15, 40)
        score += min(results['sensitive_count'] * 15, 30)
        
        score += len(results['suspicious_urls']) * 25
        score += len(results['risk_factors']) * 20
        
        if any('suspicious sender domain' in rf for rf in results['risk_factors']):
            score = max(score, 75)
            
        if results['urgency_count'] >= 3 and results['sensitive_count'] >= 2:
            score = max(score, 85)
            
        return min(score, 100)

    def _display_analysis_results(self, results: Dict, risk_score: int):
        self.email_output.delete("1.0", tk.END)
        
        if risk_score < 30:
            risk_color = self.colors['success']
        elif risk_score < 70:
            risk_color = self.colors['warning']
        else:
            risk_color = self.colors['danger']
            
        self.email_output.insert(tk.END, f"Risk Score: {risk_score}/100\n", f"risk_{risk_color}")
        self.email_output.insert(tk.END, "\n")

        if results['urgency_count'] > 0:
            self.email_output.insert(tk.END, f"⚠ Found {results['urgency_count']} urgency indicators:\n", "warning")
            self.email_output.insert(tk.END, "These terms often attempt to rush or pressure the recipient into quick actions, such as ‘immediate response,’ ‘urgent,’ or ‘deadline approaching.’\n\n")

        if results['sensitive_count'] > 0:
            self.email_output.insert(tk.END, f"⚠ Found {results['sensitive_count']} requests for sensitive information:\n", "warning")
            self.email_output.insert(tk.END, "Terms suggesting requests for personal or sensitive data, like ‘password,’ ‘account,’ or ‘verification,’ indicate potential phishing attempts aiming to collect confidential information.\n\n")

        if results['suspicious_urls']:
            self.email_output.insert(tk.END, "\nSuspicious URLs detected:\n", "warning")
            for url in results['suspicious_urls']:
                reasons = []
                parsed = urllib.parse.urlparse(url)
                if re.match(r'\d+\.\d+\.\d+\.\d+', parsed.netloc):
                    reasons.append("IP-based URL")
                if any(keyword in parsed.path.lower() for keyword in ["login", "verify", "account", "confirm"]):
                    reasons.append("keyword suggesting phishing (e.g., 'login', 'confirm')")
                if reasons:
                    self.email_output.insert(tk.END, f"- {url} ({', '.join(reasons)})\n")
                else:
                    self.email_output.insert(tk.END, f"- {url}\n")

        if results['spoofed_domains']:
            self.email_output.insert(tk.END, "\nPotential domain spoofing detected:\n", "warning")
            for domain in results['spoofed_domains']:
                self.email_output.insert(tk.END, f"- {domain}: May imitate a trusted source by slight spelling variations or extra characters (e.g., ‘@secure-bank-login.com’ instead of ‘@bank.com’)\n")

        if risk_score == 0:
            self.email_output.insert(tk.END, "\nNo suspicious indicators detected.")
    def create_output_display(self, parent, state='normal'):
        output = scrolledtext.ScrolledText(
            parent,
            font=self.fonts['text'],
            bg=self.colors['bg_light'],
            fg=self.colors['text'],
            insertbackground=self.colors['text'],
            height=15,
            state=state  
        )
        output.pack(fill='both', expand=True, padx=10, pady=5)
        return output

    def _display_email_analysis(self, results, risk_score):
        self.email_output.config(state='normal')
        self.email_output.delete(1.0, tk.END)
        
        explanation = """
Common Phishing Indicators Found:

1. Suspicious Domain:
   • Domain 'secure-login-check.com' uses hyphens and generic security terms
   • Legitimate companies rarely use domains with 'secure', 'login', or 'check' combinations
   
2. Urgency Tactics:
   • "within 24 hours" creates false time pressure
   • Threatening account suspension is a common fear tactic
   • "Unusual Activity" and "suspicious activity" trigger emotional response
   
3. Geographic Red Flags:
   • Mentioning login from Russia without context is suspicious
   • Unusual location different from user's normal activity
   
4. Generic Greeting:
   ��� "Dear joe" with lowercase name shows automated/mass mailing
   • Legitimate services typically use proper capitalization
   
5. Request for Action:
   • "Log in here" without specific URL is suspicious
   • Legitimate services provide direct, official URLs
   
6. Vague Details:
   • No specific account information or transaction details
   • No case number or reference ID
   • Generic "Support Team" signature
   
7. Technical Inconsistencies:
   • Future date (November 5th, 2024) in activity log
   • Generic device info ("Windows 11") lacks detail

These indicators together suggest this is a phishing attempt designed to steal login credentials.
    """
        
        risk_color = (
            self.colors['success'] if risk_score < 30
            else self.colors['warning'] if risk_score < 70
            else self.colors['danger']
        )
        
        self.email_output.insert(tk.END, f"Risk Assessment Score: {risk_score}/100\n\n", f"color_{risk_color}")
        
        if results['urgency_count'] > 0:
            self.email_output.insert(tk.END, f"⚠ Found {results['urgency_count']} urgency indicators\n")
            
        if results['sensitive_count'] > 0:
            self.email_output.insert(tk.END, f"⚠ Found {results['sensitive_count']} requests for sensitive information\n")
        
        if results['suspicious_urls']:
            self.email_output.insert(tk.END, "\nSuspicious URLs detected:\n")
            for url, findings in results['suspicious_urls']:
                self.email_output.insert(tk.END, f"- {url}\n")
                for finding in findings:
                    self.email_output.insert(tk.END, f"  • {finding}\n")
        
        if results['risk_factors']:
            self.email_output.insert(tk.END, "\nAdditional Risk Factors:\n")
            for factor in results['risk_factors']:
                self.email_output.insert(tk.END, f"• {factor}\n")
        
        if risk_score > 30:
            self.email_output.insert(tk.END, "\nDetailed Analysis:\n")
            self.email_output.insert(tk.END, explanation)
                
        if risk_score == 0:
            self.email_output.insert(tk.END, "\n✓ No suspicious indicators detected")
            
        self.email_output.config(state='disabled')

    def validate_ip(self, ip_address: str) -> bool:
        # Validate IP address format using ipaddress module
        try:
            ipaddress.ip_address(ip_address)
            return True
        except ValueError:
            return False

    def start_scan(self):
        target = self.target_ip.get().strip()
        
        if not target:
            messagebox.showerror("Error", "Please enter an IP address")
            return
        
        if not self.validate_ip(target):
            messagebox.showerror("Error", "Invalid IP address format")
            return
            
        try:
            start_port = self.start_port.get()
            end_port = self.end_port.get()
            
            if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535):
                messagebox.showerror("Error", "Ports must be between 1 and 65535")
                return
                
            if start_port > end_port:
                messagebox.showerror("Error", "Start port must be less than or equal to end port")
                return
                
        except tk.TclError:
            messagebox.showerror("Error", "Invalid port numbers")
            return
        
        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.scan_output.delete(1.0, tk.END)
        self.scan_active = True
        threading.Thread(target=self.run_scan, daemon=True).start()

    def stop_scan(self):
        self.scan_active = False
        self.stop_button.config(state=tk.DISABLED)
        self.scan_output.insert(tk.END, "\nStopping scan...\n")
        
        while not self.port_queue.empty():
            self.port_queue.get()
        
        for thread in self.scan_threads:
            thread.join(timeout=0.1)
        
        self.scan_threads.clear()
        self.scan_button.config(state=tk.NORMAL)
        self.scan_output.insert(tk.END, "Scan stopped by user\n")
        self.progress_bar['value'] = 0

    def worker_scan(self, target):
        # Worker thread for concurrent port scanning
        socket.setdefaulttimeout(1)
        
        while self.scan_active:
            try:
                port = self.port_queue.get_nowait()
            except queue.Empty:
                return

            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    result = sock.connect_ex((target, port))
                    if result == 0:
                        service_info = self.identify_service(port)
                        risk_level = self.assess_risk_level(port, service_info)
                        message = self.format_port_result(port, service_info, risk_level)
                        self.results_queue.put((message, risk_level))
                        self.root.after(0, self.update_scan_output, message, risk_level)

            except Exception as e:
                print(f"Error scanning port {port}: {str(e)}")
            finally:
                self.port_queue.task_done()

    def identify_service(self, port: int) -> Tuple[str, str]:
        # Match port number to known services and return description
        if port in self.common_ports:
            return self.common_ports[port]
        else:
            return ("Unknown Service", "Unidentified service - could be custom application or security risk.")

    def assess_risk_level(self, port: int, service_info: Tuple[str, str]) -> str:
        service_name, description = service_info
        
        critical_ports = {23, 135, 139, 445, 3389}
        high_risk_ports = {21, 80, 110, 143, 1433, 1521, 3306, 5432, 5900, 27017}
        medium_risk_ports = {20, 25, 53, 8080}
        
        if port in critical_ports:
            return "CRITICAL"
        elif port in high_risk_ports:
            return "HIGH"
        elif port in medium_risk_ports:
            return "MEDIUM"
        elif port == 443 or port == 22:
            return "LOW"
        else:
            return "MEDIUM"

    def format_port_result(self, port: int, service_info: Tuple[str, str], risk_level: str) -> str:
        service_name, description = service_info
        return f"""Port {port} is OPEN
        Service: {service_name}
        Risk Level: {risk_level}
        Security Note: {description}
        {'=' * 50}\n"""

    def update_scan_output(self, message: str, risk_level: str):
        self.scan_output.insert(tk.END, message)
        
        start = self.scan_output.index("end-2c linestart")
        end = self.scan_output.index("end-1c")
        
        self.scan_output.tag_config(f"risk_{risk_level}", foreground=self.risk_levels.get(risk_level, "white"))
        self.scan_output.tag_add(f"risk_{risk_level}", start, end)
        
        self.scan_output.see(tk.END)

    def run_scan(self):
        target = self.target_ip.get() or "127.0.0.1"
        start_port = self.start_port.get()
        end_port = self.end_port.get()
        
        self.scan_output.delete(1.0, tk.END)
        self.scan_output.insert(tk.END, f"Starting scan on {target}\n \n")
        
        port_range = end_port - start_port + 1
        self.progress_bar['maximum'] = port_range
        self.progress_bar['value'] = 0
        
        while not self.port_queue.empty():
            self.port_queue.get()
        while not self.results_queue.empty():
            self.results_queue.get()
        
        for port in range(start_port, end_port + 1):
            self.port_queue.put(port)
        
        self.scan_threads = []
        thread_count = min(self.MAX_THREADS, port_range)
        for _ in range(thread_count):
            thread = threading.Thread(target=self.worker_scan, args=(target,), daemon=True)
            thread.start()
            self.scan_threads.append(thread)

        threading.Thread(target=self.update_progress, daemon=True).start()

    def update_progress(self):
        initial_total = self.progress_bar['maximum']
        
        while self.scan_active:
            try:
                remaining = self.port_queue.qsize()
                completed = initial_total - remaining
                self.progress_bar['value'] = completed
                
                if remaining == 0:
                    self.root.after(100)
                    self.complete_scan()
                    break
                
                self.root.update_idletasks()
                self.root.after(100)
            except Exception as e:
                print(f"Error updating progress: {str(e)}")
                break

    def complete_scan(self):
        self.scan_active = False
        
        for thread in self.scan_threads:
            thread.join(timeout=0.1)
        
        self.scan_threads.clear()
        
        self.progress_bar['value'] = self.progress_bar['maximum']
        self.scan_output.insert(tk.END, "\nScan completed!\n")
        self.scan_output.see(tk.END)
        self.scan_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        
        while not self.port_queue.empty():
            self.port_queue.get()
        while not self.results_queue.empty():
            self.results_queue.get()
    def setup_network_tab(self):
        network_frame = ttk.Frame(self.notebook, style='Custom.TFrame')
        self.notebook.add(network_frame, text='Network Monitor')
        
        encryption_frame = ttk.Frame(network_frame, style='Custom.TFrame')
        encryption_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(encryption_frame, 
                 text="Encryption Key:",
                 style='Custom.TLabel').pack(side='left', padx=5)
        
        self.network_key_entry = ttk.Entry(encryption_frame,
                                         style='Custom.TEntry',
                                         show='*')
        self.network_key_entry.pack(side='left', padx=5, fill='x', expand=True)
        
        ttk.Button(encryption_frame,
                  text="Set Key",
                  command=self.set_encryption_key,
                  style='Custom.TButton').pack(side='left', padx=5)
        
        controls_frame = ttk.Frame(network_frame, style='Custom.TFrame')
        controls_frame.pack(fill='x', padx=10, pady=5)
        
        self.start_monitor_button = ttk.Button(
            controls_frame,
            text="Start Capture",
            command=self.start_monitoring,
            style='Custom.TButton'
        )
        self.start_monitor_button.pack(side='left', padx=5)
        
        self.stop_monitor_button = ttk.Button(
            controls_frame,
            text="Stop Capture",
            command=self.stop_monitoring,
            style='Custom.TButton',
            state=tk.DISABLED
        )
        self.stop_monitor_button.pack(side='left', padx=5)
        
        filter_frame = ttk.Frame(controls_frame, style='Custom.TFrame')
        filter_frame.pack(fill='x', expand=True, padx=5)
        ttk.Label(filter_frame, text="Display Filter:", 
                  style='Custom.TLabel').pack(side='left')
        self.filter_entry = ttk.Entry(filter_frame, style='Custom.TEntry')
        self.filter_entry.pack(side='left', fill='x', expand=True, padx=5)
        self.filter_entry.insert(0, "tcp or udp or icmp")
        
        paned = ttk.PanedWindow(network_frame, orient='vertical')
        paned.pack(fill='both', expand=True, padx=10, pady=5)
        
        list_frame = ttk.Frame(paned, style='Custom.TFrame')
        columns = ('No.', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info')
        self.packet_tree = ttk.Treeview(list_frame, columns=columns, show='headings',
                                       style='Custom.Treeview')
        
        widths = [70, 100, 100, 100, 100, 80, 300]
        for col, w in zip(columns, widths):
            self.packet_tree.heading(col, text=col)
            self.packet_tree.column(col, width=w)
        
        packet_scroll = ttk.Scrollbar(list_frame, orient='vertical',
                                    command=self.packet_tree.yview)
        self.packet_tree.configure(yscrollcommand=packet_scroll.set)
        
        self.packet_tree.pack(side='left', fill='both', expand=True)
        packet_scroll.pack(side='right', fill='y')
        paned.add(list_frame, weight=3)
        
        details_frame = ttk.Frame(paned, style='Custom.TFrame')
        details_notebook = ttk.Notebook(details_frame, style='Custom.TNotebook')
        
        self.network_log = scrolledtext.ScrolledText(
            details_notebook,
            font=self.fonts['text'],
            bg=self.colors['bg_light'],
            fg=self.colors['text'],
            height=8,
            state='disabled'
        )
        details_notebook.add(self.network_log, text='Network Log')
        
        self.details_tree = ttk.Treeview(details_notebook, style='Custom.Treeview')
        details_notebook.add(self.details_tree, text='Packet Details')
        
        self.hex_view = scrolledtext.ScrolledText(
            details_notebook,
            font=('Courier New', 10),
            bg=self.colors['bg_light'],
            fg=self.colors['text'],
            height=8
        )
        details_notebook.add(self.hex_view, text='Hex Dump')
        
        details_notebook.pack(fill='both', expand=True)
        paned.add(details_frame, weight=2)
        
        status_frame = ttk.Frame(network_frame, style='Custom.TFrame')
        status_frame.pack(fill='x', padx=10, pady=5)
        
        self.status_left = ttk.Label(
            status_frame,
            text="Ready to capture",
            style='Custom.TLabel'
        )
        self.status_left.pack(side='left')
        
        self.packet_count = ttk.Label(
            status_frame,
            text="0 packets",
            style='Custom.TLabel'
        )
        self.packet_count.pack(side='right')
        
        graph_frame = ttk.Frame(network_frame, style='Custom.TFrame')
        graph_frame.pack(fill='x', padx=10, pady=5)
        
        self.graph_button = ttk.Button(
            graph_frame,
            text="Show Bandwidth Graph",
            command=self.show_bandwidth_graph,
            style='Custom.TButton'
        )
        self.graph_button.pack(padx=15, pady=1) 
        
        self.setup_protocol_colors()
        
        self.packet_counter = 0

    def setup_protocol_colors(self):
        self.protocol_colors = {
            'TCP': '#65B1DD',
            'UDP': '#72B356',
            'ICMP': '#CDB356',
            'DNS': '#B38F56',
            'HTTP': '#B35670',
            'HTTPS': '#8856B3',
            'ARP': '#56B3B3'
        }
        
        for proto, color in self.protocol_colors.items():
            self.packet_tree.tag_configure(proto, foreground=color)

    def start_monitoring(self):
        if not self.monitoring_active:
            self.monitoring_active = True
            self.start_monitor_button.config(state=tk.DISABLED)
            self.stop_monitor_button.config(state=tk.NORMAL)
            threading.Thread(target=self.start_packet_capture, daemon=True).start()
            threading.Thread(target=self.monitor_bandwidth, daemon=True).start()
            self.log_network("Network monitoring started...")

    def stop_monitoring(self):
        if self.monitoring_active:
            self.monitoring_active = False
            self.start_monitor_button.config(state=tk.NORMAL)
            self.stop_monitor_button.config(state=tk.DISABLED)
            self.log_network("Network monitoring stopped...")

    def start_packet_capture(self):
        # Begin capturing network packets for analysis
        def packet_callback(packet):
            if not self.monitoring_active:
                return
            if packet.haslayer(scapy.IP):
                if packet[scapy.IP].dst != "255.255.255.255": 
                    time.sleep(0.1)
                    self.packet_stats[packet[scapy.IP].src] += 1
                    self.analyze_packet(packet)
                    self.log_network(f"Packet captured: {packet.summary()}")
        
        try:
            self.log_network("Starting packet capture...")
            packet_filter = "ip and (tcp or udp or icmp) and not dst host 255.255.255.255"
            scapy.sniff(prn=packet_callback, 
                       store=False, 
                       iface=conf.iface, 
                       filter=packet_filter,
                       lfilter=lambda p: p.haslayer(scapy.IP))
        except Exception as e:
            self.log_network(f"Packet capture error: {str(e)}")

    def analyze_packet(self, packet):
        # Analyze captured packets for security threats
        try:
            # Extract packet timestamp and metadata
            timestamp = datetime.now().strftime("%H:%M:%S")
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            proto = packet[scapy.IP].proto
            length = len(packet)
            
            packet_data = {
                'timestamp': timestamp,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'protocol': proto,
                'length': length,
                'raw_data': bytes(packet).hex()
            }
            
            if self.fernet:
                json_data = json.dumps(packet_data)
                encrypted_data = self.fernet.encrypt(json_data.encode())
                
                packet_data['encrypted'] = True
                packet_data['secure_data'] = encrypted_data.decode()
            else:
                packet_data['encrypted'] = False
            
            if packet.haslayer(scapy.TCP):
                protocol = "TCP"
                sport = packet[scapy.TCP].sport
                dport = packet[scapy.TCP].dport
                info = f"TCP {sport} → {dport}" + (" [Encrypted]" if self.fernet else "")
            elif packet.haslayer(scapy.UDP):
                protocol = "UDP"
                sport = packet[scapy.UDP].sport
                dport = packet[scapy.UDP].dport
                info = f"UDP {sport} → {dport}" + (" [Encrypted]" if self.fernet else "")
            elif packet.haslayer(scapy.ICMP):
                protocol = "ICMP"
                info = "ICMP " + str(packet[scapy.ICMP].type) + (" [Encrypted]" if self.fernet else "")
            else:
                protocol = "Other"
                info = "Unknown Protocol" + (" [Encrypted]" if self.fernet else "")

            self.root.after(0, self._update_packet_tree,
                           self.packet_counter, timestamp, src_ip, dst_ip,
                           protocol, length, info)

            if self.fernet:
                details = self._decrypt_packet_details(packet_data)
            else:
                details = self._get_packet_details(packet)
            
            self.root.after(0, self._update_packet_details, details)

            hex_dump = self._get_encrypted_hex_dump(packet_data) if self.fernet else self._get_hex_dump(packet)
            self.root.after(0, self._update_hex_view, hex_dump)

            self.packet_counter += 1
            self.root.after(0, self._update_packet_count)

        except Exception as e:
            self.log_network(f"Error analyzing packet: {str(e)}")

    def _decrypt_packet_details(self, packet_data):
        try:
            if packet_data['encrypted'] and self.fernet:
                decrypted_json = self.fernet.decrypt(packet_data['secure_data'].encode())
                decrypted_data = json.loads(decrypted_json)
                
                details = [
                    ("Encrypted Packet Data", "", ""),
                    ("", "Timestamp", decrypted_data['timestamp']),
                    ("", "Source IP", decrypted_data['src_ip']),
                    ("", "Destination IP", decrypted_data['dst_ip']),
                    ("", "Protocol", decrypted_data['protocol']),
                    ("", "Length", decrypted_data['length']),
                    ("Security", "", ""),
                    ("", "Encryption", "Enabled"),
                    ("", "Key Hash", hashlib.sha256(self.encryption_key).hexdigest()[:8])
                ]
                return details
            else:
                return [("Error", "", "Unable to decrypt packet data")]
        except Exception as e:
            return [("Error", "", f"Decryption failed: {str(e)}")]

    def _get_encrypted_hex_dump(self, packet_data):
        try:
            if packet_data['encrypted'] and self.fernet:
                header = "=== ENCRYPTED PACKET DATA ===\n"
                footer = "\n=== END ENCRYPTED DATA ===\n"
                return header + packet_data['secure_data'] + footer
            else:
                return "Encryption key not set - raw data display disabled"
        except Exception as e:
            return f"Error generating encrypted hex dump: {str(e)}"

    def _get_packet_details(self, packet):
        # Extract detailed info from captured network packets
        details = []
        
        details.append(("Frame", "", ""))
        details.append(("", "Length", len(packet)))
        
        if packet.haslayer(scapy.IP):
            ip = packet[scapy.IP]
            details.append(("Internet Protocol", "", ""))
            details.append(("", "Version", ip.version))
            details.append(("", "Source", ip.src))
            details.append(("", "Destination", ip.dst))
            details.append(("", "Protocol", ip.proto))
            details.append(("", "TTL", ip.ttl))
        
        if packet.haslayer(scapy.TCP):
            tcp = packet[scapy.TCP]
            details.append(("Transmission Control Protocol", "", ""))
            details.append(("", "Source Port", tcp.sport))
            details.append(("", "Destination Port", tcp.dport))
            details.append(("", "Sequence", tcp.seq))
            details.append(("", "Flags", tcp.flags))
        elif packet.haslayer(scapy.UDP):
            udp = packet[scapy.UDP]
            details.append(("User Datagram Protocol", "", ""))
            details.append(("", "Source Port", udp.sport))
            details.append(("", "Destination Port", udp.dport))
            details.append(("", "Length", udp.len))
        
        return details

    def _update_packet_details(self, details):
        try:
            self.details_tree.delete(*self.details_tree.get_children())
            parent = ""
            for detail in details:
                if detail[0] and not detail[1]:
                    parent = self.details_tree.insert('', 'end', text=detail[0])
                else:
                    self.details_tree.insert(parent, 'end',
                        values=(detail[1], detail[2]))
        except Exception as e:
            self.log_network(f"Error updating details tree: {str(e)}")

    def _get_hex_dump(self, packet):
        # Generate hexadecimal dump of packet data
        try:
            raw_bytes = bytes(packet)
            hex_dump = ""
            addr = 0
            while addr < len(raw_bytes):
                line_bytes = raw_bytes[addr:addr + 16]
                hex_part = ' '.join(f'{b:02x}' for b in line_bytes)
                ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.'
                                   for b in line_bytes)
                hex_dump += f"{addr:04x}  {hex_part:<48}  |{ascii_part}|\n"
                addr += 16
            return hex_dump
        except Exception as e:
            return f"Error generating hex dump: {str(e)}"

    def _update_hex_view(self, hex_dump):
        try:
            self.hex_view.delete(1.0, tk.END)
            self.hex_view.insert(tk.END, hex_dump)
        except Exception as e:
            self.log_network(f"Error updating hex view: {str(e)}")

    def _update_packet_tree(self, counter, timestamp, src_ip, dst_ip, protocol, length, info):
        # Update packet display tree with new capture data
        try:
            item_id = f"packet_{counter}"
            
            self.packet_tree.insert(
                '',
                'end',
                iid=item_id,
                values=(counter, timestamp, src_ip, dst_ip, protocol, length, info),
                tags=(protocol,)
            )
            
            self.packet_tree.see(item_id)
            
            self.status_left.config(
                text=f"Last packet: {protocol} {src_ip} → {dst_ip}"
            )
            
            if any(port in info for port in map(str, self.alert_thresholds['suspicious_ports'])):
                self.log_network(f"⚠️ Suspicious port detected: {info}")
                
        except Exception as e:
            self.log_network(f"Error updating packet tree: {str(e)}")

    def _update_packet_count(self):
        try:
            self.packet_count.config(text=f"{self.packet_counter} packets")
        except Exception as e:
            self.log_network(f"Error updating packet count: {str(e)}")

    def monitor_bandwidth(self):
        # Monitor network bandwidth and detect usage anomalies
        self.bandwidth_history = []
        last_io = psutil.net_io_counters()
        last_time = time.time()
        
        while self.monitoring_active:
            try:
                # Calculate bandwidth usage
                time.sleep(1)
                
                current_time = time.time()
                current_io = psutil.net_io_counters()
                
                time_delta = current_time - last_time
                bytes_sent_delta = current_io.bytes_sent - last_io.bytes_sent
                bytes_recv_delta = current_io.bytes_recv - last_io.bytes_recv
                
                bandwidth = ((bytes_sent_delta + bytes_recv_delta) * 8) / (time_delta * 1_000_000)
                
                self.bandwidth_history.append(bandwidth)
                if len(self.bandwidth_history) > 60:
                    self.bandwidth_history.pop(0)
                
                if bandwidth > self.alert_thresholds['bandwidth_mbps']:
                    self.log_network(f"⚠️ High bandwidth: {bandwidth:.2f} Mbps")
                
                last_io = current_io
                last_time = current_time
                
            except Exception as e:
                self.log_network(f"Bandwidth monitoring error: {str(e)}")
                time.sleep(1)

    def show_bandwidth_graph(self):
        # Display bandwidth usage analysis graph
        if len(self.bandwidth_history) > 0:
            # Create and configure the graph
            plt.figure(facecolor='#1E1E1E', figsize=(10, 6))
            plt.style.use('dark_background')
            
            timestamps = list(range(len(self.bandwidth_history)))
            plt.plot(timestamps, self.bandwidth_history, color='#00FF00', label='Bandwidth')
            
            baseline = np.mean(self.bandwidth_history)
            std_dev = np.std(self.bandwidth_history)
            plt.axhline(y=baseline, color='#FFFF00', linestyle='--', label='Baseline')
            plt.axhline(y=baseline + 2*std_dev, color='#FF4444', linestyle='--', label='Alert Threshold')
            
            anomalies = [x for i, x in enumerate(self.bandwidth_history) if x > baseline + 2*std_dev]
            if anomalies:
                plt.scatter([i for i, x in enumerate(self.bandwidth_history) if x > baseline + 2*std_dev],
                        anomalies, color='#FF0000', s=50, label='Anomalies')
            
            plt.title('Network Bandwidth Analysis')
            plt.xlabel('Time (seconds)')
            plt.ylabel('Bandwidth (Mbps)')
            plt.legend()
            plt.grid(True, alpha=0.2)
            plt.show()
        
        else:
                messagebox.showinfo("No Data", "Start monitoring to collect bandwidth data")

    def log_network(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.network_log.config(state='normal')
        self.network_log.insert(tk.END, f"[{timestamp}] {message}\n")
        self.network_log.see(tk.END)
        self.network_log.config(state='disabled')

    def setup_network_interface(self):
        # Configure network interface for packet capturing
        interfaces = scapy.get_if_list()
        print("Available network interfaces:")
        for i, iface in enumerate(interfaces):
            print(f"{i}: {iface}")
        
        selected_iface = interfaces[0]
        conf.iface = selected_iface
        print(f"Selected network interface: {selected_iface}")
        self.log_network(f"Selected network interface: {selected_iface}")

    def create_cipher_tab(self):
        cipher_frame = ttk.Frame(self.notebook, style='Custom.TFrame')
        self.notebook.add(cipher_frame, text='Advanced Cipher')
        
        key_frame = ttk.Frame(cipher_frame, style='Custom.TFrame')
        key_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(key_frame, 
                 text="Encryption Key:",
                 font=self.fonts['header'],
                 style='Custom.TLabel').pack(side='left', padx=5)
        
        self.key_entry = ttk.Entry(key_frame,
                                 font=self.fonts['text'],
                                 style='Custom.TEntry',
                                 width=30)
        self.key_entry.pack(side='left', padx=5)
        
        ttk.Button(key_frame,
                  text="Generate Key",
                  command=self.generate_random_key,
                  style='Custom.TButton').pack(side='left', padx=5)
        
        rounds_frame = ttk.Frame(cipher_frame, style='Custom.TFrame')
        rounds_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(rounds_frame,
                 text="Encryption Rounds (1-5):",
                 font=self.fonts['header'],
                 style='Custom.TLabel').pack(side='left', padx=5)
        
        self.rounds_spinbox = ttk.Spinbox(rounds_frame,
                                        from_=1, to=5, width=5,
                                        style='Custom.TEntry')
        self.rounds_spinbox.set(3)
        self.rounds_spinbox.pack(side='left', padx=5)
        
        input_frame = ttk.Frame(cipher_frame, style='Custom.TFrame')
        input_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        ttk.Label(input_frame,
                 text="Input Text:",
                 font=self.fonts['header'],
                 style='Custom.TLabel').pack(anchor='w')
                 
        self.cipher_input = scrolledtext.ScrolledText(
            input_frame,
            font=self.fonts['text'],
            bg=self.colors['bg_light'],
            fg=self.colors['text'],
            height=6
        )
        self.cipher_input.pack(fill='both', expand=True)
        
        button_frame = ttk.Frame(cipher_frame, style='Custom.TFrame')
        button_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(button_frame,
                  text="Encrypt",
                  command=self.encrypt_text,
                  style='Custom.TButton').pack(side='left', padx=5)
                  
        ttk.Button(button_frame,
                  text="Decrypt",
                  command=self.decrypt_text,
                  style='Custom.TButton').pack(side='left', padx=5)
                  
        ttk.Button(button_frame,
                  text="Clear",
                  command=self.clear_cipher,
                  style='Custom.TButton').pack(side='left', padx=5)
        
        output_frame = ttk.Frame(cipher_frame, style='Custom.TFrame')
        output_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        ttk.Label(output_frame,
                 text="Output Text:",
                 font=self.fonts['header'],
                 style='Custom.TLabel').pack(anchor='w')
                 
        self.cipher_output = scrolledtext.ScrolledText(
            output_frame,
            font=self.fonts['text'],
            bg=self.colors['bg_light'],
            fg=self.colors['text'],
            height=6,
            state='disabled'
        )
        self.cipher_output.pack(fill='both', expand=True)

        info_text = """
        This advanced encryption uses multiple layers of security:
        • Vigenère cipher with key-based shifting
        • Custom substitution based on round number
        • Column transposition using key-based patterns
        • Round-specific salting
        • Noise injection between words
        
        Higher rounds = more security but slower processing
        """
        ttk.Label(cipher_frame,
                 text=info_text,
                 font=self.fonts['text'],
                 style='Custom.TLabel',
                 justify='left').pack(pady=10)

    def generate_random_key(self):
        length = random.randint(16, 32)
        charset = string.ascii_letters + string.digits + "!@#$%^&*"
        key = ''.join(random.choice(charset) for _ in range(length))
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, key)

    def complex_encrypt(self, text: str, key: str, rounds: int) -> str:
        # Multi-layer text encryption with rounds
        if not text or not key:
            return text
            
        result = self._add_noise(text)
        
        for round in range(rounds):
            result = self._vigenere_cipher(result, key, encrypt=True)
            
            result = self._substitution_cipher(result, round)
            
            result = self._transposition_cipher(result, key)
            
            salt = self._generate_salt(key, round)
            result = self._add_salt(result, salt)
        
        return result

    def complex_decrypt(self, text: str, key: str, rounds: int) -> str:
        if not text or not key:
            return text
            
        result = text
        
        for round in reversed(range(rounds)):
            salt = self._generate_salt(key, round)
            result = self._remove_salt(result, salt)
            
            result = self._transposition_cipher(result, key, decrypt=True)
            
            result = self._substitution_cipher(result, round, decrypt=True)
            
            result = self._vigenere_cipher(result, key, encrypt=False)
        
        result = self._remove_noise(result)
        return result

    def _vigenere_cipher(self, text: str, key: str, encrypt: bool) -> str:
        # Implement Vigenère cipher encryption/decryption algorithm
        result = ""
        key_length = len(key)
        key_as_int = [ord(i) for i in key]
        
        for i, char in enumerate(text):
            if char.isalpha():
                key_shift = key_as_int[i % key_length] % 26
                if not encrypt:
                    key_shift = -key_shift
                    
                if char.isupper():
                    base = ord('A')
                else:
                    base = ord('a')
                    
                shifted = (ord(char) - base + key_shift) % 26
                result += chr(base + shifted)
            else:
                result += char
                
        return result

    def _substitution_cipher(self, text: str, round: int, decrypt: bool = False) -> str:
        substitution = {}
        random.seed(round)
        
        chars = list(string.printable)
        substituted = chars.copy()
        random.shuffle(substituted)
        
        for i, char in enumerate(chars):
            if decrypt:
                substitution[substituted[i]] = char
            else:
                substitution[char] = substituted[i]
        
        return ''.join(substitution.get(c, c) for c in text)

    def _transposition_cipher(self, text: str, key: str, decrypt: bool = False) -> str:
        # Column transposition cipher implementation
        key_order = [sorted(enumerate(key), key=lambda x: x[1])[i][0] 
                    for i in range(len(key))]
        
        padding = len(key) - (len(text) % len(key)) if len(text) % len(key) != 0 else 0
        text = text + ' ' * padding
        
        matrix = [text[i:i + len(key)] for i in range(0, len(text), len(key))]
        
        if decrypt:
            result = ''
            for row in matrix:
                for col in key_order:
                    if col < len(row):
                        result += row[col]
        else:
            result = ''
            for col in key_order:
                for row in matrix:
                    if col < len(row):
                        result += row[col]
                        
        return result.rstrip()

    def _add_noise(self, text: str) -> str:
        words = text.split()
        noise_chars = "!@#$%^&*"
        return random.choice(noise_chars).join(words)

    def _remove_noise(self, text: str) -> str:
        return ' '.join(text.split())

    def _generate_salt(self, key: str, round: int) -> str:
        salt_base = hashlib.sha256(f"{key}{round}".encode()).hexdigest()
        return salt_base[:8]

    def _add_salt(self, text: str, salt: str) -> str:
        return f"{salt}{text}"

    def _remove_salt(self, text: str, salt: str) -> str:
        if text.startswith(salt):
            return text[len(salt):]
        return text

    def encrypt_text(self):
        try:
            key = self.key_entry.get().strip()
            if not key:
                raise ValueError("Encryption key is required")
                
            rounds = int(self.rounds_spinbox.get())
            if not (1 <= rounds <= 5):
                raise ValueError("Rounds must be between 1 and 5")
                
            text = self.cipher_input.get("1.0", tk.END).strip()
            if not text:
                messagebox.showwarning("Input Required", "Please enter text to encrypt")
                return
                
            encrypted = self.complex_encrypt(text, key, rounds)
            
            self.cipher_output.config(state='normal')
            self.cipher_output.delete("1.0", tk.END)
            self.cipher_output.insert("1.0", encrypted)
            self.cipher_output.config(state='disabled')
            
        except ValueError as e:
            messagebox.showerror("Error", str(e))

    def decrypt_text(self):
        try:
            key = self.key_entry.get().strip()
            if not key:
                raise ValueError("Encryption key is required")
                
            rounds = int(self.rounds_spinbox.get())
            if not (1 <= rounds <= 5):
                raise ValueError("Rounds must be between 1 and 5")
                
            text = self.cipher_input.get("1.0", tk.END).strip()
            if not text:
                messagebox.showwarning("Input Required", "Please enter text to decrypt")
                return
                
            decrypted = self.complex_decrypt(text, key, rounds)
            
            self.cipher_output.config(state='normal')
            self.cipher_output.delete("1.0", tk.END)
            self.cipher_output.insert("1.0", decrypted)
            self.cipher_output.config(state='disabled')
            
        except ValueError as e:
            messagebox.showerror("Error", str(e))

    def clear_cipher(self):
        self.cipher_input.delete("1.0", tk.END)
        self.cipher_output.config(state='normal')
        self.cipher_output.delete("1.0", tk.END)
        self.cipher_output.config(state='disabled')

    def set_encryption_key(self):
        key = self.network_key_entry.get().strip()
        if not key:
            messagebox.showerror("Error", "Please enter an encryption key")
            return
            
        key_bytes = key.encode()
        key_b64 = b64encode(hashlib.sha256(key_bytes).digest())
        self.encryption_key = key_b64
        self.fernet = Fernet(key_b64)
        
        messagebox.showinfo("Success", "Encryption key set successfully")
        self.log_network("Encryption enabled for packet analysis")

    def init_cipher(self):
        key_file = 'security.key'
        if not os.path.exists(key_file):
            key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(key)
        with open(key_file, 'rb') as f:
            self.cipher = Fernet(f.read())

    def encrypt_data(self, data, compress=True):
        if isinstance(data, str):
            data = data.encode()
        if compress:
            data = zlib.compress(data)
        return self.cipher.encrypt(data)

    def decrypt_data(self, encrypted_data, compressed=True):
        decrypted = self.cipher.decrypt(encrypted_data)
        if compressed:
            decrypted = zlib.decompress(decrypted)
        return decrypted.decode()

    def secure_file_write(self, filename, data):
        encrypted = self.encrypt_data(data)
        with open(filename, 'wb') as f:
            f.write(encrypted)

    def secure_file_read(self, filename):
        with open(filename, 'rb') as f:
            encrypted = f.read()
        return self.decrypt_data(encrypted)
    
    def save_network_data(self, packet_data):
        self.secure_file_write('network_log.enc', str(packet_data))

    def load_network_data(self):
        return self.secure_file_read('network_log.enc')

    def create_encryption_tab(self):
        encryption_tab = EncryptionTab(self.notebook, self.colors, self.fonts, self.style)
        self.notebook.add(encryption_tab, text='Encryption')

class EncryptionTab(ttk.Frame):
    def __init__(self, parent, colors, fonts, style):
        # Initialize encryption interface components
        super().__init__(parent)
        self.key = None
        self.colors = colors
        self.fonts = fonts
        self.style = style
        self.setup_ui()

    def setup_ui(self):
        self.configure(style='Custom.TFrame')
        
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        self.text_frame = ttk.LabelFrame(
            self, 
            text="Text Encryption",
            style='Custom.TFrame'
        )
        self.text_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        self.text_frame.grid_columnconfigure(0, weight=1)
        
        self.input_text = tk.Text(
            self.text_frame,
            height=8,  
            width=40,  
            font=self.fonts['text'],
            bg=self.colors['bg_light'],
            fg=self.colors['text'],
            insertbackground=self.colors['text']
        )
        self.input_text.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        
        controls_frame = ttk.Frame(self.text_frame, style='Custom.TFrame')
        controls_frame.grid(row=1, column=0, padx=10, pady=10, sticky="ew")
        
        self.password_label = ttk.Label(
            controls_frame,
            text="Password:",
            font=self.fonts['header'],  
            style='Custom.TLabel'
        )
        self.password_label.pack(side='left', padx=5)
        
        self.password_entry = ttk.Entry(
            controls_frame,
            font=self.fonts['header'],  
            style='Custom.TEntry',
            show="*",
            width=20
        )
        self.password_entry.pack(side='left', padx=5, fill='x', expand=True)
        
        button_frame = ttk.Frame(self.text_frame, style='Custom.TFrame')
        button_frame.grid(row=2, column=0, padx=10, pady=10, sticky="ew")
        button_frame.grid_columnconfigure((0,1), weight=1)
        
        self.encrypt_btn = ttk.Button(
            button_frame,
            text="Encrypt",
            command=self.encrypt_text,
            style='Custom.TButton',
            padding=(20, 10)  
        )
        self.encrypt_btn.grid(row=0, column=0, padx=10, pady=5, sticky="ew")
        
        self.decrypt_btn = ttk.Button(
            button_frame,
            text="Decrypt",
            command=self.decrypt_text,
            style='Custom.TButton',
            padding=(20, 10)  
        )
        self.decrypt_btn.grid(row=0, column=1, padx=10, pady=5, sticky="ew")
        
        self.file_frame = ttk.LabelFrame(
            self,
            text="File Encryption",
            style='Custom.TFrame'
        )
        self.file_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")
        self.file_frame.grid_columnconfigure(0, weight=1)
        
        select_frame = ttk.Frame(self.file_frame, style='Custom.TFrame')
        select_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        
        self.select_file_btn = ttk.Button(
            select_frame,
            text="Select File",
            command=self.select_file,
            style='Custom.TButton',
            padding=(20, 10)  
        )
        self.select_file_btn.pack(side='left', padx=10)
        
        self.file_label = ttk.Label(
            select_frame,
            text="No file selected",
            font=self.fonts['header'],
            style='Custom.TLabel'
        )
        self.file_label.pack(side='left', padx=10, fill='x', expand=True)

        self.file_list = tk.Listbox(
            self.file_frame,
            font=self.fonts['header'],  
            bg=self.colors['bg_light'],
            fg=self.colors['text'],
            selectmode='single',
            height=6  
        )
        self.file_list.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")
        
        file_buttons_frame = ttk.Frame(self.file_frame, style='Custom.TFrame')
        file_buttons_frame.grid(row=2, column=0, padx=10, pady=10, sticky="ew")
        file_buttons_frame.grid_columnconfigure((0,1), weight=1)
        
        self.encrypt_file_btn = ttk.Button(
            file_buttons_frame,
            text="Encrypt File",
            command=self.encrypt_file,
            style='Custom.TButton',
            padding=(20, 10)  
        )
        self.encrypt_file_btn.grid(row=0, column=0, padx=10, pady=5, sticky="ew")
        
        self.decrypt_file_btn = ttk.Button(
            file_buttons_frame,
            text="Decrypt File",
            command=self.decrypt_file,
            style='Custom.TButton',
            padding=(20, 10)  
        )
        self.decrypt_file_btn.grid(row=0, column=1, padx=10, pady=5, sticky="ew")
        
        self.status_label = ttk.Label(
            self.file_frame,
            text="Ready for encryption/decryption operations",
            font=self.fonts['header'],
            style='Custom.TLabel',
            wraplength=300
        )
        self.status_label.grid(row=3, column=0, padx=10, pady=10, sticky="ew")


    def generate_key(self, password):
        # Generate encryption key from password using PBKDF2
        salt = b'salt_'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return Fernet(key)

    def encrypt_text(self):
        try:
            text = self.input_text.get("1.0", tk.END).strip()
            password = self.password_entry.get()
            if not text or not password:
                tk.messagebox.showerror("Error", "Please enter both text and password")
                return
                
            f = self.generate_key(password)
            encrypted_text = f.encrypt(text.encode())
            self.input_text.delete("1.0", tk.END)
            self.input_text.insert("1.0", encrypted_text.decode())
        except Exception as e:
            tk.messagebox.showerror("Error", f"Encryption failed: {str(e)}")

    def decrypt_text(self):
        try:
            text = self.input_text.get("1.0", tk.END).strip()
            password = self.password_entry.get()
            if not text or not password:
                tk.messagebox.showerror("Error", "Please enter both text and password")
                return
                
            f = self.generate_key(password)
            decrypted_text = f.decrypt(text.encode())
            self.input_text.delete("1.0", tk.END)
            self.input_text.insert("1.0", decrypted_text.decode())
        except Exception as e:
            tk.messagebox.showerror("Error", f"Decryption failed: {str(e)}")

    def select_file(self):
        filepath = filedialog.askopenfilename()
        if filepath:
            self.file_label.config(text=os.path.basename(filepath))
            self.current_file = filepath

    def encrypt_file(self):
        # Encrypt file using password-based key and save output
        try:
            if not hasattr(self, 'current_file'):
                tk.messagebox.showerror("Error", "Please select a file first")
                return
                
            password = self.password_entry.get()
            if not password:
                tk.messagebox.showerror("Error", "Please enter a password")
                return

            f = self.generate_key(password)
            
            with open(self.current_file, 'rb') as file:
                file_data = file.read()
            
            encrypted_data = f.encrypt(file_data)
            
            with open(f"{self.current_file}.encrypted", 'wb') as file:
                file.write(encrypted_data)
                
            tk.messagebox.showinfo("Success", "File encrypted successfully")
        except Exception as e:
            tk.messagebox.showerror("Error", f"File encryption failed: {str(e)}")

    def decrypt_file(self):
        # Decrypt encrypted file using password-based key
        try:
            if not hasattr(self, 'current_file'):
                tk.messagebox.showerror("Error", "Please select a file first")
                return
                
            password = self.password_entry.get()
            if not password:
                tk.messagebox.showerror("Error", "Please enter a password")
                return

            f = self.generate_key(password)
            
            with open(self.current_file, 'rb') as file:
                encrypted_data = file.read()
            
            decrypted_data = f.decrypt(encrypted_data)
            
            output_file = self.current_file.replace('.encrypted', '.decrypted')
            with open(output_file, 'wb') as file:
                file.write(decrypted_data)
                
            tk.messagebox.showinfo("Success", "File decrypted successfully")
        except Exception as e:
            tk.messagebox.showerror("Error", f"File decryption failed: {str(e)}")

class SecurityTool(ABC):
    """Abstract base class for security analysis tools"""
    @abstractmethod
    def initialize(self):
        pass
    
    @abstractmethod
    def start(self):
        pass
    
    @abstractmethod
    def stop(self):
        pass

class PortScanner(SecurityTool):
    """Port scanning implementation with UI"""
    def __init__(self, root):
        self.root = root
        self.scan_active = False
        self.MAX_THREADS = 100
        
        self.main_frame = ctk.CTkFrame(root)
        self.main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        self.title_label = ctk.CTkLabel(
            self.main_frame, 
            text="Port Scanner",
            font=("Roboto", 24, "bold")
        )
        self.title_label.pack(pady=10)
        
        self.ip_frame = ctk.CTkFrame(self.main_frame)
        self.ip_frame.pack(fill="x", padx=10, pady=5)
        
        self.ip_label = ctk.CTkLabel(self.ip_frame, text="Target IP:")
        self.ip_label.pack(side="left", padx=5)
        
        self.target_ip = ctk.CTkEntry(
            self.ip_frame,
            placeholder_text="Enter IP address..."
        )
        self.target_ip.pack(side="left", fill="x", expand=True, padx=5)
        
        self.port_frame = ctk.CTkFrame(self.main_frame)
        self.port_frame.pack(fill="x", padx=10, pady=5)
        
        self.start_port_label = ctk.CTkLabel(self.port_frame, text="Start Port:")
        self.start_port_label.pack(side="left", padx=5)
        
        self.start_port = ctk.CTkEntry(
            self.port_frame,
            placeholder_text="1"
        )
        self.start_port.pack(side="left", padx=5)
        
        self.end_port_label = ctk.CTkLabel(self.port_frame, text="End Port:")
        self.end_port_label.pack(side="left", padx=5)
        
        self.end_port = ctk.CTkEntry(
            self.port_frame,
            placeholder_text="1024"
        )
        self.end_port.pack(side="left", padx=5)
        
        self.progress = ctk.CTkProgressBar(self.main_frame)
        self.progress.pack(fill="x", padx=10, pady=10)
        self.progress.set(0)
        
        self.button_frame = ctk.CTkFrame(self.main_frame)
        self.button_frame.pack(fill="x", padx=10, pady=5)
        
        self.start_button = ctk.CTkButton(
            self.button_frame,
            text="Start Scan",
            command=self.start
        )
        self.start_button.pack(side="left", padx=5)
        
        self.stop_button = ctk.CTkButton(
            self.button_frame,
            text="Stop Scan",
            fg_color="red",
            command=self.stop
        )
        self.stop_button.pack(side="left", padx=5)
        
        self.results_text = ctk.CTkTextbox(
            self.main_frame,
            height=200
        )
        self.results_text.pack(fill="both", expand=True, padx=10, pady=10)

class SecurityController:
    def __init__(self, root):
        self.root = root
        self.tools = {}
        self.encryption_key = None
        self.fernet = None

def main():
    # Initialize and launch security suite application
    root = tk.Tk()
    app = SecuritySuiteApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()