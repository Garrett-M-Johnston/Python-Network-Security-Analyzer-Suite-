import tkinter as tk
from tkinter import ttk, scrolledtext, font, messagebox
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


class SecuritySuiteApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Security Analysis Suite")
        self.root.geometry("1000x700")
        
        # Color Scheme
        self.root.configure(bg='#121212')
        
        self.setup_variables()
        self.setup_styles()
        self.create_notebook()
        
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
        
        self.risk_levels = {
            "CRITICAL": "#FF0000",  # Red
            "HIGH": "#FFA500",      # Orange
            "MEDIUM": "#FFFF00",    # Yellow
            "LOW": "#00FF00"        # Green
        }

        #URL Analysis
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

    def setup_variables(self):
        """Initialize all application variables"""
        self.target_ip = tk.StringVar()
        self.start_port = tk.IntVar(value=1)
        self.end_port = tk.IntVar(value=1024)
        self.scan_active = False
        self.MAX_THREADS = 100
        self.scan_threads = []
        self.port_queue = queue.Queue()
        self.results_queue = queue.Queue()
        self.network_monitoring = False
        self.network_data = deque(maxlen=100)  # Store last 100 readings
        self.password_requirements = {
            'length': 12,
            'uppercase': 1,
            'lowercase': 1,
            'numbers': 1,
            'special': 1
        }
        # Phishing detection parameters
        self.phishing_indicators = {
            'urgency_words': {
                'urgent', 'immediate', 'action required', 'account suspended', 'verify now',
                'limited time', 'expires soon', 'suspended', 'blocked'
            },
            'sensitive_words': {
                'password', 'credit card', 'ssn', 'social security', 'bank account',
                'login', 'credential', 'billing', 'payment'
            },
            'common_spoofed_domains': {
                'paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook',
                'netflix', 'bank', 'secure', 'account'
            }
        }

    def setup_styles(self):
        """Configure application styling with monochromatic theme"""
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

    def create_notebook(self):
        """Create main notebook interface with additional tabs"""
        self.notebook = ttk.Notebook(self.root, style='Custom.TNotebook')
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.create_port_scanner_tab()
        self.create_email_analyzer_tab()
        self.create_url_analyzer_tab()
        self.create_network_monitor_tab()
        self.create_password_analyzer_tab()

    def create_labeled_entry(self, parent, label_text, variable, placeholder=""):
        """Create a labeled entry widget"""
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
        
        if placeholder:
            entry.insert(0, placeholder)
            entry.bind('<FocusIn>', lambda e: entry.delete(0, 'end') if entry.get() == placeholder else None)
            entry.bind('<FocusOut>', lambda e: entry.insert(0, placeholder) if entry.get() == "" else None)
        
        return frame

    def create_port_scanner_tab(self):
        """Create port scanner interface"""
        scanner_frame = ttk.Frame(self.notebook, style='Custom.TFrame')
        self.notebook.add(scanner_frame, text='Port Scanner')
        
        # Input controls
        input_frame = self.create_labeled_entry(
            scanner_frame,
            "Target IP:",
            self.target_ip,
            placeholder="Enter IP address"
        )
        input_frame.pack(fill='x', padx=10, pady=5)

        # Port range controls
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

        # Control buttons
        self.create_scanner_controls(scanner_frame)
        
        # Progress bar
        self.progress_bar = ttk.Progressbar(
            scanner_frame,
            orient="horizontal",
            length=400,
            mode="determinate"
        )
        self.progress_bar.pack(pady=10)
        
        # Results display
        self.scan_output = self.create_output_display(scanner_frame)

    def create_scanner_controls(self, parent):
        """Create scanner control buttons"""
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
        """Create URL analyzer interface"""
        url_frame = ttk.Frame(self.notebook, style='Custom.TFrame')
        self.notebook.add(url_frame, text='URL Analyzer')
        
        # Instructions
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
        
        # URL input
        self.url_input = self.create_output_display(url_frame)
        self.url_input.configure(height=5)
        
        # Analysis button
        ttk.Button(
            url_frame,
            text="Analyze URLs",
            command=self.analyze_urls,
            style='Custom.TButton'
        ).pack(pady=10)
        
        # Results display
        self.url_output = self.create_output_display(url_frame, state='disabled')

    def analyze_urls(self):
        """Analyze URLs for potential security threats"""
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
        """Analyze a single URL for security risks"""
        findings = []
        risk_score = 0
        
        # Ensure URL has scheme
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        try:
            parsed = urllib.parse.urlparse(url)
            extracted = tldextract.extract(url)
            
            # Check for HTTP (non-HTTPS)
            if parsed.scheme != 'https':
                findings.append("Uses unsecure HTTP protocol")
                risk_score += 20
            
            # Check suspicious TLDs
            if f".{extracted.suffix}" in self.malicious_url_patterns['suspicious_tlds']:
                findings.append(f"Suspicious TLD: .{extracted.suffix}")
                risk_score += 25
            
            # Check for IP-based URLs
            if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', parsed.netloc):
                findings.append("IP-based URL")
                risk_score += 30
            
            # Check for suspicious keywords
            domain_parts = f"{extracted.domain}.{extracted.suffix}".lower()
            for keyword in self.malicious_url_patterns['suspicious_keywords']:
                if keyword in domain_parts:
                    findings.append(f"Contains suspicious keyword: {keyword}")
                    risk_score += 15
                    break
            
            # Check for suspicious patterns
            for pattern in self.malicious_url_patterns['suspicious_patterns']:
                if re.search(pattern, parsed.netloc):
                    findings.append("Contains suspicious character pattern")
                    risk_score += 20
                    break
            
            # Check domain length
            if len(parsed.netloc) > 40:
                findings.append("Unusually long domain name")
                risk_score += 15
            
            # Check for multiple subdomains
            if len(extracted.subdomain.split('.')) > 2:
                findings.append("Multiple levels of subdomains")
                risk_score += 15
            
        except Exception as e:
            findings.append(f"Error parsing URL: {str(e)}")
            risk_score += 50
            
        return min(risk_score, 100), findings

    def _display_url_analysis(self, url: str, risk_score: int, findings: List[str]):
        """Display URL analysis results"""
        # Determine risk level color
        if risk_score < 30:
            risk_color = self.colors['success']
            risk_level = "LOW"
        elif risk_score < 70:
            risk_color = self.colors['warning']
            risk_level = "MEDIUM"
        else:
            risk_color = self.colors['danger']
            risk_level = "HIGH"
            
        # Display results
        self.url_output.insert(tk.END, f"\nAnalysis for: {url}\n", "url_header")
        self.url_output.insert(tk.END, f"Risk Score: {risk_score}/100 ({risk_level})\n", f"risk_{risk_color}")
        
        if findings:
            self.url_output.insert(tk.END, "\nFindings:\n")
            for finding in findings:
                self.url_output.insert(tk.END, f"• {finding}\n")
        else:
            self.url_output.insert(tk.END, "No suspicious indicators detected.\n")
            
        self.url_output.insert(tk.END, "=" * 50 + "\n")

    def create_network_monitor_tab(self):
        """Create network traffic monitoring interface"""
        network_frame = ttk.Frame(self.notebook, style='Custom.TFrame')
        self.notebook.add(network_frame, text='Network Monitor')
        
        # Control buttons
        controls_frame = ttk.Frame(network_frame, style='Custom.TFrame')
        controls_frame.pack(fill='x', padx=10, pady=5)
        
        self.monitor_button = ttk.Button(
            controls_frame,
            text="Start Monitoring",
            command=self.toggle_network_monitoring,
            style='Custom.TButton'
        )
        self.monitor_button.pack(side='left', padx=5)
        
        # Statistics display
        stats_frame = ttk.Frame(network_frame, style='Custom.TFrame')
        stats_frame.pack(fill='x', padx=10, pady=5)
        
        # Create labels for network statistics
        self.bytes_sent_label = ttk.Label(
            stats_frame,
            text="Bytes Sent: 0 B/s",
            font=self.fonts['text'],
            foreground=self.colors['text'],
            style='Custom.TLabel'
        )
        self.bytes_sent_label.pack(pady=2)
        
        self.bytes_recv_label = ttk.Label(
            stats_frame,
            text="Bytes Received: 0 B/s",
            font=self.fonts['text'],
            foreground=self.colors['text'],
            style='Custom.TLabel'
        )
        self.bytes_recv_label.pack(pady=2)
        
        self.connections_label = ttk.Label(
            stats_frame,
            text="Active Connections: 0",
            font=self.fonts['text'],
            foreground=self.colors['text'],
            style='Custom.TLabel'
        )
        self.connections_label.pack(pady=2)
        
        # Network traffic log
        ttk.Label(network_frame,
                 text="Network Traffic Log:",
                 font=self.fonts['header'],
                 foreground=self.colors['text'],
                 style='Custom.TLabel').pack(pady=5)
                 
        self.network_log = scrolledtext.ScrolledText(
            network_frame,
            font=self.fonts['text'],
            bg=self.colors['bg_light'],
            fg=self.colors['text'],
            height=15,
            state='disabled'
        )
        self.network_log.pack(fill='both', expand=True, padx=10, pady=5)

    def toggle_network_monitoring(self):
        """Toggle network monitoring on/off"""
        if not self.network_monitoring:
            self.network_monitoring = True
            self.monitor_button.config(text="Stop Monitoring")
            threading.Thread(target=self.monitor_network, daemon=True).start()
        else:
            self.network_monitoring = False
            self.monitor_button.config(text="Start Monitoring")

    def monitor_network(self):
        """Monitor network traffic and update display"""
        last_bytes_sent = psutil.net_io_counters().bytes_sent
        last_bytes_recv = psutil.net_io_counters().bytes_recv
        last_time = time.time()
        
        while self.network_monitoring:
            try:
                # Get current network stats
                current_time = time.time()
                current_bytes_sent = psutil.net_io_counters().bytes_sent
                current_bytes_recv = psutil.net_io_counters().bytes_recv
                
                # Calculate rates
                time_delta = current_time - last_time
                bytes_sent_rate = (current_bytes_sent - last_bytes_sent) / time_delta
                bytes_recv_rate = (current_bytes_recv - last_bytes_recv) / time_delta
                
                # Get connection count
                connections = len(psutil.net_connections())
                
                # Update labels
                self.root.after(0, self.update_network_labels,
                              bytes_sent_rate, bytes_recv_rate, connections)
                
                # Log detailed network activity
                self.log_network_activity(
                    f"Sent: {self.format_bytes(bytes_sent_rate)}/s, "
                    f"Received: {self.format_bytes(bytes_recv_rate)}/s, "
                    f"Connections: {connections}"
                )
                
                # Log suspicious activity (high data rates)
                if bytes_sent_rate > 1000000 or bytes_recv_rate > 1000000:  # 1 MB/s threshold
                    self.log_network_activity(
                        f"High data transfer rate detected! "
                        f"Sent: {self.format_bytes(bytes_sent_rate)}/s, "
                        f"Received: {self.format_bytes(bytes_recv_rate)}/s"
                    )
                
                # Update last values
                last_bytes_sent = current_bytes_sent
                last_bytes_recv = current_bytes_recv
                last_time = current_time
                
                time.sleep(1)  # Update every second
                
            except Exception as e:
                self.log_network_activity(f"Error monitoring network: {str(e)}")
                break

    def update_network_labels(self, sent_rate, recv_rate, connections):
        """Update network statistics labels"""
        self.bytes_sent_label.config(text=f"Bytes Sent: {self.format_bytes(sent_rate)}/s")
        self.bytes_recv_label.config(text=f"Bytes Received: {self.format_bytes(recv_rate)}/s")
        self.connections_label.config(text=f"Active Connections: {connections}")

    def log_network_activity(self, message: str):
        """Add message to network log"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.network_log.config(state='normal')
        self.network_log.insert(tk.END, f"[{timestamp}] {message}\n")
        self.network_log.see(tk.END)
        self.network_log.config(state='disabled')

    def format_bytes(self, bytes: float) -> str:
        """Format bytes into human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes < 1024:
                return f"{bytes:.2f} {unit}"
            bytes /= 1024
        return f"{bytes:.2f} TB"

    def create_password_analyzer_tab(self):
        """Create password strength analyzer interface"""
        password_frame = ttk.Frame(self.notebook, style='Custom.TFrame')
        self.notebook.add(password_frame, text='Password Analyzer')
        
        # Password input
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
            # show='•'  # Mask password
        )
        self.password_input.pack(side='left', padx=5, fill='x', expand=True)
        
        # Analysis controls
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
        
        # Results display
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
        """Analyze password strength"""
        password = self.password_input.get()
        
        if not password:
            messagebox.showerror("Error", "Please enter a password")
            return
            
        # Calculate strength metrics
        length_score = min(len(password) / self.password_requirements['length'], 1.0)
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)
        
        # Calculate entropy
        charset_size = 0
        if has_upper: charset_size += 26
        if has_lower: charset_size += 26
        if has_digit: charset_size += 10
        if has_special: charset_size += 32
        entropy = len(password) * (charset_size.bit_length() if charset_size > 0 else 0)
        
        # Check common patterns
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
        
        # Calculate overall strength (0-100)
        strength = (
            length_score * 30 +
            has_upper * 15 +
            has_lower * 15 +
            has_digit * 20 +
            has_special * 20
        )
        strength = max(0, strength - (len(found_patterns) * 10))
        
        # Display results
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
        
        # Hash information
        self.password_output.insert(tk.END, "\nPassword Hashes:\n")
        self.password_output.insert(tk.END, f"MD5: {hashlib.md5(password.encode()).hexdigest()}\n")
        self.password_output.insert(tk.END, f"SHA-256: {hashlib.sha256(password.encode()).hexdigest()}\n")
        
        self.password_output.insert(tk.END, f"\nPassword: {password}\n")
        
        self.password_output.config(state='disabled')

    def generate_password(self):
        """Generate a strong password"""
        length = self.password_requirements['length']
        
        # Character sets
        uppercase = string.ascii_uppercase
        lowercase = string.ascii_lowercase
        digits = string.digits
        special = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        # Ensure at least one character from each set
        password = [
            random.choice(uppercase),
            random.choice(lowercase),
            random.choice(digits),
            random.choice(special)
        ]
        
        # Fill remaining length with random characters
        all_chars = uppercase + lowercase + digits + special
        for _ in range(length - len(password)):
            password.append(random.choice(all_chars))
            
        # Shuffle password
        random.shuffle(password)
        password = ''.join(password)
        
        # Update input field
        self.password_input.delete(0, tk.END)
        self.password_input.insert(0, password)
        
        # Analyze the generated password
        self.analyze_password()

    def create_output_display(self, parent, state='normal'):
        """Create scrolled text widget for output"""
        output = scrolledtext.ScrolledText(
            parent,
            font=self.fonts['text'],
            bg=self.colors['bg_light'],
            fg=self.colors['text'],
            insertbackground=self.colors['text'],
            height=15,
            state=state  # Make read-only by default
        )
        output.pack(fill='both', expand=True, padx=10, pady=5)
        return output
    def create_email_analyzer_tab(self):
        """Create email analyzer interface"""
        email_frame = ttk.Frame(self.notebook, style='Custom.TFrame')
        self.notebook.add(email_frame, text='Email Analyzer')
        
        # Instructions
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
        
        # Email input
        self.email_input = self.create_output_display(email_frame)
        self.email_input.configure(height=10)
        
        # Analysis button
        ttk.Button(
            email_frame,
            text="Analyze Email",
            command=self.analyze_email,
            style='Custom.TButton'
        ).pack(pady=10)
        
        # Results display
        self.email_output = self.create_output_display(email_frame, state='disabled')
    def analyze_email(self):
        """Analyze email content for potential phishing indicators"""
        email_content = self.email_input.get("1.0", tk.END).strip()
        
        if not email_content:
            messagebox.showerror("Error", "Please enter email content to analyze")
            return
            
        self.email_output.delete("1.0", tk.END)
        
        # Parse email content
        try:
            msg = email.message_from_string(email_content)
        except Exception as e:
            self.email_output.insert(tk.END, "Error parsing email content\n")
            return
            
        # Initialize analysis results
        analysis_results = {
            'urgency_count': 0,
            'sensitive_count': 0,
            'suspicious_urls': [],
            'spoofed_domains': [],
            'risk_score': 0
        }
        
        # Analyze headers
        self._analyze_headers(msg, analysis_results)
        
        # Analyze body content
        self._analyze_body(msg, analysis_results)
        
        # Calculate risk score (0-100)
        risk_score = self._calculate_risk_score(analysis_results)
        
        # Display results
        self._display_analysis_results(analysis_results, risk_score)

    def _analyze_headers(self, msg: Message, results: Dict):
        from_header = msg.get('from', '')
        if from_header:
            domain = from_header.split('@')[-1].strip('>')
            # SPF/DKIM check example
            if 'spf=fail' in msg.get('Received-SPF', '') or 'dkim=fail' in msg.get('Authentication-Results', ''):
                results['risk_score'] += 20
                results['spoofed_domains'].append(domain)
        
        # Check reply-to mismatch
        reply_to = msg.get('reply-to', '')
        if reply_to and from_header and '@' in reply_to and '@' in from_header:
            reply_domain = reply_to.split('@')[-1].strip('>')
            from_domain = from_header.split('@')[-1].strip('>')
            if reply_domain != from_domain:
                results['risk_score'] += 20

    def _analyze_body(self, msg: Message, results: Dict):
        """Analyze email body for suspicious content"""
        # Get email body content
        if msg.is_multipart():
            body = ''
            for part in msg.walk():
                # Check if it's text/plain or text/html part
                if part.get_content_type() == "text/plain":
                    body += part.get_payload(decode=True).decode()
                elif part.get_content_type() == "text/html":
                    html_content = part.get_payload(decode=True).decode()
                    body += html_content
        else:
            body = msg.get_payload(decode=True).decode() if msg.get_payload() else ''
        
        # Parse HTML with BeautifulSoup to extract all links
        soup = BeautifulSoup(body, 'html.parser')
        all_links = [a['href'] for a in soup.find_all('a', href=True)]

        # Analyze all found links for suspicious patterns
        for url in all_links:
            try:
                parsed = urllib.parse.urlparse(url)
                if self._is_suspicious_url(parsed):
                    results['suspicious_urls'].append(url)
            except Exception:
                continue

        # Check for urgency indicators
        for word in self.phishing_indicators['urgency_words']:
            if word.lower() in body.lower():
                results['urgency_count'] += 1
        
        # Check for sensitive information requests
        for word in self.phishing_indicators['sensitive_words']:
            if word.lower() in body.lower():
                results['sensitive_count'] += 1
        
        # Sentiment analysis to detect urgency or fear-inducing language
        blob = TextBlob(body)
        sentiment = blob.sentiment.polarity
        if sentiment < -0.3:  # Threshold for detecting negative sentiment
            results['urgency_count'] += 1  # Increase urgency count if aggressive language detected
        
        # Combine HTML and plain text URL analysis
        urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', body)
        urls += all_links  # Include all HTML links
        urls = list(set(urls))  # Remove duplicates
        
        # Analyze all URLs for suspicious indicators
        for url in urls:
            try:
                parsed = urllib.parse.urlparse(url)
                if self._is_suspicious_url(parsed):
                    results['suspicious_urls'].append(url)
            except Exception:
                continue

    def _is_suspicious_url(self, parsed_url) -> bool:
        """Check if a URL has suspicious characteristics"""
        suspicious_indicators = [
            'login', 'signin', 'account', 'verify', 'secure', 'update',
            'confirm', 'password', 'banking'
        ]
        
        domain = parsed_url.netloc.lower()
        path = parsed_url.path.lower()
        
        # Check for IP-based URLs
        if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
            return True
            
        # Check for suspicious keywords in domain or path
        for indicator in suspicious_indicators:
            if indicator in domain or indicator in path:
                return True
                
        # Check for domain spoofing patterns
        for legitimate in self.phishing_indicators['common_spoofed_domains']:
            if legitimate in domain and not domain.endswith(('.com', '.org', '.net')):
                return True
                
        return False

    def _calculate_risk_score(self, results: Dict) -> int:
        """Calculate overall phishing risk score"""
        score = 0
        
        # Add points for urgency indicators
        score += min(results['urgency_count'] * 10, 30)
        
        # Add points for sensitive information requests
        score += min(results['sensitive_count'] * 15, 30)
        
        # Add points for suspicious URLs
        score += min(len(results['suspicious_urls']) * 20, 30)
        
        # Add points for spoofed domains
        score += min(len(results['spoofed_domains']) * 25, 40)
        
        return min(score, 100)

    def _display_analysis_results(self, results: Dict, risk_score: int):
        """Display analysis results in the output text widget with detailed reasons for suspicion"""
        self.email_output.delete("1.0", tk.END)
        
        # Display risk score with color coding
        if risk_score < 30:
            risk_color = self.colors['success']
        elif risk_score < 70:
            risk_color = self.colors['warning']
        else:
            risk_color = self.colors['danger']
            
        self.email_output.insert(tk.END, f"Risk Score: {risk_score}/100\n", f"risk_{risk_color}")
        self.email_output.insert(tk.END, "\n")

        # Display detailed findings with specific reasons
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

        # No suspicious elements
        if risk_score == 0:
            self.email_output.insert(tk.END, "\nNo suspicious indicators detected.")
    def create_output_display(self, parent, state='normal'):
        """Create scrolled text widget for output"""
        output = scrolledtext.ScrolledText(
            parent,
            font=self.fonts['text'],
            bg=self.colors['bg_light'],
            fg=self.colors['text'],
            insertbackground=self.colors['text'],
            height=15,
            state=state  # Make read-only by default
        )
        output.pack(fill='both', expand=True, padx=10, pady=5)
        return output

    # [Previous methods for scanning and analysis remain the same]
    def validate_ip(self, ip_address: str) -> bool:
        """Validate if the given string is a valid IP address"""
        try:
            ipaddress.ip_address(ip_address)
            return True
        except ValueError:
            return False

    def start_scan(self):
        """Start port scan with input validation"""
        target = self.target_ip.get().strip()
        
        # Validate IP address
        if not target:
            messagebox.showerror("Error", "Please enter an IP address")
            return
        
        if not self.validate_ip(target):
            messagebox.showerror("Error", "Invalid IP address format")
            return
            
        # Validate port range
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
        """Stop the scan gracefully"""
        self.scan_active = False
        self.stop_button.config(state=tk.DISABLED)
        self.scan_output.insert(tk.END, "\nStopping scan...\n")
        
        # Clear remaining ports
        while not self.port_queue.empty():
            self.port_queue.get()
        
        # Wait for threads to finish
        for thread in self.scan_threads:
            thread.join(timeout=0.1)
        
        self.scan_threads.clear()
        self.scan_button.config(state=tk.NORMAL)
        self.scan_output.insert(tk.END, "Scan stopped by user\n")
        self.progress_bar['value'] = 0

    def worker_scan(self, target):
        """Enhanced worker thread for scanning ports with service identification"""
        socket.setdefaulttimeout(1)
        
        while self.scan_active:
            try:
                port = self.port_queue.get_nowait()
            except queue.Empty:
                return  # Exit when no more ports to scan

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
        """Identify service and security implications for a given port"""
        if port in self.common_ports:
            return self.common_ports[port]
        else:
            return ("Unknown Service", "Unidentified service - could be custom application or security risk.")

    def assess_risk_level(self, port: int, service_info: Tuple[str, str]) -> str:
        """Assess the risk level of an open port"""
        service_name, description = service_info
        
        # Define critical ports that should usually be closed
        critical_ports = {23, 135, 139, 445, 3389}
        high_risk_ports = {21, 80, 110, 143, 1433, 1521, 3306, 5432, 5900, 27017}
        medium_risk_ports = {20, 25, 53, 8080}
        
        if port in critical_ports:
            return "CRITICAL"
        elif port in high_risk_ports:
            return "HIGH"
        elif port in medium_risk_ports:
            return "MEDIUM"
        elif port == 443 or port == 22:  # Secure ports
            return "LOW"
        else:
            return "MEDIUM"  # Unknown ports treated as medium risk

    def format_port_result(self, port: int, service_info: Tuple[str, str], risk_level: str) -> str:
        """Format the port scan result message"""
        service_name, description = service_info
        return f"""Port {port} is OPEN
Service: {service_name}
Risk Level: {risk_level}
Security Note: {description}
{'=' * 50}\n"""

    def update_scan_output(self, message: str, risk_level: str):
        """Update scan output with color-coded results"""
        self.scan_output.insert(tk.END, message)
        
        # Apply color tag based on risk level
        start = self.scan_output.index("end-2c linestart")
        end = self.scan_output.index("end-1c")
        
        # Create and configure tag for risk level color
        self.scan_output.tag_config(f"risk_{risk_level}", foreground=self.risk_levels.get(risk_level, "white"))
        self.scan_output.tag_add(f"risk_{risk_level}", start, end)
        
        self.scan_output.see(tk.END)

    def run_scan(self):
        """Execute port scan with threading for speed"""
        target = self.target_ip.get() or "127.0.0.1"
        start_port = self.start_port.get()
        end_port = self.end_port.get()
        
        self.scan_output.delete(1.0, tk.END)
        self.scan_output.insert(tk.END, f"Starting scan on {target}\n \n")
        
        port_range = end_port - start_port + 1
        self.progress_bar['maximum'] = port_range
        self.progress_bar['value'] = 0
        
        # Clear queues
        while not self.port_queue.empty():
            self.port_queue.get()
        while not self.results_queue.empty():
            self.results_queue.get()
        
        # Queue up the ports to scan
        for port in range(start_port, end_port + 1):
            self.port_queue.put(port)
        
        # Start scan threads
        self.scan_threads = []
        thread_count = min(self.MAX_THREADS, port_range)
        for _ in range(thread_count):
            thread = threading.Thread(target=self.worker_scan, args=(target,), daemon=True)
            thread.start()
            self.scan_threads.append(thread)

        # Start progress update thread
        threading.Thread(target=self.update_progress, daemon=True).start()

    def update_progress(self):
        """Update progress bar and check for scan completion"""
        initial_total = self.progress_bar['maximum']
        
        while self.scan_active:
            try:
                remaining = self.port_queue.qsize()
                completed = initial_total - remaining
                self.progress_bar['value'] = completed
                
                # Check if scan is complete
                if remaining == 0:
                    # Wait briefly to ensure all results are processed
                    self.root.after(100)
                    self.complete_scan()
                    break
                
                self.root.update_idletasks()
                self.root.after(100)  # Update every 100ms
            except Exception as e:
                print(f"Error updating progress: {str(e)}")
                break

    def complete_scan(self):
        """Handle scan completion"""
        self.scan_active = False
        
        # Clean up threads
        for thread in self.scan_threads:
            thread.join(timeout=0.1)
        
        self.scan_threads.clear()
        
        # Update UI
        self.progress_bar['value'] = self.progress_bar['maximum']
        self.scan_output.insert(tk.END, "\nScan completed!\n")
        self.scan_output.see(tk.END)
        self.scan_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        
        # Clear queues
        while not self.port_queue.empty():
            self.port_queue.get()
        while not self.results_queue.empty():
            self.results_queue.get()
    def create_network_monitor_tab(self):
        """Create network traffic monitoring interface"""
        network_frame = ttk.Frame(self.notebook, style='Custom.TFrame')
        self.notebook.add(network_frame, text='Network Monitor')
        
        # Control buttons
        controls_frame = ttk.Frame(network_frame, style='Custom.TFrame')
        controls_frame.pack(fill='x', padx=10, pady=5)
        
        self.monitor_button = ttk.Button(
            controls_frame,
            text="Start Monitoring",
            command=self.toggle_network_monitoring,
            style='Custom.TButton'
        )
        self.monitor_button.pack(side='left', padx=5)
        
        # Statistics display
        stats_frame = ttk.Frame(network_frame, style='Custom.TFrame')
        stats_frame.pack(fill='x', padx=10, pady=5)
        
        # Create labels for network statistics
        self.bytes_sent_label = ttk.Label(
            stats_frame,
            text="Bytes Sent: 0 B/s",
            font=self.fonts['text'],
            foreground=self.colors['text'],
            style='Custom.TLabel'
        )
        self.bytes_sent_label.pack(pady=2)
        
        self.bytes_recv_label = ttk.Label(
            stats_frame,
            text="Bytes Received: 0 B/s",
            font=self.fonts['text'],
            foreground=self.colors['text'],
            style='Custom.TLabel'
        )
        self.bytes_recv_label.pack(pady=2)
        
        self.connections_label = ttk.Label(
            stats_frame,
            text="Active Connections: 0",
            font=self.fonts['text'],
            foreground=self.colors['text'],
            style='Custom.TLabel'
        )
        self.connections_label.pack(pady=2)
        
        # Network traffic log
        ttk.Label(network_frame,
                 text="Network Traffic Log:",
                 font=self.fonts['header'],
                 foreground=self.colors['text'],
                 style='Custom.TLabel').pack(pady=5)
                 
        self.network_log = scrolledtext.ScrolledText(
            network_frame,
            font=self.fonts['text'],
            bg=self.colors['bg_light'],
            fg=self.colors['text'],
            height=15,
            state='disabled'
        )
        self.network_log.pack(fill='both', expand=True, padx=10, pady=5)

    def toggle_network_monitoring(self):
        """Toggle network monitoring on/off"""
        if not self.network_monitoring:
            self.network_monitoring = True
            self.monitor_button.config(text="Stop Monitoring")
            threading.Thread(target=self.monitor_network, daemon=True).start()
        else:
            self.network_monitoring = False
            self.monitor_button.config(text="Start Monitoring")

    def monitor_network(self):
        """Monitor network traffic and update display"""
        last_bytes_sent = psutil.net_io_counters().bytes_sent
        last_bytes_recv = psutil.net_io_counters().bytes_recv
        last_time = time.time()
        
        while self.network_monitoring:
            try:
                # Get current network stats
                current_time = time.time()
                current_bytes_sent = psutil.net_io_counters().bytes_sent
                current_bytes_recv = psutil.net_io_counters().bytes_recv
                
                # Calculate rates
                time_delta = current_time - last_time
                bytes_sent_rate = (current_bytes_sent - last_bytes_sent) / time_delta
                bytes_recv_rate = (current_bytes_recv - last_bytes_recv) / time_delta
                
                # Get connection count
                connections = len(psutil.net_connections())
                
                # Update labels
                self.root.after(0, self.update_network_labels,
                              bytes_sent_rate, bytes_recv_rate, connections)
                
                # Log detailed network activity
                self.log_network_activity(
                    f"Sent: {self.format_bytes(bytes_sent_rate)}/s, "
                    f"Received: {self.format_bytes(bytes_recv_rate)}/s, "
                    f"Connections: {connections}"
                )
                
                # Log suspicious activity (high data rates)
                if bytes_sent_rate > 1000000 or bytes_recv_rate > 1000000:  # 1 MB/s threshold
                    self.log_network_activity(
                        f"High data transfer rate detected! "
                        f"Sent: {self.format_bytes(bytes_sent_rate)}/s, "
                        f"Received: {self.format_bytes(bytes_recv_rate)}/s"
                    )
                
                # Update last values
                last_bytes_sent = current_bytes_sent
                last_bytes_recv = current_bytes_recv
                last_time = current_time
                
                time.sleep(1)  # Update every second
                
            except Exception as e:
                self.log_network_activity(f"Error monitoring network: {str(e)}")
                break

    def update_network_labels(self, sent_rate, recv_rate, connections):
        """Update network statistics labels"""
        self.bytes_sent_label.config(text=f"Bytes Sent: {self.format_bytes(sent_rate)}/s")
        self.bytes_recv_label.config(text=f"Bytes Received: {self.format_bytes(recv_rate)}/s")
        self.connections_label.config(text=f"Active Connections: {connections}")

    def log_network_activity(self, message: str):
        """Add message to network log"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.network_log.config(state='normal')
        self.network_log.insert(tk.END, f"[{timestamp}] {message}\n")
        self.network_log.see(tk.END)
        self.network_log.config(state='disabled')

    def format_bytes(self, bytes: float) -> str:
        """Format bytes into human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes < 1024:
                return f"{bytes:.2f} {unit}"
            bytes /= 1024
        return f"{bytes:.2f} TB"

    def create_password_analyzer_tab(self):
        """Create password strength analyzer interface"""
        password_frame = ttk.Frame(self.notebook, style='Custom.TFrame')
        self.notebook.add(password_frame, text='Password Analyzer')
        
        # Password input
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
            # show='•'  # Mask password
        )
        self.password_input.pack(side='left', padx=5, fill='x', expand=True)
        
        # Analysis controls
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
        
        # Results display
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
        """Analyze password strength"""
        password = self.password_input.get()
        
        if not password:
            messagebox.showerror("Error", "Please enter a password")
            return
            
        # Calculate strength metrics
        length_score = min(len(password) / self.password_requirements['length'], 1.0)
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)
        
        # Calculate entropy
        charset_size = 0
        if has_upper: charset_size += 26
        if has_lower: charset_size += 26
        if has_digit: charset_size += 10
        if has_special: charset_size += 32
        entropy = len(password) * (charset_size.bit_length() if charset_size > 0 else 0)
        
        # Check common patterns
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
        
        # Calculate overall strength (0-100)
        strength = (
            length_score * 30 +
            has_upper * 15 +
            has_lower * 15 +
            has_digit * 20 +
            has_special * 20
        )
        strength = max(0, strength - (len(found_patterns) * 10))
        
        # Display results
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
        
        # Hash information
        self.password_output.insert(tk.END, "\nPassword Hashes:\n")
        self.password_output.insert(tk.END, f"MD5: {hashlib.md5(password.encode()).hexdigest()}\n")
        self.password_output.insert(tk.END, f"SHA-256: {hashlib.sha256(password.encode()).hexdigest()}\n")
        
        self.password_output.insert(tk.END, f"\nPassword: {password}\n")
        
        self.password_output.config(state='disabled')

    def generate_password(self):
        """Generate a strong password"""
        length = self.password_requirements['length']
        
        # Character sets
        uppercase = string.ascii_uppercase
        lowercase = string.ascii_lowercase
        digits = string.digits
        special = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        # Ensure at least one character from each set
        password = [
            random.choice(uppercase),
            random.choice(lowercase),
            random.choice(digits),
            random.choice(special)
        ]
        
        # Fill remaining length with random characters
        all_chars = uppercase + lowercase + digits + special
        for _ in range(length - len(password)):
            password.append(random.choice(all_chars))
            
        # Shuffle password
        random.shuffle(password)
        password = ''.join(password)
        
        # Update input field
        self.password_input.delete(0, tk.END)
        self.password_input.insert(0, password)
        
        # Analyze the generated password
        self.analyze_password()

    def create_output_display(self, parent, state='normal'):
        """Create scrolled text widget for output"""
        output = scrolledtext.ScrolledText(
            parent,
            font=self.fonts['text'],
            bg=self.colors['bg_light'],
            fg=self.colors['text'],
            insertbackground=self.colors['text'],
            height=15,
            state=state  # Make read-only by default
        )
        output.pack(fill='both', expand=True, padx=10, pady=5)
        return output
def main():
    root = tk.Tk()
    app = SecuritySuiteApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()