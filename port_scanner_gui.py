import tkinter as tk
from tkinter import scrolledtext
import threading
import socket
import time
import queue
import sys


class PortScannerApp:
    def __init__(self, root):
        # Set up main window
        self.root = root
        self.root.title("Port Scanner")
        
        # Initialize scanner components
        self.port_queue = queue.Queue()
        self.results = []
        self.target_ip = tk.StringVar()
        self.start_port = tk.IntVar(value=1)
        self.end_port = tk.IntVar(value=1024)
        
        # Set up UI components
        self.create_widgets()

    def create_widgets(self):
        """Set up input fields, buttons, and output display"""
        # Target IP Entry
        tk.Label(self.root, text="Target IP:").grid(row=0, column=0, sticky="e")
        tk.Entry(self.root, textvariable=self.target_ip).grid(row=0, column=1, padx=5, pady=5)

        # Port Range Entries
        tk.Label(self.root, text="Start Port:").grid(row=1, column=0, sticky="e")
        tk.Entry(self.root, textvariable=self.start_port).grid(row=1, column=1, padx=5, pady=5)
        
        tk.Label(self.root, text="End Port:").grid(row=2, column=0, sticky="e")
        tk.Entry(self.root, textvariable=self.end_port).grid(row=2, column=1, padx=5, pady=5)
        
        # Start Button
        self.start_button = tk.Button(self.root, text="Start Scan", command=self.start_scan)
        self.start_button.grid(row=3, column=0, columnspan=2, pady=10)
        
        # Output display (scrollable text area)
        self.output_display = scrolledtext.ScrolledText(self.root, width=50, height=20)
        self.output_display.grid(row=4, column=0, columnspan=2, padx=10, pady=10)

    def start_scan(self):
        """Start scan in a new thread to keep the UI responsive"""
        # Disable start button to prevent multiple scans
        self.start_button.config(state=tk.DISABLED)
        
        # Clear previous results
        self.output_display.delete(1.0, tk.END)
        
        # Start scanning in a new thread
        threading.Thread(target=self.run_scan).start()

    def run_scan(self):
        """Perform the port scan and update the UI with results"""
        target = self.target_ip.get() or "127.0.0.1"
        start_port = self.start_port.get()
        end_port = self.end_port.get()
        
        self.output_display.insert(tk.END, f"Starting scan on {target} (Ports {start_port}-{end_port})\n")
        
        # Perform the scan
        for port in range(start_port, end_port + 1):
            result = self.scan_port(target, port)
            if result['is_open']:
                self.output_display.insert(tk.END, f"Port {port} is open: {result['service']} (Risk: {result['risk_level']})\n")
            
            # Update the display
            self.output_display.yview(tk.END)
        
        self.output_display.insert(tk.END, "\nScan Complete!\n")
        
        # Re-enable start button after scan completes
        self.start_button.config(state=tk.NORMAL)

    def scan_port(self, target, port):
        """Scan a single port and return details"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            sock.close()
            
            if result == 0:
                return {
                    'port': port,
                    'is_open': True,
                    'service': self.port_info.get(port, "Unknown Service"),
                    'risk_level': self.risk_levels.get(port, "UNKNOWN")
                }
            else:
                return {'port': port, 'is_open': False}
        except socket.error:
            return {'port': port, 'is_open': False}

if __name__ == "__main__":
    root = tk.Tk()
    app = PortScannerApp(root)
    root.mainloop()
