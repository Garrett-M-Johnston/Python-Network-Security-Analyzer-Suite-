import email
import re
from collections import defaultdict
import logging
from datetime import datetime
import json
import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from io import StringIO
import spf
import re

class PhishingDetector:
    def __init__(self):
        self.suspicious_keywords = ["urgent", "click here", "verify your account", "update your information"]
        
    def check_spf(self, from_address):
        # Extract domain from the from_address
        domain = re.findall(r'@([\w.-]+)', from_address)
        if not domain:
            return False  # Invalid domain format
        domain = domain[0]

        # Perform SPF check
        result, _ = spf.check2(i="127.0.0.1", s=from_address, h=domain)  # Using localhost as the sender IP
        return result == "pass"
    
    def analyze_email(self, from_address, email_content):
        spf_valid = self.check_spf(from_address)
        
        if not spf_valid:
            print("Warning: SPF check failed. This email may be suspicious.")
        else:
            print("SPF check passed.")
        
        # Check for suspicious keywords in email content
        for keyword in self.suspicious_keywords:
            if keyword.lower() in email_content.lower():
                print(f"Suspicious keyword found: {keyword}")
                break
        else:
            print("No suspicious keywords found.")
            
# Example Usage
detector = PhishingDetector()
from_address = "example@example.com"  # The email address to check
email_content = "Please click here to verify your account urgently!"

detector.analyze_email(from_address, email_content)

def generate_report(self, results):
        """Generate a human-readable report with clear explanations."""
        report = []
        report.append("=== Phishing Email Analysis Report ===\n")
        report.append(f"Analysis Time: {results['timestamp']}")
        report.append(f"Risk Level: {results['risk_level']}")
        report.append(f"Risk Score: {results['risk_score']:.2f}/{self.config['max_risk_score']}\n")

        # Friendly descriptions for findings
        report.append("=== Key Findings and Explanations ===")

        # Headers Analysis
        if 'headers' in results['findings']:
            report.append("\nSender and Headers:")
            if 'spoofing_indicators' in results['findings']['headers']:
                report.append("⚠️ Possible Spoofing: The sender's email might be faked (From and Return-Path don't match).")
        
        # Content Analysis
        if 'content' in results['findings']:
            report.append("\nEmail Content:")
            suspicious_words = results['findings']['content'].get('suspicious_words', [])
            if suspicious_words:
                report.append("⚠️ Suspicious Phrases: The email uses phrases often seen in phishing (e.g., 'urgent', 'account', 'verify').")
            for url_info in results['findings']['content'].get('urls', []):
                if url_info['suspicious']:
                    report.append(f"⚠️ Suspicious Link: The link '{url_info['url']}' uses a shortened URL, which is often used in scams.")

        # Attachment Analysis
        if 'attachments' in results['findings']:
            report.append("\nAttachments:")
            for attachment in results['findings']['attachments']['attachments']:
                if attachment['suspicious']:
                    reasons = ', '.join(attachment['reasons'])
                    report.append(f"⚠️ Suspicious Attachment: '{attachment['filename']}' might be unsafe ({reasons}).")

        # Closing message
        report.append("\n---\nPlease be cautious with this email if you received it unexpectedly.")
        report.append("Consider checking with the sender directly (without using any links or contact details in the email).")

        return "\n".join(report)

# The rest of your main and GUI code remains unchanged

def main():
    """Main function to run the phishing detector"""
    detector = PhishingDetector()
    
    try:
        # Create a sample config file if it doesn't exist
        if not os.path.exists('config.json'):
            with open('config.json', 'w') as f:
                json.dump(detector.config, f, indent=2)
        
        # Read and analyze email
        with open('phishing_email.eml', 'r') as f:
            email_msg = email.message_from_string(f.read())
        
        # Analyze the email
        results = detector.analyze_email(email_msg)
        
        # Generate and print report
        report = detector.generate_report(results)
        print(report)
        
    except FileNotFoundError:
        print("Error: Required files not found. Please ensure both config.json and phishing_email.eml exist.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        detector.logger.error(f"Main function error: {str(e)}")
class PhishingDetectorGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Phishing Detector")
        self.master.geometry("600x600")
        
        # Use a theme for a modern look
        style = ttk.Style(master)
        style.theme_use('clam')
        
        # Main frame
        main_frame = tk.Frame(master, padx=10, pady=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header
        header_label = tk.Label(main_frame, text="Phishing Detector", font=("Helvetica", 16, "bold"))
        header_label.pack(pady=(0, 10))

        # Input Section
        input_frame = tk.LabelFrame(main_frame, text="Email Content", padx=10, pady=10)
        input_frame.pack(fill="both", expand=True, pady=5)

        self.email_content = tk.Text(input_frame, wrap=tk.WORD, height=10)
        self.email_content.pack(fill="both", expand=True)

        # Analyze Button
        analyze_button = ttk.Button(main_frame, text="Analyze Email", command=self.analyze_email)
        analyze_button.pack(pady=10)

        # Status label
        self.status_label = tk.Label(main_frame, text="", font=("Helvetica", 10, "italic"))
        self.status_label.pack()

        # Results Section
        results_frame = tk.LabelFrame(main_frame, text="Analysis Report", padx=10, pady=10)
        results_frame.pack(fill="both", expand=True, pady=5)
        
        # Scrollable text box for the report
        self.results_text = tk.Text(results_frame, wrap=tk.WORD, height=15, state='disabled')
        self.results_text.pack(fill="both", expand=True)
        
    def analyze_email(self):
        email_content = self.email_content.get("1.0", tk.END).strip()
        if not email_content:
            messagebox.showwarning("No Email Content", "Please paste email content into the text box.")
            return
        
        # Parse the email content
        email_msg = email.message_from_file(StringIO(email_content))
        detector = PhishingDetector()
        
        try:
            # Analyze and generate report
            results = detector.analyze_email(email_msg)
            report = detector.generate_report(results)
            
            # Display the report
            self.results_text.config(state='normal')
            self.results_text.delete("1.0", tk.END)
            self.results_text.insert(tk.END, report)
            self.results_text.config(state='disabled')

            # Update status
            self.status_label.config(text=f"Analysis Complete - Risk Level: {results['risk_level']}")
        
        except Exception as e:
            self.status_label.config(text="Error in analysis.")
            messagebox.showerror("Error", f"An error occurred during analysis:\n{str(e)}")

# Run the app
root = tk.Tk()
app = PhishingDetectorGUI(root)
root.mainloop()

if __name__ == '__main__':
    main()