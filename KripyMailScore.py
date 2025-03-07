#!/usr/bin/env python3

import re
import email
import tldextract
import requests
from email.header import decode_header
from urllib.parse import urlparse
from colorama import Fore, Style, init
import sys

# Initialize colorama
init(autoreset=True)

def display_logo():
    logo = f"""
{Fore.RED}    __  _  ____   ____  ____  __ __  ___ ___   ____  ____  _      _____   __   ___   ____     ___ 
   |  l/ ]|    \ l    j|    \|  T  T|   T   T /    Tl    j| T    / ___/  /  ] /   \ |    \   /  _]
   |  ' / |  D  ) |  T |  o  )  |  || _   _ |Y  o  | |  T | |   (   \_  /  / Y     Y|  D  ) /  [_ 
   |    \ |    /  |  | |   _/|  ~  ||  \_/  ||     | |  | | l___ \__  T/  /  |  O  ||    / Y    _]
   |     Y|    \  |  | |  |  l___, ||   |   ||  _  | |  | |     T/  \ /   \_ |     ||    \ |   [_ 
   |  .  ||  .  Y j  l |  |  |     !|   |   ||  |  | j  l |     |\    \     |l     !|  .  Y|     T
   l__j\_jl__j\_j|____jl__j  l____/ l___j___jl__j__j|____jl_____j \___j\____j \___/ l__j\_jl_____j

       {Fore.YELLOW}Phishing Email Detector
    """
    print(logo)

def display_help():
    help_text = f"""
{Fore.GREEN}Usage:sudo python KripyMailScore.py <email_file.eml>

Options:
  -h, --help    Show this help message and exit.

Description:
  This script analyzes email files (.eml) to detect phishing attempts. It checks for:
  - Spoofed senders
  - Urgent language indicating phishing
  - Suspicious attachments
  - Hidden or shortened URLs
  - Generic greetings commonly used in phishing emails
  - Other phishing indicators

  The program assigns a suspicion score and provides a risk assessment based on detected threats.
    """
    print(help_text)

class PhishingDetector:
    def __init__(self, email_file):
        self.email_file = email_file
        self.suspicious_score = 0
        self.threshold = 5  # Threshold for phishing determination
        self.results = {
            'suspicious_links': [],
            'spoofed_sender': False,
            'urgent_language': False,
            'suspicious_attachments': [],
            'hidden_urls': [],
            'generic_greeting': False
        }
    
    def analyze_email(self):
        try:
            with open(self.email_file, 'r', encoding='utf-8') as f:
                msg = email.message_from_file(f)
            
            self._check_headers(msg)
            self._check_content(msg)
            self._check_links(msg)
            self._check_attachments(msg)
            
            return self._generate_report()
        except Exception as e:
            return f"{Fore.RED}Error analyzing email: {str(e)}"
    
    def _check_headers(self, msg):
        from_header = msg.get('From', '')
        return_path = msg.get('Return-Path', '')
        
        from_email = re.findall(r'<(.+?)>', from_header)
        return_email = re.findall(r'<(.+?)>', return_path)
        
        if from_email and return_email and from_email[0] != return_email[0]:
            self.suspicious_score += 3
            self.results['spoofed_sender'] = True
    
    def _check_content(self, msg):
        subject, encoding = decode_header(msg['Subject'])[0]
        if isinstance(subject, bytes):
            subject = subject.decode(encoding or 'utf-8')
        
        urgent_keywords = [
            'urgent', 'immediate action', 'account (verification|suspended)',
            'password (expired reset)', 'security alert', 'click here'
        ]
        body = self._get_email_body(msg)
        
        for pattern in urgent_keywords:
            if re.search(pattern, subject + body, re.IGNORECASE):
                self.suspicious_score += 2
                self.results['urgent_language'] = True
        
        if re.search(r'Dear (Customer|User|Valued Member)', body, re.IGNORECASE):
            self.suspicious_score += 1
            self.results['generic_greeting'] = True
    
    def _check_links(self, msg):
        body = self._get_email_body(msg)
        links = re.findall(r'href=["\']([^"\']+)', body)
        
        for link in links:
            parsed = urlparse(link)
            
            if any(domain in parsed.netloc for domain in ['bit.ly', 'goo.gl', 'tinyurl']):
                self.suspicious_score += 2
                self.results['suspicious_links'].append(link)
            
            if parsed.scheme != 'https':
                self.suspicious_score += 1
            
            if self._is_new_domain(parsed.netloc):
                self.suspicious_score += 3
            
            if re.search(r'@.*//', link):
                self.suspicious_score += 2
                self.results['hidden_urls'].append(link)
    
    def _check_attachments(self, msg):
        suspicious_extensions = ['.exe', '.zip', '.js', '.scr', '.bat']
        
        for part in msg.walk():
            if part.get_content_disposition() == 'attachment':
                filename = part.get_filename()
                if filename:
                    if any(filename.endswith(ext) for ext in suspicious_extensions):
                        self.suspicious_score += 3
                        self.results['suspicious_attachments'].append(filename)
    
    def _get_email_body(self, msg):
        body = ""
        for part in msg.walk():
            if part.get_content_type() == 'text/plain':
                charset = part.get_content_charset() or 'utf-8'
                body += part.get_payload(decode=True).decode(charset, errors='replace')
        return body
    
    def _generate_report(self):
        risk_level = (
            f"{Fore.RED}Maximum Chance of Risk, Be Careful!" if self.suspicious_score > 8 else
            f"{Fore.YELLOW}Possible Risk" if 3 <= self.suspicious_score <= 8 else
            f"{Fore.GREEN}Probable Risk"
        )
        print(f"\n{Fore.YELLOW}PHISHING DETECTION REPORT")
        print(f"{Fore.CYAN}Total Suspicion Score: {self.suspicious_score}")
        print(f"{Fore.MAGENTA}Conclusion: {risk_level}\n")
        
        print(f"{Fore.BLUE}Reasons for the Score:")
        for key, value in self.results.items():
            if value:
                print(f"- {key.replace('_', ' ').title()}: {value}")

if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] in ('-h', '--help'):
        display_help()
        sys.exit(0)
    elif len(sys.argv) != 2:
        print(f"{Fore.RED}Usage: python spam.py <email_file.eml>")
        sys.exit(1)
    
    display_logo()
    detector = PhishingDetector(sys.argv[1])
    detector.analyze_email()
