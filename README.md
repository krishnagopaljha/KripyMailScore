# KripyMailScore

## Overview
Phishing Email Detector is a Python-based tool that analyzes email files (`.eml`) to detect potential phishing attempts. It checks various indicators such as spoofed senders, urgent language, suspicious attachments, hidden or shortened URLs, and generic greetings commonly used in phishing emails.

## Features
- Detects spoofed senders by analyzing email headers.
- Identifies urgent language commonly used in phishing attempts.
- Scans for suspicious links, including shortened or hidden URLs.
- Checks for dangerous attachments (e.g., `.exe`, `.zip`, `.js`).
- Assigns a suspicion score and provides a risk assessment.

## Installation
This script requires Python 3 and several dependencies. Install the required packages using:

```sh
pip3 install -r requirements.txt
```
Give the necessary executable permission by 

`chmod +x KripyMailScore.py` 

## Usage
To run the script use the following command:

```sh
python3 KripyMailScore.py example.eml
```
