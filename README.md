# KripyMailScore

Overview

Phishing Email Detector is a Python-based tool that analyzes email files (.eml) to detect potential phishing attempts. It checks various indicators such as spoofed senders, urgent language, suspicious attachments, hidden or shortened URLs, and generic greetings commonly used in phishing emails.

Features

Detects spoofed senders by analyzing email headers.

Identifies urgent language commonly used in phishing attempts.

Scans for suspicious links, including shortened or hidden URLs.

Checks for dangerous attachments (e.g., .exe, .zip, .js).

Assigns a suspicion score and provides a risk assessment.

Installation

This script requires Python 3 and several dependencies. Install the required packages using:

pip install -r requirements.txt

Usage

To run the script, use the following command:

python spam.py <email_file.eml>

Options

-h, --help : Display the help message.

Example

python spam.py phishing_email.eml

Output

The script will analyze the email and display a report, including:

Suspicion Score

Indicators found (e.g., spoofed sender, suspicious links, urgent language)

Final risk assessment: Maximum Risk, Possible Risk, or Probable Risk

Dependencies

This script requires the following Python libraries:

re

email

tldextract

requests

colorama

To install dependencies:

pip install tldextract requests colorama

License

This project is licensed under the MIT License.

Disclaimer

This tool is for educational and research purposes only. Always verify results manually before taking action.
