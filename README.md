# My PhishGuard
Built for Brainwave Matrix Solutions Internship - March 2025 by Nirpesh551

## What It Does
A Python tool to detect phishing URLs with advanced checks.

## Features
- Analyzes HTTPS, domains, keywords, domain age, and Google Safe Browsing.
- Scans multiple URLs at once.
- Shows a visual risk bar.
- Logs scan history.

## How to Run
1. Clone: `git clone https://github.com/Nirpesh551/Brainwave_Matrix_Intern.git`
2. Cd: `cd Brainwave_Matrix_Intern`
3. Env: `python3 -m venv myenv`
4. Activate: `source myenv/bin/activate`
5. Install: `pip install requests colorama python-whois`
6. Get your API key:
   - Go to [console.cloud.google.com](https://console.cloud.google.com).
   - Create a project, enable Safe Browsing API, and generate an API key.
   - Save it in `mykey.txt` in the project folder (or enter it when prompted).
7. Run: `python phishguard.py`

## Example
- `https://google.com` → Risk: 0 (Safe)
- `http://testsafebrowsing.appspot.com/s/phishing.html` → Risk: 50+ (Suspicious)

## Demo
![Batch Scan Demo](demo.jpg)
