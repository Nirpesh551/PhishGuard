import requests
import json
from colorama import Fore, Style, init
from urllib.parse import urlparse
import whois
from datetime import datetime
from time import sleep
import os

# Start colorama for colored output
init()

# Load API key from file
if os.path.exists("mykey.txt"):
    with open("mykey.txt", "r") as key_file:
        MY_API_KEY = key_file.read().strip()
else:
    MY_API_KEY = input(f"{Fore.YELLOW}Enter your Google Safe Browsing API key: {Style.RESET_ALL}")

# Phishing indicators
SHADY_TLDS = [".tk", ".ml", ".ga", ".xyz", ".top"]
SNEAKY_TERMS = ["login", "verify", "account", "secure", "bank"]
PAST_SCANS = []  # Track previous scans

def basic_url_check(url):
    """Check URL for basic phishing signs."""
    danger_level = 0
    issues = []
    url_bits = urlparse(url)

    if not url.startswith("https"):
        issues.append("Missing HTTPS")
        danger_level += 20
    if len(url) > 75:
        issues.append("URL too long")
        danger_level += 15
    for tld in SHADY_TLDS:
        if tld in url.lower():
            issues.append(f"Risky TLD: {tld}")
            danger_level += 25
    for term in SNEAKY_TERMS:
        if term in url.lower():
            issues.append(f"Suspicious term: {term}")
            danger_level += 20
    if url_bits.path in ["", "/"]:
        issues.append("No path detected")
        danger_level += 10

    return danger_level, issues

def domain_age_lookup(url):
    """Estimate domain age using WHOIS."""
    try:
        domain_name = urlparse(url).netloc
        domain_info = whois.whois(domain_name)
        start_date = domain_info.creation_date
        if isinstance(start_date, list):
            start_date = start_date[0]
        days_old = (datetime.now() - start_date).days
        if days_old < 30:
            return 25, f"New domain: {days_old} days"
        elif days_old < 90:
            return 15, f"Young domain: {days_old} days"
        return 0, f"Older domain: {days_old} days"
    except:
        return 0, "Age check failed"

def google_safe_check(url):
    """Query Google Safe Browsing API."""
    if MY_API_KEY == "put-your-key-here":
        return 0, f"{Fore.RED}No valid API key provided{Style.RESET_ALL}"
    data_to_send = {
        "client": {"clientId": "MyPhishGuard", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        response = requests.post(
            "https://safebrowsing.googleapis.com/v4/threatMatches:find",
            params={"key": MY_API_KEY},
            json=data_to_send
        )
        if "matches" in response.json():
            return 30, "Google flags it unsafe"
        return 0, "Google says it’s safe"
    except:
        return 0, f"{Fore.RED}Google check error{Style.RESET_ALL}"

def check_one_url(url):
    """Perform a full scan on a single URL."""
    print(f"{Fore.CYAN}{Style.BRIGHT}🔎 Scanning: {url}{Style.RESET_ALL}")
    total_risk = 0
    all_issues = []

    basic_risk, basic_issues = basic_url_check(url)
    total_risk += basic_risk
    all_issues += basic_issues

    age_risk, age_note = domain_age_lookup(url)
    total_risk += age_risk
    all_issues.append(age_note)

    google_risk, google_note = google_safe_check(url)
    total_risk += google_risk
    all_issues.append(google_note)

    total_risk = min(total_risk, 100)

    risk_bar = f"[{Fore.GREEN}{'■' * (total_risk // 10)}{Fore.RED}{'□' * (10 - total_risk // 10)}{Style.RESET_ALL}]"
    print(f"{Fore.YELLOW}Issues:{Style.RESET_ALL}")
    for issue in all_issues:
        print(f"  - {issue}")
    print(f"\n{Fore.GREEN}{Style.BRIGHT}Risk: {total_risk}/100 {risk_bar}{Style.RESET_ALL}")
    
    verdict = "✅ Safe" if total_risk <= 30 else "⚠️ Suspicious" if total_risk <= 60 else "🚨 Phishing"
    print(f"{Style.BRIGHT}Verdict:{Style.RESET_ALL} {Fore.GREEN if total_risk <= 30 else Fore.YELLOW if total_risk <= 60 else Fore.RED}{verdict}{Style.RESET_ALL}")

    PAST_SCANS.append({"url": url, "risk": total_risk, "notes": all_issues})

def check_multiple_urls(url_list):
    """Scan multiple URLs in a batch."""
    for url in url_list:
        check_one_url(url)
        sleep(1)  # Avoid API rate limits
    with open("my_scan_log.json", "w") as log_file:
        json.dump(PAST_SCANS, log_file, indent=2)
    print(f"{Fore.GREEN}Saved to my_scan_log.json{Style.RESET_ALL}")

def show_past_scans():
    """Display history of scans."""
    if not PAST_SCANS:
        print(f"{Fore.YELLOW}No scans yet{Style.RESET_ALL}")
        return
    print(f"{Fore.CYAN}{Style.BRIGHT}📋 Scan History:{Style.RESET_ALL}")
    for scan in PAST_SCANS:
        status = "Safe" if scan["risk"] <= 30 else "Suspicious" if scan["risk"] <= 60 else "Phishing"
        print(f" - {scan['url']} → Risk: {scan['risk']} ({status})")

# Start the program
print(f"{Fore.CYAN}{Style.BRIGHT}=== My PhishGuard - Nirpesh551 ==={Style.RESET_ALL}")
while True:
    print("\nOptions:")
    print("1. Scan a single URL")
    print("2. Scan multiple URLs (comma-separated)")
    print("3. View scan history")
    print("4. Exit")
    pick = input(f"{Fore.GREEN}Choose (1-4): {Style.RESET_ALL}")

    if pick == "1":
        url = input("Enter a URL: ")
        check_one_url(url)
    elif pick == "2":
        urls = input("Enter URLs (e.g., url1, url2): ").split(", ")
        check_multiple_urls(urls)
    elif pick == "3":
        show_past_scans()
    elif pick == "4":
        print(f"{Fore.GREEN}Exiting - stay safe!{Style.RESET_ALL}")
        break
    else:
        print(f"{Fore.RED}Please pick 1-4{Style.RESET_ALL}")
