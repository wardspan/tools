import whois
import requests
import re
import json
import os
import socket
from dns import resolver
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Get API keys from environment variables
virus_total_api_key = os.getenv('VIRUSTOTAL_API_KEY')
google_safe_browsing_api_key = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY')
abuseipdb_api_key = os.getenv('ABUSEIPDB_API_KEY')
urlscan_api_key = os.getenv('URLSCAN_API_KEY')
alienvault_api_key = os.getenv('ALIENVAULT_API_KEY')
shodan_api_key = os.getenv('SHODAN_API_KEY')
ipinfo_api_key = os.getenv('IPINFO_API_KEY')


#VirusTotal URL Safety Check
def check_virustotal(url):
    endpoint = "https://www.virustotal.com/vtapi/v2/url/report"
    params = {'apikey': virus_total_api_key, 'resource': url}
    
    try:
        response = requests.get(endpoint, params=params)
        if response.status_code == 200:
            try:
                result = response.json()
                if result['response_code'] == 1:
                    positives = result.get('positives', 0)
                    total = result.get('total', 0)
                    if positives > 0:
                        return f"VirusTotal: {positives} out of {total} engines flagged the URL as unsafe."
                    else:
                        return "VirusTotal: The URL is safe."
                else:
                    return "VirusTotal: URL not found in the database."
            except json.JSONDecodeError:
                return "VirusTotal: Failed to parse JSON response."
        else:
            return f"VirusTotal: Failed to fetch data. Status code: {response.status_code}"
    except requests.RequestException as e:
        return f"VirusTotal: An error occurred: {str(e)}"

#Google Safe Browsing API Check
def check_google_safebrowsing(url):
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={google_safe_browsing_api_key}"
    payload = {
        "client": {
            "clientId": "your_client_id",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": url}
            ]
        }
    }
    
    headers = {'Content-Type': 'application/json'}
    response = requests.post(endpoint, json=payload, headers=headers)
    
    if response.status_code == 200:
        result = response.json()
        if 'matches' in result:
            return "Google Safe Browsing: The URL is unsafe."
        else:
            return "Google Safe Browsing: The URL is safe."
    else:
        return f"Google Safe Browsing: Failed to fetch data. Status code: {response.status_code}"

#AbuseIPDB Check for Domain's IP
def check_abuseipdb(ip):
    endpoint = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        'Accept': 'application/json',
        'Key': abuseipdb_api_key
    }
    params = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }
    
    try:
        response = requests.get(endpoint, headers=headers, params=params)
        if response.status_code == 200:
            result = response.json()
            if result['data']['abuseConfidenceScore'] > 0:
                return f"AbuseIPDB: The IP address {ip} has an abuse confidence score of {result['data']['abuseConfidenceScore']}."
            else:
                return f"AbuseIPDB: The IP address {ip} is clean."
        else:
            return f"AbuseIPDB: Failed to fetch data. Status code: {response.status_code}"
    except requests.RequestException as e:
        return f"AbuseIPDB: An error occurred: {str(e)}"

# URLScan.io Check
def check_urlscan(url):
    endpoint = "https://urlscan.io/api/v1/scan/"
    headers = {
        'API-Key': urlscan_api_key,
        'Content-Type': 'application/json'
    }
    payload = {
        'url': url,
        'visibility': 'public'
    }
    
    try:
        response = requests.post(endpoint, json=payload, headers=headers)
        if response.status_code == 200:
            result = response.json()
            return f"URLScan.io: Scan initiated successfully. Visit {result.get('result')} for details."
        else:
            return f"URLScan.io: Failed to initiate scan. Status code: {response.status_code}"
    except requests.RequestException as e:
        return f"URLScan.io: An error occurred: {str(e)}"

# DNS Lookup
def dns_lookup(url):
    try:
        # Remove the "http" or "https" scheme from the URL
        domain = re.sub(r'^https?://', '', url)
        
        # Perform DNS resolution
        answers = resolver.resolve(domain, 'A')
        ips = [answer.address for answer in answers]
        return f"DNS Lookup: The domain {domain} resolved to IP addresses: {', '.join(ips)}"
    except Exception as e:
        return f"DNS Lookup: Failed to resolve domain {url}. Error: {str(e)}"
        
# AlienVault OTX API Check
def check_alienvault_otx(url):
    endpoint = f"https://otx.alienvault.com/api/v1/indicators/url/{url}/general"
    headers = {
        'X-OTX-API-KEY': 'your_alienvault_api_key'
    }
    
    try:
        response = requests.get(endpoint, headers=headers)
        if response.status_code == 200:
            result = response.json()
            if result['pulse_info']['count'] > 0:
                return f"AlienVault OTX: The URL is associated with {result['pulse_info']['count']} known malicious activities."
            else:
                return "AlienVault OTX: The URL is not associated with known malicious activities."
        else:
            return f"AlienVault OTX: Failed to fetch data. Status code: {response.status_code}"
    except requests.RequestException as e:
        return f"AlienVault OTX: An error occurred: {str(e)}"
    
# Whois Lookup for domain info
def whois_lookup(url):
    try:
        # Remove the "http" or "https" scheme from the URL
        domain = re.sub(r'^https?://', '', url)
        whois_info = whois.whois(domain)
        
        if whois_info:
            creation_date = whois_info.get('creation_date')
            expiration_date = whois_info.get('expiration_date')
            return f"Whois: Domain created on {creation_date}, expires on {expiration_date}."
        else:
            return "Whois: Failed to retrieve whois information."
    except Exception as e:
        return f"Whois: An error occurred: {str(e)}"
    
# IPinfo API Check
def check_ipinfo(ip):
    endpoint = f"https://ipinfo.io/{ip}/json"
    headers = {
        'Authorization': f'Bearer {os.getenv("IPINFO_API_KEY")}'
    }
    
    try:
        response = requests.get(endpoint, headers=headers)
        if response.status_code == 200:
            result = response.json()
            return (f"IPinfo: The IP {ip} is located in {result.get('city')}, "
                    f"{result.get('region')}, {result.get('country')}, hosted by {result.get('org')}.")
        else:
            return f"IPinfo: Failed to fetch data. Status code: {response.status_code}"
    except requests.RequestException as e:
        return f"IPinfo: An error occurred: {str(e)}"
    
# Shodan API Check
def check_shodan(ip):
    endpoint = f"https://api.shodan.io/shodan/host/{ip}?key={os.getenv('SHODAN_API_KEY')}"
    
    try:
        response = requests.get(endpoint)
        if response.status_code == 200:
            result = response.json()
            open_ports = result.get('ports', [])
            vulns = result.get('vulns', [])
            return (f"Shodan: The IP {ip} has the following open ports: {', '.join(map(str, open_ports))}. "
                    f"Vulnerabilities: {', '.join(vulns) if vulns else 'None'}")
        else:
            return f"Shodan: Failed to fetch data. Status code: {response.status_code}"
    except requests.RequestException as e:
        return f"Shodan: An error occurred: {str(e)}"
    
# Basic URL structure validation
def basic_url_validation(url):
    ip_pattern = re.compile(r'^(http[s]?:\/\/)?(\d{1,3}\.){3}\d{1,3}')
    if ip_pattern.match(url):
        return "Basic URL Check: The URL contains an IP address. Be cautious as this is often a sign of malicious intent."
    
    if len(url) > 100:
        return "Basic URL Check: The URL is unusually long. This may be a phishing attempt."
    
    return "Basic URL Check: No obvious structural issues detected."

# Main function to check URL using multiple methods
def check_url_safety():
    url = input("Enter the URL you want to check: ")

    print(basic_url_validation(url))
    print(check_virustotal(url))
    print(check_google_safebrowsing(url))
    print(dns_lookup(url))
    print(whois_lookup(url))
    
    # Get the domain's IP address and check with AbuseIPDB, IPinfo, and Shodan
    try:
        domain = re.sub(r'^https?://', '', url)
        ip = socket.gethostbyname(domain)
        print(f"Resolved IP: {ip}")
        print(check_abuseipdb(ip))
        print(check_ipinfo(ip))
        print(check_shodan(ip))
    except socket.gaierror:
        print(f"Failed to resolve IP for domain: {url}")

    print(check_urlscan(url))
    print(check_alienvault_otx(url))

# Call the function to check URL
check_url_safety()