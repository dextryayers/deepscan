import requests
import dns.resolver
import socket
import concurrent.futures
import argparse
import json
import os
import time
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from collections import defaultdict
import tldextract
import ssl
import csv
from datetime import datetime

# Disable SSL Warnings
requests.packages.urllib3.disable_warnings()

# User-Agent for requests
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
}

# Common Subdomains (300+ entries)
COMMON_SUBDOMAINS = [
    'www', 'mail', 'ftp', 'webmail', 'smtp', 'pop', 'ns1', 'ns2', 'ns3', 'ns4',
    'blog', 'dev', 'test', 'staging', 'm', 'mobile', 'admin', 'secure', 'login',
    'vpn', 'api', 'app', 'cdn', 'static', 'img', 'images', 'download', 'upload',
    'support', 'forum', 'shop', 'store', 'wiki', 'status', 'portal', 'dashboard',
    # ... (keep the rest of your subdomains list)
]

# Common Ports for scanning
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 8080, 8443]

def get_args():
    parser = argparse.ArgumentParser(description="🚀 Advanced Subdomain & Port Scanner 🚀")
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g., example.com)")
    parser.add_argument("-o", "--output", help="Output file (JSON/CSV)")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Threads (default: 20)")
    parser.add_argument("-w", "--wordlist", help="Custom subdomain wordlist")
    parser.add_argument("-p", "--ports", help="Custom ports (e.g., '80,443,8080')")
    parser.add_argument("--deep-scan", action="store_true", help="Enable deep scanning")
    parser.add_argument("--scan-ports", action="store_true", help="Enable port scanning")
    parser.add_argument("--resolve-ip", action="store_true", help="Resolve IP for all subdomains")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    return parser.parse_args()

def load_wordlist(wordlist_path):
    if wordlist_path and os.path.exists(wordlist_path):
        with open(wordlist_path, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    return []

def get_subdomains_from_crt(domain):
    subdomains = set()
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(url, timeout=15, headers=HEADERS)
        if response.ok:
            data = response.json()
            for item in data:
                name = item['name_value']
                if '\n' in name:
                    for sub in name.split('\n'):
                        if sub.startswith('*.'):
                            subdomains.add(sub[2:])
                        else:
                            subdomains.add(sub)
                else:
                    if name.startswith('*.'):
                        subdomains.add(name[2:])
                    else:
                        subdomains.add(name)
    except Exception as e:
        if args.verbose:
            print(f"[!] crt.sh Error: {e}")
    return subdomains

def dns_query(subdomain, domain):
    full_domain = f"{subdomain}.{domain}"
    try:
        answers = dns.resolver.resolve(full_domain, 'A')
        return full_domain if answers else None
    except:
        return None

def check_port(ip, port, timeout=1):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            return port if result == 0 else None
    except:
        return None

def scan_ports(ip, ports, timeout=1):
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(check_port, ip, port, timeout): port for port in ports}
        for future in concurrent.futures.as_completed(futures):
            port = futures[future]
            if future.result():
                open_ports.append(port)
    return sorted(open_ports)

def get_http_info(subdomain_full, timeout=5):
    result = {
        'http_status': None,
        'https_status': None,
        'server': None,
        'title': None,
        'ip': None,
        'ssl_issuer': None
    }
    
    try:
        result['ip'] = socket.gethostbyname(subdomain_full)
    except:
        pass
    
    for scheme in ['http', 'https']:
        url = f"{scheme}://{subdomain_full}"
        try:
            response = requests.get(
                url,
                timeout=timeout,
                allow_redirects=True,
                headers=HEADERS,
                verify=False
            )
            result[f'{scheme}_status'] = response.status_code
            if scheme == 'https':
                result['server'] = response.headers.get('Server', '')
                try:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    title = soup.title.string if soup.title else ''
                    result['title'] = title.strip()[:100] if title else ''
                except:
                    pass
                try:
                    cert = ssl.get_server_certificate((subdomain_full, 443))
                    x509 = ssl.load_cert_x509(ssl.PEM_cert_to_DER_cert(cert))
                    result['ssl_issuer'] = x509.get_issuer().CN
                except:
                    pass
        except Exception as e:
            result[f'{scheme}_status'] = f"Error: {str(e)}"
    
    return result

def process_subdomain(subdomain, domain, ports=None):
    full_domain = f"{subdomain}.{domain}"
    result = {
        'subdomain': full_domain,
        'ip': None,
        'http_status': None,
        'https_status': None,
        'server': None,
        'title': None,
        'ssl_issuer': None,
        'open_ports': []
    }
    
    http_info = get_http_info(full_domain)
    result.update(http_info)
    
    if args.scan_ports and result['ip']:
        ports_to_scan = ports or COMMON_PORTS
        result['open_ports'] = scan_ports(result['ip'], ports_to_scan)
    
    return result

def print_result(result):
    status_http = result.get('http_status', 'N/A')
    status_https = result.get('https_status', 'N/A')
    ip = result.get('ip', 'N/A')
    server = result.get('server', 'N/A')
    title = result.get('title', 'N/A')
    ports = ', '.join(map(str, result.get('open_ports', []))) if result.get('open_ports') else 'None'
    
    print(f"[+] {result['subdomain']}")
    print(f"    IP: {ip}")
    print(f"    HTTP: {status_http} | HTTPS: {status_https}")
    print(f"    Server: {server} | Title: {title}")
    if args.scan_ports:
        print(f"    Open Ports: {ports}")
    print("-" * 50)

def save_results(results, output_file):
    if not output_file:
        return
    
    if output_file.endswith('.json'):
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=4)
    elif output_file.endswith('.csv'):
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Subdomain', 'IP', 'HTTP Status', 'HTTPS Status', 'Server', 'Title', 'Open Ports'])
            for res in results:
                writer.writerow([
                    res['subdomain'],
                    res.get('ip', ''),
                    res.get('http_status', ''),
                    res.get('https_status', ''),
                    res.get('server', ''),
                    res.get('title', ''),
                    ', '.join(map(str, res.get('open_ports', [])))
                ])

def main():
    global args
    args = get_args()
    
    extracted = tldextract.extract(args.domain)
    main_domain = f"{extracted.domain}.{extracted.suffix}"
    
    print(f"\n🔍 [DEEP SUBDOMAIN SCANNER BY: DextryAyers, V. 1.0] Target: {main_domain}")
    print(f"📌 Threads: {args.threads} | Port Scan: {'ON' if args.scan_ports else 'OFF'}")
    print("⏳ Scanning...\n")
    
    start_time = time.time()
    
    # Get subdomains from multiple sources
    subdomains = set()
    subdomains.update(get_subdomains_from_crt(main_domain))
    subdomains.update([f"{sub}.{main_domain}" for sub in COMMON_SUBDOMAINS])
    
    # Load custom wordlist if provided
    custom_wordlist = load_wordlist(args.wordlist) if args.wordlist else []
    if custom_wordlist:
        subdomains.update([f"{sub}.{main_domain}" for sub in custom_wordlist])
    
    # Process subdomains
    results = []
    ports_to_scan = list(map(int, args.ports.split(','))) if args.ports else COMMON_PORTS
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = []
        for sub in subdomains:
            sub_parts = sub.split('.')
            if len(sub_parts) > 2 and '.'.join(sub_parts[1:]) == main_domain:
                sub_name = sub_parts[0]
                futures.append(executor.submit(process_subdomain, sub_name, main_domain, ports_to_scan))
        
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result.get('ip') or result.get('http_status') or result.get('https_status'):
                results.append(result)
                print_result(result)
    
    # Save results
    if args.output:
        save_results(results, args.output)
        print(f"\n💾 Results saved to: {args.output}")
    
    elapsed_time = time.time() - start_time
    print(f"\n✅ Scan completed in {elapsed_time:.2f} seconds")
    print(f"📊 Total Subdomains Found: {len(results)}")
    print(f"byee....., Powered By : AniipID")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n❌ Scan interrupted by user. byee............")
    except Exception as e:
        print(f"\n❌ Error: {e}")
