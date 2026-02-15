import streamlit as st

import requests

import socket

import dns.resolver

import whois

import json

import pandas as pd

import plotly.express as px

import plotly.graph_objects as go

from datetime import datetime, timedelta

import time

import re

import subprocess

import threading

from concurrent.futures import ThreadPoolExecutor, as_completed

import hashlib

import base64

from io import BytesIO

import folium

from streamlit_folium import st_folium

from reportlab.lib.pagesizes import letter

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

from reportlab.lib.units import inch

from reportlab.lib import colors

import ssl

import concurrent.futures

from urllib.parse import urlparse

import warnings

import nmap # Make sure to import nmap

import ipaddress

warnings.filterwarnings('ignore')



# Configuration

st.set_page_config(

page_title="OSINT Automation Tool",

page_icon="🔍",

layout="wide",

initial_sidebar_state="expanded"

)



class OSINTAgent:

def __init__(self):

self.results = {}

self.risk_factors = {

'suspicious_tlds': ['.tk', '.ml', '.cf', '.ga', '.pw', '.bit'],

'suspicious_keywords': ['admin', 'test', 'dev', 'staging', 'temp', 'backup', 'old'],

'high_risk_ports': [22, 23, 135, 139, 445, 1433, 3389, 5432, 1521, 3306, 5984, 6379, 9200, 27017],

'cdn_providers': ['cloudflare', 'akamai', 'fastly', 'amazon', 'google'],

'common_ports': {

21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP',

110: 'POP3', 135: 'RPC', 139: 'NetBIOS', 143: 'IMAP', 443: 'HTTPS',

993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 3306: 'MySQL', 3389: 'RDP',

5432: 'PostgreSQL', 5984: 'CouchDB', 6379: 'Redis', 8080: 'HTTP-Alt',

8443: 'HTTPS-Alt', 9200: 'Elasticsearch', 27017: 'MongoDB'

}

}


# Initialize Nmap scanner with improved error handling

self.nmap_error = None

try:

self.nm = nmap.PortScanner()

self.nmap_available = True

except nmap.PortScannerError as e:

self.nmap_available = False

self.nmap_error = "Nmap is not installed or not in your system's PATH. Please see installation instructions below."

print(f"Nmap initialization error: {e}")

except Exception as e:

self.nmap_available = False

self.nmap_error = f"An unexpected error occurred with Nmap: {e}"

print(f"Nmap unexpected error: {e}")


def whois_lookup(self, domain):

"""Perform WHOIS lookup with enhanced error handling"""

try:

w = whois.whois(domain)


# Extract and clean data

creation_date = w.creation_date

if isinstance(creation_date, list):

creation_date = creation_date[0] if creation_date else None


expiration_date = w.expiration_date

if isinstance(expiration_date, list):

expiration_date = expiration_date[0] if expiration_date else None


updated_date = w.updated_date

if isinstance(updated_date, list):

updated_date = updated_date[0] if updated_date else None


registrar = w.registrar if hasattr(w, 'registrar') else 'Unknown'

name_servers = w.name_servers if hasattr(w, 'name_servers') else []


return {

'domain': domain,

'registrar': registrar,

'creation_date': creation_date,

'expiration_date': expiration_date,

'updated_date': updated_date,

'name_servers': name_servers,

'status': w.status if hasattr(w, 'status') else [],

'country': w.country if hasattr(w, 'country') else 'Unknown',

'organization': w.org if hasattr(w, 'org') else 'Unknown'

}

except Exception as e:

return {'error': f"WHOIS lookup failed: {str(e)}"}


def dns_lookup(self, domain):

"""Comprehensive DNS lookup"""

dns_records = {}

record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']


for record_type in record_types:

try:

answers = dns.resolver.resolve(domain, record_type)

dns_records[record_type] = [str(rdata) for rdata in answers]

except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, Exception):

dns_records[record_type] = []


return dns_records


def subdomain_finder(self, domain, wordlist=None):

"""Advanced subdomain enumeration"""

if wordlist is None:

wordlist = [

'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'api', 'cdn',

'blog', 'shop', 'secure', 'vpn', 'remote', 'backup', 'old', 'new',

'mobile', 'app', 'panel', 'dashboard', 'status', 'monitor', 'log',

'support', 'help', 'docs', 'wiki', 'forum', 'chat', 'beta', 'alpha'

]


subdomains = []


def check_subdomain(sub):

subdomain = f"{sub}.{domain}"

try:

socket.gethostbyname(subdomain)

return subdomain

except socket.gaierror:

return None


with ThreadPoolExecutor(max_workers=50) as executor:

future_to_sub = {executor.submit(check_subdomain, sub): sub for sub in wordlist}

for future in as_completed(future_to_sub):

result = future.result()

if result:

subdomains.append(result)


return sorted(subdomains)


def basic_port_scan(self, target, ports, timeout=1):

"""Basic port scanner using socket connections"""

open_ports = []


def scan_port(port):

try:

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

sock.settimeout(timeout)

result = sock.connect_ex((target, port))

sock.close()

if result == 0:

return port

except Exception:

pass

return None


with ThreadPoolExecutor(max_workers=100) as executor:

future_to_port = {executor.submit(scan_port, port): port for port in ports}

for future in as_completed(future_to_port):

result = future.result()

if result:

open_ports.append(result)


return sorted(open_ports)


def nmap_port_scan(self, target, scan_type='basic', port_range='1-1000'):

"""Advanced Nmap port scanning"""

if not self.nmap_available:

return {'error': self.nmap_error}


try:

# Validate if target is IP or domain

try:

ipaddress.ip_address(target)

scan_target = target

except ValueError:

# It's a domain, resolve to IP

scan_target = socket.gethostbyname(target)


scan_results = {

'target': target,

'ip': scan_target,

'scan_type': scan_type,

'open_ports': [],

'filtered_ports': [],

'closed_ports_count': 0,

'os_detection': {},

'service_detection': {},

'scan_stats': {}

}


# Different scan types using keyword arguments for clarity

if scan_type == 'stealth':

# SYN stealth scan - may require sudo/admin privileges

self.nm.scan(hosts=scan_target, ports=port_range, arguments='-sS -T4 -f')

elif scan_type == 'service':

# Service version detection

self.nm.scan(hosts=scan_target, ports=port_range, arguments='-sV -T4')

elif scan_type == 'os':

# OS detection - may require sudo/admin privileges

self.nm.scan(hosts=scan_target, ports=port_range, arguments='-O -T4')

elif scan_type == 'comprehensive':

# Comprehensive scan - may require sudo/admin privileges

self.nm.scan(hosts=scan_target, ports=port_range, arguments='-sS -sV -O -A -T4')

else: # 'basic'

# Basic TCP connect scan

self.nm.scan(hosts=scan_target, ports=port_range, arguments='-sT -T4')


# Process results

if scan_target in self.nm.all_hosts():

host_info = self.nm[scan_target]


# Get scan statistics

if self.nm.scanstats():

scan_results['scan_stats'] = {

'scan_time': self.nm.scanstats().get('timestr', 'N/A'),

'total_time': self.nm.scanstats().get('elapsed', 'N/A'),

'hosts_up': self.nm.scanstats().get('uphosts', 'N/A'),

'hosts_down': self.nm.scanstats().get('downhosts', 'N/A')

}


# Process port information

for protocol in host_info.all_protocols():

ports = host_info[protocol].keys()

for port in ports:

port_info = host_info[protocol][port]

port_data = {

'port': port,

'protocol': protocol,

'state': port_info['state'],

'service': port_info.get('name', 'unknown'),

'version': port_info.get('version', ''),

'product': port_info.get('product', ''),

'extrainfo': port_info.get('extrainfo', ''),

'reason': port_info.get('reason', ''),

'conf': port_info.get('conf', '')

}


if port_info['state'] == 'open':

scan_results['open_ports'].append(port_data)

elif port_info['state'] == 'filtered':

scan_results['filtered_ports'].append(port_data)

else:

scan_results['closed_ports_count'] += 1


# OS detection results

if 'osmatch' in host_info and host_info['osmatch']:

scan_results['os_detection'] = {

'os_classes': host_info.get('osclass', []),

'os_matches': host_info.get('osmatch', [])

}


# Service detection summary

scan_results['service_detection'] = {

'services_found': len([p for p in scan_results['open_ports'] if p['service'] != 'unknown']),

'unique_services': list(set([p['service'] for p in scan_results['open_ports']]))

}

else:

return {'error': f"Nmap scan failed for {scan_target}. Host may be down or blocking scans."}


return scan_results


except Exception as e:

return {'error': f"Nmap scan failed: {str(e)}"}


def analyze_port_security(self, port_scan_results):

"""Analyze port scan results for security implications"""

security_analysis = {

'high_risk_ports': [],

'medium_risk_ports': [],

'low_risk_ports': [],

'security_score': 100,

'recommendations': []

}


if 'open_ports' not in port_scan_results or 'error' in port_scan_results:

return security_analysis


for port_data in port_scan_results['open_ports']:

port = port_data['port']

service = port_data['service']

version = port_data.get('version', '')


risk_level = 'low'

risk_points = 0


# Check against high-risk ports

if port in self.risk_factors['high_risk_ports']:

risk_level = 'high'

risk_points = 20

security_analysis['high_risk_ports'].append({

'port': port,

'service': service,

'version': version,

'risk_reason': f'Port {port} ({service}) is commonly targeted by attackers'

})


# Check for dangerous services

elif service.lower() in ['telnet', 'ftp', 'rsh', 'rlogin']:

risk_level = 'high'

risk_points = 15

security_analysis['high_risk_ports'].append({

'port': port,

'service': service,

'version': version,

'risk_reason': f'{service} uses unencrypted communication'

})


# Check for database services

elif service.lower() in ['mysql', 'postgresql', 'mssql', 'mongodb', 'redis', 'elasticsearch']:

risk_level = 'medium'

risk_points = 10

security_analysis['medium_risk_ports'].append({

'port': port,

'service': service,

'version': version,

'risk_reason': f'Database service {service} exposed to internet'

})


# Check for admin/management interfaces

elif service.lower() in ['http', 'https'] and port in [8080, 8443, 9090, 9443]:

risk_level = 'medium'

risk_points = 8

security_analysis['medium_risk_ports'].append({

'port': port,

'service': service,

'version': version,

'risk_reason': f'Potential admin interface on port {port}'

})


else:

security_analysis['low_risk_ports'].append({

'port': port,

'service': service,

'version': version,

'risk_reason': 'Standard service - monitor for vulnerabilities'

})


security_analysis['security_score'] -= risk_points


# Ensure score doesn't go below 0

security_analysis['security_score'] = max(0, security_analysis['security_score'])


# Generate recommendations

if security_analysis['high_risk_ports']:

security_analysis['recommendations'].append('🔴 Close or secure high-risk ports immediately')

if security_analysis['medium_risk_ports']:

security_analysis['recommendations'].append('🟡 Review medium-risk services and implement additional security measures')

if len(port_scan_results['open_ports']) > 10:

security_analysis['recommendations'].append('📊 Consider reducing attack surface by closing unnecessary services')


security_analysis['recommendations'].extend([

'🛡️ Implement a Web Application Firewall (WAF)',

'🔄 Regular security updates and patches',

'👥 Restrict access using IP whitelisting where possible',

'📝 Enable comprehensive logging and monitoring'

])


return security_analysis


def ip_geolocation(self, ip):

"""Get IP geolocation information"""

try:

response = requests.get(f'http://ipinfo.io/{ip}/json', timeout=10)

if response.status_code == 200:

data = response.json()

return {

'ip': ip,

'city': data.get('city', 'Unknown'),

'region': data.get('region', 'Unknown'),

'country': data.get('country', 'Unknown'),

'location': data.get('loc', '0,0'),

'organization': data.get('org', 'Unknown'),

'timezone': data.get('timezone', 'Unknown')

}

except Exception as e:

st.error(f"Geolocation lookup failed: {str(e)}")


return {'error': 'Geolocation failed'}


def calculate_risk_score(self, domain_data, port_scan_results=None):

"""Advanced risk scoring algorithm"""

risk_score = 0

risk_details = []


# Domain age analysis

if 'creation_date' in domain_data and domain_data['creation_date']:

try:

if isinstance(domain_data['creation_date'], str):

creation_date = datetime.strptime(domain_data['creation_date'][:10], '%Y-%m-%d')

else:

creation_date = domain_data['creation_date']


domain_age = (datetime.now() - creation_date).days

if domain_age < 30:

risk_score += 40

risk_details.append("Very new domain (< 30 days)")

elif domain_age < 365:

risk_score += 20

risk_details.append("Recently created domain (< 1 year)")

except:

risk_score += 10

risk_details.append("Cannot determine domain age")


# TLD analysis

domain_name = domain_data.get('domain', '')

for suspicious_tld in self.risk_factors['suspicious_tlds']:

if domain_name.endswith(suspicious_tld):

risk_score += 30

risk_details.append(f"Suspicious TLD: {suspicious_tld}")

break


# Registrar analysis

registrar = domain_data.get('registrar', '').lower()

if 'unknown' in registrar or not registrar:

risk_score += 15

risk_details.append("Unknown or suspicious registrar")


# Privacy protection

org = domain_data.get('organization', '').lower()

if 'privacy' in org or 'protected' in org or 'whoisguard' in org:

risk_score += 10

risk_details.append("Domain privacy protection enabled")


# Port scan risk factors

if port_scan_results and 'open_ports' in port_scan_results:

high_risk_ports_found = [

p for p in port_scan_results['open_ports']

if p['port'] in self.risk_factors['high_risk_ports']

]

if high_risk_ports_found:

risk_score += 25

risk_details.append(f"High-risk ports exposed: {[p['port'] for p in high_risk_ports_found]}")


# Too many open ports

if len(port_scan_results['open_ports']) > 15:

risk_score += 15

risk_details.append("Large attack surface (many open ports)")


return min(risk_score, 100), risk_details


def flag_suspicious_subdomains(self, subdomains):

"""Flag potentially suspicious subdomains"""

suspicious = []


for subdomain in subdomains:

subdomain_lower = subdomain.lower()

for keyword in self.risk_factors['suspicious_keywords']:

if keyword in subdomain_lower:

suspicious.append({

'subdomain': subdomain,

'reason': f"Contains suspicious keyword: {keyword}",

'risk_level': 'Medium'

})

break


# Check for unusual patterns

if re.search(r'\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}', subdomain):

suspicious.append({

'subdomain': subdomain,

'reason': "Contains IP-like pattern",

'risk_level': 'High'

})


return suspicious


def generate_pdf_report(self, analysis_results):

"""Generate comprehensive PDF report"""

buffer = BytesIO()

doc = SimpleDocTemplate(buffer, pagesize=letter)

styles = getSampleStyleSheet()

story = []


# Title

title_style = ParagraphStyle(

'CustomTitle',

parent=styles['Heading1'],

fontSize=24,

alignment=1,

spaceAfter=30,

textColor=colors.darkblue

)

story.append(Paragraph("OSINT Automation Tool", title_style))

story.append(Spacer(1, 20))


# Executive Summary

story.append(Paragraph("Executive Summary", styles['Heading2']))

domain = analysis_results.get('domain', 'Unknown')

risk_score = analysis_results.get('risk_score', 0)


port_scan_summary = ""

if 'port_scan_results' in analysis_results:

port_results = analysis_results['port_scan_results']

open_ports_count = len(port_results.get('open_ports', []))

port_scan_summary = f"<br/>Open Ports Found: {open_ports_count}"


summary_text = f"""

Target Domain: {domain}<br/>

Risk Score: {risk_score}/100<br/>

Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br/>

Subdomains Found: {len(analysis_results.get('subdomains', []))}<br/>

Suspicious Subdomains: {len(analysis_results.get('suspicious_subdomains', []))}{port_scan_summary}

"""

story.append(Paragraph(summary_text, styles['Normal']))

story.append(Spacer(1, 20))


# Port Scan Results Section

if 'port_scan_results' in analysis_results and 'open_ports' in analysis_results['port_scan_results']:

story.append(Paragraph("Port Scan Results", styles['Heading2']))


port_results = analysis_results['port_scan_results']

port_table_data = [['Port', 'Protocol', 'Service', 'State', 'Version']]


for port_info in port_results['open_ports'][:20]: # Limit to first 20

port_table_data.append([

str(port_info['port']),

port_info['protocol'],

port_info['service'],

port_info['state'],

port_info.get('version', 'N/A')[:30] # Truncate version info

])


port_table = Table(port_table_data)

port_table.setStyle(TableStyle([

('BACKGROUND', (0, 0), (-1, 0), colors.grey),

('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),

('ALIGN', (0, 0), (-1, -1), 'CENTER'),

('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),

('FONTSIZE', (0, 0), (-1, 0), 12),

('BOTTOMPADDING', (0, 0), (-1, 0), 12),

('BACKGROUND', (0, 1), (-1, -1), colors.beige),

('GRID', (0, 0), (-1, -1), 1, colors.black)

]))

story.append(port_table)

story.append(Spacer(1, 20))


# WHOIS Information

if 'whois_data' in analysis_results:

story.append(Paragraph("WHOIS Information", styles['Heading2']))

whois_data = analysis_results['whois_data']

whois_table_data = [

['Field', 'Value'],

['Domain', whois_data.get('domain', 'N/A')],

['Registrar', whois_data.get('registrar', 'N/A')],

['Creation Date', str(whois_data.get('creation_date', 'N/A'))[:10]],

['Expiration Date', str(whois_data.get('expiration_date', 'N/A'))[:10]],

['Country', whois_data.get('country', 'N/A')]

]


whois_table = Table(whois_table_data)

whois_table.setStyle(TableStyle([

('BACKGROUND', (0, 0), (-1, 0), colors.grey),

('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),

('ALIGN', (0, 0), (-1, -1), 'CENTER'),

('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),

('FONTSIZE', (0, 0), (-1, 0), 14),

('BOTTOMPADDING', (0, 0), (-1, 0), 12),

('BACKGROUND', (0, 1), (-1, -1), colors.beige),

('GRID', (0, 0), (-1, -1), 1, colors.black)

]))

story.append(whois_table)

story.append(Spacer(1, 20))


doc.build(story)

buffer.seek(0)

return buffer


def create_geolocation_map(self, ip_locations):

"""Create interactive geolocation map"""

if not ip_locations:

return None


# Calculate center point

lats = []

lons = []


for location in ip_locations:

if 'location' in location and location['location'] != '0,0':

lat, lon = location['location'].split(',')

lats.append(float(lat))

lons.append(float(lon))


if not lats:

center_lat, center_lon = 39.8283, -98.5795 # Center of USA

else:

center_lat = sum(lats) / len(lats)

center_lon = sum(lons) / len(lons)


m = folium.Map(location=[center_lat, center_lon], zoom_start=4)


for location in ip_locations:

if 'location' in location and location['location'] != '0,0':

lat, lon = location['location'].split(',')

folium.Marker(

[float(lat), float(lon)],

popup=f"IP: {location.get('ip', 'Unknown')}<br>"

f"City: {location.get('city', 'Unknown')}<br>"

f"Country: {location.get('country', 'Unknown')}<br>"

f"Org: {location.get('organization', 'Unknown')}",

tooltip=location.get('ip', 'Unknown')

).add_to(m)


return m


def check_email_breaches_xposed(self, email):

"""Check an email against the free XposedOrNot API"""

try:


url = f"https://api.xposedornot.com/v1/check-email/{email}"


headers = {'User-Agent': 'AI-OSINT-Agent'}


response = requests.get(url, headers=headers)


if response.status_code == 200:

data = response.json()

st.json(data)


# This endpoint returns {'pwned': true/false}

if data.get('pwned') == True:

# 'pwned' is true, so breaches exist

return {'status': 'pwned', 'data': data}

elif data.get('pwned') == False:

# 'pwned' is false, so it's safe

return {'status': 'safe', 'data': 'No breaches found for this email.'}

else:

# This handles the "Unknown response" error we saw

return {'status': 'error', 'data': data.get('message', 'Unknown response structure')}


elif response.status_code == 404:

# 404 can also mean safe/not found

return {'status': 'safe', 'data': 'No breaches found for this email.'}


elif response.status_code == 429:

return {'status': 'error', 'data': 'API rate limit hit. Please wait a moment.'}


else:

return {'status': 'error', 'data': f'Error: {response.status_code} - {response.text}'}



except Exception as e:

return {'status': 'error', 'data': f"An exception occurred: {str(e)}"}



# Streamlit UI

def main():

st.title("🔍 OSINT Automation Tool")

st.markdown("**Enhanced with Advanced Port Scanning Capabilities**")

st.markdown("---")


# Initialize session state

if 'analysis_complete' not in st.session_state:

st.session_state.analysis_complete = False

if 'analysis_results' not in st.session_state:

st.session_state.analysis_results = {}


# Sidebar

st.sidebar.title("🛠️ Control Panel")

target_domain = st.sidebar.text_input("Enter Target Domain/IP:", placeholder="example.com or 192.168.1.1")


# Advanced options

st.sidebar.subheader("📊 Scan Options")

enable_subdomain_scan = st.sidebar.checkbox("Enable Subdomain Enumeration", True)

include_geolocation = st.sidebar.checkbox("Include IP Geolocation", True)


# Port scanning options

st.sidebar.subheader("🔌 Port Scanning")

enable_port_scan = st.sidebar.checkbox("Enable Port Scanning", True)


scan_method = "Nmap"

scan_type = "basic"

port_range = "1-1000"



if enable_port_scan:

scan_method = st.sidebar.selectbox(

"Scanning Method",

["Nmap", "Basic Socket Scan"]

)


if scan_method == "Nmap":

scan_type = st.sidebar.selectbox(

"Scan Type",

["basic", "stealth", "service", "os", "comprehensive"],

help="basic: Standard TCP scan | stealth: SYN scan (requires root/admin) | service: Service detection | os: OS detection (requires root/admin) | comprehensive: All features (requires root/admin)"

)

port_range = st.sidebar.text_input("Port Range", "1-1000", help="e.g., 1-1000, 80,443,22 or specific ports")

else: # Basic Socket Scan

common_ports_list = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1433, 3306, 3389, 5432, 8080, 8443]

port_range_list = st.sidebar.multiselect("Select Ports to Scan", common_ports_list, default=[22, 80, 443, 8080])



if st.sidebar.button("🚀 Start Analysis", type="primary"):

if target_domain:

agent = OSINTAgent()


# Progress tracking

progress_bar = st.progress(0)

status_text = st.empty()


with st.spinner('Initializing OSINT analysis...'):

results = {}


# Determine if target is IP or domain

try:

ipaddress.ip_address(target_domain)

is_ip = True

target_ip = target_domain

except ValueError:

is_ip = False

try:

target_ip = socket.gethostbyname(target_domain)

except Exception as e:

st.error(f"Could not resolve domain: {e}")

target_ip = None


# Step 1: WHOIS Lookup (only for domains)

if not is_ip:

status_text.text('Performing WHOIS lookup...')

progress_bar.progress(10)

results['whois_data'] = agent.whois_lookup(target_domain)

time.sleep(0.5)

else:

progress_bar.progress(10)


# Step 2: DNS Lookup (only for domains)

if not is_ip:

status_text.text('Performing DNS lookup...')

progress_bar.progress(20)

results['dns_records'] = agent.dns_lookup(target_domain)

time.sleep(0.5)

else:

progress_bar.progress(20)


# Step 3: Subdomain Enumeration (only for domains)

if enable_subdomain_scan and not is_ip:

status_text.text('Enumerating subdomains...')

progress_bar.progress(30)

results['subdomains'] = agent.subdomain_finder(target_domain)

progress_bar.progress(35)

else:

progress_bar.progress(35)


# Step 4: Port Scanning

if enable_port_scan and target_ip:

status_text.text('Performing port scan...')

progress_bar.progress(40)


if scan_method == "Nmap":

results['port_scan_results'] = agent.nmap_port_scan(target_ip, scan_type, port_range)

else: # Basic Socket Scan

open_ports = agent.basic_port_scan(target_ip, port_range_list)

results['port_scan_results'] = {

'target': target_domain,

'ip': target_ip,

'scan_type': 'basic_socket',

'open_ports': [{'port': p, 'protocol': 'tcp', 'state': 'open', 'service': agent.risk_factors['common_ports'].get(p, 'unknown')} for p in open_ports],

'scan_stats': {'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

}


progress_bar.progress(55)


# Port security analysis

if 'port_scan_results' in results and 'error' not in results['port_scan_results']:

status_text.text('Analyzing port security...')

results['port_security_analysis'] = agent.analyze_port_security(results['port_scan_results'])

progress_bar.progress(60)

else:

progress_bar.progress(60)


# Step 5: Risk Scoring

status_text.text('Calculating risk score...')

progress_bar.progress(70)

if not is_ip and 'whois_data' in results:

risk_score, risk_details = agent.calculate_risk_score(

results['whois_data'],

results.get('port_scan_results')

)

else:

# For IP addresses, base risk only on port scan results

risk_score, risk_details = 50, ["IP address analysis - limited domain information"]

if 'port_scan_results' in results:

port_risk_score, port_risk_details = agent.calculate_risk_score(

{}, results['port_scan_results']

)

risk_score += port_risk_score

risk_details.extend(port_risk_details)

risk_score = min(risk_score, 100)


results['risk_score'] = risk_score

results['risk_details'] = risk_details


# Step 6: Suspicious Subdomain Flagging

if enable_subdomain_scan and not is_ip and results.get('subdomains'):

status_text.text('Flagging suspicious subdomains...')

progress_bar.progress(80)

results['suspicious_subdomains'] = agent.flag_suspicious_subdomains(results['subdomains'])


# Step 7: IP Geolocation

if include_geolocation and target_ip:

status_text.text('Getting IP geolocation data...')

progress_bar.progress(90)

ip_locations = []


# Get geolocation for main IP

geo_data = agent.ip_geolocation(target_ip)

if 'error' not in geo_data:

ip_locations.append(geo_data)


# Get IPs from A records if domain scan

if not is_ip and 'dns_records' in results and 'A' in results['dns_records']:

for ip in results['dns_records']['A'][:5]: # Limit to first 5 IPs

if ip != target_ip:

geo_data = agent.ip_geolocation(ip)

if 'error' not in geo_data:

ip_locations.append(geo_data)


results['ip_locations'] = ip_locations


progress_bar.progress(100)

status_text.text('Analysis complete!')


results['domain'] = target_domain

results['target_ip'] = target_ip

results['is_ip_scan'] = is_ip

results['analysis_timestamp'] = datetime.now()


st.session_state.analysis_results = results

st.session_state.analysis_complete = True

else:

st.error("Please enter a domain name or IP address.")


st.sidebar.subheader("📧 Email Breach Check")

email_to_check = st.sidebar.text_input("Enter Email to Check:", key="email_check_input")

check_email_button = st.sidebar.button("Check Email", key="email_check_button")



# This handles the click for the *new* button

if check_email_button:

if not email_to_check:

st.error("Please enter an email address to check.")

else:

agent = OSINTAgent()

with st.spinner(f"Checking {email_to_check} against XposedOrNot..."):

breach_results = agent.check_email_breaches_xposed(email_to_check)


st.subheader(f"Breach Results for: {email_to_check}")


if breach_results['status'] == 'pwned':

st.error("🔴 This email was found in one or more data breaches.")


# Get the new data structure from the 'check-email' endpoint

breach_data = breach_results['data']

breach_count = breach_data.get('breaches_count', 'an unknown number of')

breach_list = breach_data.get('breaches_list', [])


st.write(f"**Found in {breach_count} breaches.**")


if breach_list:

st.write("**Breach Names:**")

# Loop through the simple list of names

for breach_name in breach_list:

st.warning(f"• {breach_name}")

st.markdown("---")


# Display results

if st.session_state.analysis_complete and st.session_state.analysis_results:

results = st.session_state.analysis_results


# Main dashboard

st.header("📊 Analysis Dashboard")


# Display target information

target_info = f"**Target:** {results['domain']}"

if results.get('target_ip') and results['domain'] != results['target_ip']:

target_info += f" → {results['target_ip']}"

st.markdown(target_info)


# Key metrics

col1, col2, col3, col4, col5 = st.columns(5)


with col1:

st.metric("Risk Score", f"{results.get('risk_score', 0)}/100")


with col2:

st.metric("Subdomains Found", len(results.get('subdomains', [])))


with col3:

st.metric("Suspicious Subdomains", len(results.get('suspicious_subdomains', [])))


with col4:

port_count = 0

if 'port_scan_results' in results and 'open_ports' in results['port_scan_results']:

port_count = len(results['port_scan_results']['open_ports'])

st.metric("Open Ports", port_count)


with col5:

st.metric("IP Locations", len(results.get('ip_locations', [])))


# Port Scan Results Section

if 'port_scan_results' in results:

if 'error' in results['port_scan_results']:

st.error(f"**Port Scan Error:** {results['port_scan_results']['error']}")

elif 'open_ports' in results['port_scan_results']:

st.subheader("🔌 Port Scan Results")


port_results = results['port_scan_results']


# Port scan summary

col1, col2 = st.columns([2, 1])


with col1:

if port_results['open_ports']:

port_df = pd.DataFrame(port_results['open_ports'])

service_counts = port_df['service'].value_counts().head(10)

fig_services = px.bar(

x=service_counts.values,

y=service_counts.index,

orientation='h',

title="Top Services Found",

labels={'x': 'Count', 'y': 'Service'}

)

st.plotly_chart(fig_services, use_container_width=True)

else:

st.info("No open ports found for the selected range.")


with col2:

st.write("**Scan Statistics:**")

scan_stats = port_results.get('scan_stats', {})

for key, value in scan_stats.items():

st.write(f"• **{key.replace('_', ' ').title()}:** {value}")


if 'service_detection' in port_results:

st.write(f"• **Services Identified:** {port_results['service_detection']['services_found']}")


# Detailed port table

st.subheader("📋 Open Ports Details")

if port_results['open_ports']:

ports_df = pd.DataFrame(port_results['open_ports'])

display_df = ports_df[['port', 'protocol', 'service', 'state']].copy()

if 'version' in ports_df.columns:

display_df['version'] = ports_df['version'].apply(lambda x: x[:50] + '...' if len(str(x)) > 50 else x)

st.dataframe(display_df, use_container_width=True)


# Port Security Analysis

if 'port_security_analysis' in results:

st.subheader("🛡️ Port Security Analysis")


security_analysis = results['port_security_analysis']


col1, col2 = st.columns([1, 2])


with col1:

security_score = security_analysis['security_score']

fig_security = go.Figure(go.Indicator(

mode = "gauge+number",

value = security_score,

domain = {'x': [0, 1], 'y': [0, 1]},

title = {'text': "Port Security Score"},

gauge = {

'axis': {'range': [None, 100]},

'bar': {'color': "darkblue"},

'steps': [

{'range': [0, 50], 'color': "red"},

{'range': [50, 80], 'color': "orange"},

{'range': [80, 100], 'color': "green"}

],

}

))

fig_security.update_layout(height=300)

st.plotly_chart(fig_security, use_container_width=True)


with col2:

st.write("**Security Recommendations:**")

for rec in security_analysis['recommendations'][:6]:

st.write(f"• {rec}")


if security_analysis['high_risk_ports']:

st.error("**🔴 High Risk Ports Detected:**")

for port in security_analysis['high_risk_ports']:

st.error(f"Port {port['port']} ({port['service']}) - {port['risk_reason']}")


if security_analysis['medium_risk_ports']:

st.warning("**🟡 Medium Risk Ports:**")

for port in security_analysis['medium_risk_ports'][:5]:

st.warning(f"Port {port['port']} ({port['service']}) - {port['risk_reason']}")



# Risk Distribution Chart

st.subheader("📈 Overall Risk Analysis")


col1, col2 = st.columns([1, 1])


with col1:

# Risk score gauge

fig_gauge = go.Figure(go.Indicator(

mode = "gauge+number",

value = results.get('risk_score', 0),

domain = {'x': [0, 1], 'y': [0, 1]},

title = {'text': "Overall Risk Score"},

gauge = {

'axis': {'range': [None, 100]},

'bar': {'color': "darkblue"},

'steps': [

{'range': [0, 25], 'color': "green"},

{'range': [25, 50], 'color': "yellow"},

{'range': [50, 75], 'color': "orange"},

{'range': [75, 100], 'color': "red"}

]

}

))

st.plotly_chart(fig_gauge, use_container_width=True)


with col2:

# Risk factors breakdown

if results.get('risk_details'):

risk_df = pd.DataFrame({

'Risk Factor': results['risk_details'],

'Count': [1] * len(results['risk_details'])

})

fig_risk = px.bar(

risk_df,

y='Risk Factor',

x='Count',

title="Risk Factors Identified",

orientation='h',

labels={'Count': ''}

)

fig_risk.update_layout(showlegend=False)

st.plotly_chart(fig_risk, use_container_width=True)


# Subdomain Analysis (only for domain scans)

if not results.get('is_ip_scan') and results.get('subdomains'):

st.subheader("🌐 Subdomain Analysis")


col1, col2 = st.columns([2, 1])


with col1:

# Subdomain bar chart

subdomain_data = results['subdomains'][:20] # Show top 20

if subdomain_data:

subdomain_df = pd.DataFrame({

'Subdomain': [s.replace(f".{results['domain']}", "") for s in subdomain_data],

'Count': [1] * len(subdomain_data)

})


fig_sub = px.bar(

subdomain_df,

y='Subdomain',

x='Count',

orientation='h',

title="Discovered Subdomains",

labels={'Count': ''}

)

st.plotly_chart(fig_sub, use_container_width=True)


with col2:

st.write("**Discovered Subdomains:**")

for subdomain in results['subdomains'][:10]: # Show first 10

st.write(f"• {subdomain}")


if len(results['subdomains']) > 10:

st.write(f"... and {len(results['subdomains']) - 10} more")


# Suspicious Subdomains Alert (only for domain scans)

if not results.get('is_ip_scan') and results.get('suspicious_subdomains'):

st.subheader("⚠️ Suspicious Subdomains")


for suspicious in results['suspicious_subdomains']:

alert_color = "error" if suspicious['risk_level'] == 'High' else "warning"

if alert_color == "error":

st.error(f"**{suspicious['subdomain']}** - {suspicious['reason']} (Risk: {suspicious['risk_level']})")

else:

st.warning(f"**{suspicious['subdomain']}** - {suspicious['reason']} (Risk: {suspicious['risk_level']})")


# WHOIS Timeline (only for domain scans)

if not results.get('is_ip_scan') and results.get('whois_data') and 'creation_date' in results['whois_data']:

st.subheader("📅 Domain Timeline")


whois_data = results['whois_data']

timeline_data = []


if whois_data.get('creation_date'):

timeline_data.append({

'Event': 'Domain Created',

'Date': whois_data['creation_date'],

'Type': 'Creation'

})


if whois_data.get('updated_date'):

timeline_data.append({

'Event': 'Last Updated',

'Date': whois_data['updated_date'],

'Type': 'Update'

})


if whois_data.get('expiration_date'):

timeline_data.append({

'Event': 'Expires',

'Date': whois_data['expiration_date'],

'Type': 'Expiration'

})


if timeline_data:

timeline_df = pd.DataFrame(timeline_data)

timeline_df['Date'] = pd.to_datetime(timeline_df['Date'], errors='coerce').dropna()


if not timeline_df.empty:

fig_timeline = px.scatter(

timeline_df,

x='Date',

y='Event',

color='Type',

title="Domain Lifecycle Events",

height=400

)

st.plotly_chart(fig_timeline, use_container_width=True)


# Geolocation Map

if results.get('ip_locations'):

st.subheader("🌍 IP Geolocation Map")

agent = OSINTAgent()

geo_map = agent.create_geolocation_map(results['ip_locations'])


if geo_map:

st_folium(geo_map, width=700, height=500)


# IP Details Table

st.subheader("📍 IP Location Details")

ip_df = pd.DataFrame(results['ip_locations'])

if not ip_df.empty:

st.dataframe(ip_df, use_container_width=True)


# Detailed Information Tabs

st.subheader("📋 Detailed Information")


tabs = ["Port Scan", "WHOIS Data", "DNS Records", "Subdomains", "Raw Data"]

tab_objects = st.tabs(tabs)


# Port Scan Tab

with tab_objects[0]:

if results.get('port_scan_results'):

port_results = results['port_scan_results']


if 'error' in port_results:

st.error(f"Port scan error: {port_results['error']}")

else:

col1, col2 = st.columns(2)


with col1:

st.write("**Scan Information:**")

st.write(f"• Target: {port_results.get('target', 'Unknown')}")

st.write(f"• IP: {port_results.get('ip', 'Unknown')}")

st.write(f"• Scan Type: {port_results.get('scan_type', 'Unknown')}")


if 'scan_stats' in port_results:

st.write("**Scan Statistics:**")

for key, value in port_results['scan_stats'].items():

st.write(f"• {key.replace('_', ' ').title()}: {value}")


with col2:

if 'service_detection' in port_results:

st.write("**Service Detection:**")

svc_det = port_results['service_detection']

st.write(f"• Services Found: {svc_det.get('services_found', 0)}")

st.write("• Unique Services:")

for service in svc_det.get('unique_services', [])[:10]:

st.write(f" - {service}")


# OS Detection Results

if 'os_detection' in port_results and port_results['os_detection'].get('os_matches'):

st.write("**OS Detection Results:**")

os_det = port_results['os_detection']

for match in os_det['os_matches'][:3]:

st.write(f"• {match.get('name', 'Unknown')} (Accuracy: {match.get('accuracy', 'Unknown')}%)")


# Detailed port information

if port_results.get('open_ports'):

st.write("**Open Ports Details:**")

ports_detail_df = pd.DataFrame(port_results['open_ports'])

st.dataframe(ports_detail_df, use_container_width=True)

else:

st.info("No port scan results available.")


# WHOIS Data Tab

with tab_objects[1]:

if not results.get('is_ip_scan') and results.get('whois_data'):

whois_data = results['whois_data']

if 'error' in whois_data:

st.error(f"WHOIS lookup error: {whois_data['error']}")

else:

for key, value in whois_data.items():

if key != 'error':

st.write(f"**{key.replace('_', ' ').title()}:** {value}")

else:

st.info("WHOIS data not available for IP address scans.")


# DNS Records Tab

with tab_objects[2]:

if not results.get('is_ip_scan') and results.get('dns_records'):

for record_type, records in results['dns_records'].items():

if records:

st.write(f"**{record_type} Records:**")

for record in records:

st.write(f" • {record}")

st.write("")

else:

st.info("DNS records not available for IP address scans.")


# Subdomains Tab

with tab_objects[3]:

if not results.get('is_ip_scan') and results.get('subdomains'):

st.write("**All Discovered Subdomains:**")

subdomain_df = pd.DataFrame({

'Subdomain': results['subdomains'],

})

st.dataframe(subdomain_df, use_container_width=True)

else:

st.info("Subdomain enumeration not available for IP address scans.")


# Raw Data Tab

with tab_objects[4]:

st.json(results, expanded=False)


# PDF Report Generation

st.subheader("📄 Generate Report")

if st.button("Generate PDF Report"):

agent = OSINTAgent()

pdf_buffer = agent.generate_pdf_report(results)


st.download_button(

label="📥 Download PDF Report",

data=pdf_buffer.getvalue(),

file_name=f"osint_report_{results['domain']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",

mime="application/pdf"

)


# Footer

st.markdown("---")





if __name__ == "__main__":

main()