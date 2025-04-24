#!/usr/bin/env python3
"""
scanner.py - Core scanning module for the Web Security Analyzer
This module contains functions to perform various security checks on web applications.
"""

import requests
from bs4 import BeautifulSoup
import urllib.parse
from enum import Enum
import time
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Define vulnerability severity levels
class Severity(Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

# Timeout for requests
REQUEST_TIMEOUT = 10

# Common paths for directory enumeration
COMMON_PATHS = [
    "/admin", "/login", "/wp-admin", "/administrator", "/phpmyadmin", 
    "/backup", "/config", "/db", "/log", "/logs", "/tmp", "/temp", 
    "/test", "/settings", "/setup", "/install", "/admin.php",
    "/.git", "/.env", "/api", "/api/v1", "/api/v2", "/console",
    "/dashboard", "/.htaccess", "/.htpasswd", "/web.config",
    "/backup.sql", "/database.sql", "/user", "/users", "/password",
    "/passwords", "/private", "/secret"
]

# Common security headers to check
SECURITY_HEADERS = {
    "X-Frame-Options": {
        "present": ["DENY", "SAMEORIGIN"],
        "severity": Severity.MEDIUM,
        "message": "Controls whether a browser should be allowed to render a page in a <frame> or <iframe>."
    },
    "Strict-Transport-Security": {
        "present": True,
        "severity": Severity.HIGH,
        "message": "Enforces secure (HTTPS) connections to the server."
    },
    "Content-Security-Policy": {
        "present": True,
        "severity": Severity.MEDIUM,
        "message": "Helps prevent Cross-Site Scripting (XSS) and data injection attacks."
    },
    "X-Content-Type-Options": {
        "present": ["nosniff"],
        "severity": Severity.MEDIUM,
        "message": "Prevents browsers from MIME-sniffing a response away from the declared content-type."
    },
    "X-XSS-Protection": {
        "present": ["1", "1; mode=block"],
        "severity": Severity.MEDIUM,
        "message": "Enables the Cross-site scripting (XSS) filter in browsers."
    },
    "Referrer-Policy": {
        "present": True,
        "severity": Severity.LOW,
        "message": "Controls how much referrer information should be included with requests."
    }
}

def normalize_url(url):
    """
    Normalize a URL by ensuring it has the correct format.
    
    Args:
        url (str): URL to normalize
        
    Returns:
        str: Normalized URL
    """
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    # Remove trailing slash if present
    if url.endswith('/'):
        url = url[:-1]
        
    return url

def make_request(url, path="", method="GET", data=None, headers=None):
    """
    Make an HTTP request with error handling.
    
    Args:
        url (str): Base URL
        path (str): Path to append to the URL
        method (str): HTTP method (GET, POST, etc.)
        data (dict): Data to send with the request
        headers (dict): HTTP headers
        
    Returns:
        requests.Response or None: Response object or None if the request failed
    """
    full_url = url
    if path:
        full_url = urllib.parse.urljoin(url + '/', path.lstrip('/'))
    
    if not headers:
        headers = {
            'User-Agent': 'WebSecAnalyzer/1.0 (Security Testing Tool)'
        }
    
    try:
        if method.upper() == "GET":
            response = requests.get(full_url, headers=headers, timeout=REQUEST_TIMEOUT)
        elif method.upper() == "POST":
            response = requests.post(full_url, data=data, headers=headers, timeout=REQUEST_TIMEOUT)
        else:
            logger.error(f"Unsupported HTTP method: {method}")
            return None
            
        return response
    except requests.exceptions.RequestException as e:
        logger.error(f"Request failed for {full_url}: {str(e)}")
        return None

def enumerate_directories(url):
    """
    Enumerate common directories and files on the target website.
    
    Args:
        url (str): Target URL
        
    Returns:
        list: Dictionary with information about accessible paths
    """
    url = normalize_url(url)
    results = []
    
    logger.info(f"Starting directory enumeration for {url}")
    
    for path in COMMON_PATHS:
        response = make_request(url, path)
        if response and response.status_code == 200:
            results.append({
                "path": path,
                "status_code": response.status_code,
                "content_length": len(response.content),
                "severity": Severity.MEDIUM.value,
                "message": f"Potentially sensitive directory or file found: {path}"
            })
        
        # Small delay to avoid overwhelming the server
        time.sleep(0.2)
    
    logger.info(f"Directory enumeration completed. Found {len(results)} accessible paths.")
    return results

def analyze_headers(url):
    """
    Analyze HTTP headers for security misconfigurations.
    
    Args:
        url (str): Target URL
        
    Returns:
        dict: Information about security headers
    """
    url = normalize_url(url)
    results = []
    
    logger.info(f"Starting HTTP header analysis for {url}")
    
    response = make_request(url)
    if not response:
        logger.error(f"Failed to retrieve headers for {url}")
        return results
    
    # Check for each security header
    for header, config in SECURITY_HEADERS.items():
        header_value = response.headers.get(header)
        
        if header_value is None:
            results.append({
                "header": header,
                "value": "Missing",
                "status": "Missing",
                "severity": config["severity"].value,
                "message": f"Missing security header: {header}. {config['message']}"
            })
        else:
            # Check if the header has expected values
            if isinstance(config["present"], list) and header_value not in config["present"]:
                results.append({
                    "header": header,
                    "value": header_value,
                    "status": "Misconfigured",
                    "severity": config["severity"].value,
                    "message": f"Security header {header} has value '{header_value}' but expected one of {config['present']}. {config['message']}"
                })
            else:
                results.append({
                    "header": header,
                    "value": header_value,
                    "status": "Present",
                    "severity": Severity.INFO.value,
                    "message": f"Security header is properly configured: {header}"
                })
    
    logger.info(f"HTTP header analysis completed. Found {len([r for r in results if r['status'] != 'Present'])} issues.")
    return results

def analyze_robots_txt(url):
    """
    Analyze robots.txt file for interesting paths.
    
    Args:
        url (str): Target URL
        
    Returns:
        list: Information about disallowed paths
    """
    url = normalize_url(url)
    results = []
    
    logger.info(f"Analyzing robots.txt for {url}")
    
    response = make_request(url, "robots.txt")
    if not response or response.status_code != 200:
        logger.info(f"No robots.txt found at {url}/robots.txt")
        return [{
            "status": "Not Found",
            "severity": Severity.INFO.value,
            "message": "No robots.txt file found."
        }]
    
    disallowed_paths = []
    lines = response.text.splitlines()
    
    for line in lines:
        line = line.strip()
        if line.lower().startswith('disallow:'):
            path = line[len('disallow:'):].strip()
            if path:
                disallowed_paths.append(path)
                results.append({
                    "path": path,
                    "status": "Disallowed",
                    "severity": Severity.LOW.value,
                    "message": f"Path found in robots.txt: {path}. May contain sensitive information."
                })
    
    if not disallowed_paths:
        results.append({
            "status": "Empty",
            "severity": Severity.INFO.value,
            "message": "robots.txt file exists but no disallowed paths found."
        })
    
    logger.info(f"robots.txt analysis completed. Found {len(disallowed_paths)} disallowed paths.")
    return results

def scan_forms(url):
    """
    Scan HTML forms for security issues.
    
    Args:
        url (str): Target URL
        
    Returns:
        list: Information about forms and their security issues
    """
    url = normalize_url(url)
    results = []
    
    logger.info(f"Scanning forms on {url}")
    
    response = make_request(url)
    if not response or response.status_code != 200:
        logger.error(f"Failed to retrieve content from {url}")
        return results
    
    try:
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        
        if not forms:
            logger.info(f"No forms found on {url}")
            return [{
                "status": "No Forms",
                "severity": Severity.INFO.value,
                "message": "No HTML forms found on the page."
            }]
        
        for i, form in enumerate(forms):
            form_info = {
                "form_index": i + 1,
                "action": form.get('action', ''),
                "method": form.get('method', 'GET').upper(),
                "inputs": []
            }
            
            # Get all input fields
            for inp in form.find_all(['input', 'textarea']):
                input_type = inp.get('type', 'text')
                name = inp.get('name', '')
                
                form_info["inputs"].append({
                    "name": name,
                    "type": input_type,
                })
                
                # Check for password fields with autocomplete
                if input_type == 'password' and inp.get('autocomplete') != 'off':
                    results.append({
                        "form_index": i + 1,
                        "issue": "Autocomplete not disabled for password field",
                        "severity": Severity.LOW.value,
                        "message": f"Password field '{name}' does not have autocomplete disabled."
                    })
            
            # Check if form submits over HTTPS
            action_url = form_info["action"]
            if action_url:
                if action_url.startswith('http:'):
                    results.append({
                        "form_index": i + 1,
                        "issue": "Insecure Form Submission",
                        "severity": Severity.HIGH.value,
                        "message": f"Form submits data over unencrypted HTTP to {action_url}"
                    })
                elif not action_url.startswith('https:') and not url.startswith('https:'):
                    results.append({
                        "form_index": i + 1,
                        "issue": "Potentially Insecure Form Submission",
                        "severity": Severity.MEDIUM.value,
                        "message": f"Form uses relative action on non-HTTPS page: {action_url}"
                    })
            
            # Check for CSRF protection
            csrf_field = None
            for inp in form.find_all('input', {'type': 'hidden'}):
                if any(token in inp.get('name', '').lower() for token in ['csrf', 'token', 'nonce']):
                    csrf_field = inp.get('name')
                    break
                    
            if not csrf_field:
                results.append({
                    "form_index": i + 1,
                    "issue": "Possible CSRF Vulnerability",
                    "severity": Severity.MEDIUM.value,
                    "message": "No apparent CSRF token found in the form."
                })
        
        logger.info(f"Form scanning completed. Found {len(forms)} forms with {len(results)} potential issues.")
        return results
    
    except Exception as e:
        logger.error(f"Error scanning forms: {str(e)}")
        return [{
            "status": "Error",
            "severity": Severity.INFO.value,
            "message": f"Error scanning forms: {str(e)}"
        }]

def run_scan(url):
    """
    Run a comprehensive scan on the target URL.
    
    Args:
        url (str): Target URL
        
    Returns:
        dict: Complete scan results
    """
    url = normalize_url(url)
    logger.info(f"Starting comprehensive scan for {url}")
    
    results = {
        "target_url": url,
        "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "directory_enumeration": [],
        "header_analysis": [],
        "robots_txt_analysis": [],
        "form_analysis": []
    }
    
    try:
        # Check if the website is reachable
        response = make_request(url)
        if not response:
            logger.error(f"Target {url} is not reachable")
            return {
                "target_url": url,
                "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "error": "Target website is not reachable"
            }
        
        # Perform the different scans
        results["header_analysis"] = analyze_headers(url)
        results["robots_txt_analysis"] = analyze_robots_txt(url)
        results["directory_enumeration"] = enumerate_directories(url)
        results["form_analysis"] = scan_forms(url)
        
        logger.info(f"Scan completed for {url}")
        return results
    
    except Exception as e:
        logger.error(f"Error during scan: {str(e)}")
        return {
            "target_url": url,
            "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "error": f"Error during scan: {str(e)}"
        }