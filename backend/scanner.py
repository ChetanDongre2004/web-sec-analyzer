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
from threading import Lock

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

# Shared dictionary to track scan progress
scan_progress = {}
progress_lock = Lock()

def update_progress(scan_id, progress, status):
    """
    Update the progress and status of a scan.

    Args:
        scan_id (str): Unique identifier for the scan.
        progress (int): Progress percentage (0-100).
        status (str): Current status of the scan (e.g., 'running', 'completed').
    """
    with progress_lock:
        scan_progress[scan_id] = {
            "progress": progress,
            "status": status
        }

def get_progress(scan_id):
    """
    Retrieve the progress and status of a scan.

    Args:
        scan_id (str): Unique identifier for the scan.

    Returns:
        dict: Progress and status of the scan.
    """
    with progress_lock:
        return scan_progress.get(scan_id, {"progress": 0, "status": "pending"})

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
                "severity": Severity.HIGH.value,
                "description": "The directory or file is accessible and may contain sensitive information.",
                "solution": [
                    "Restrict access to this directory using authentication mechanisms.",
                    "If the directory is not needed, remove it from the server.",
                    "Ensure proper permissions are set to prevent unauthorized access."
                ]
            })
        
        # Small delay to avoid overwhelming the server
        time.sleep(0.2)
    
    logger.info(f"Directory enumeration completed. Found {len(results)} accessible paths.")
    return results

# Add detailed descriptions, solutions, and severity levels to the vulnerability data returned by the analyze_headers function.
def analyze_headers(url):
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
                "description": f"The {header} header is missing. {config['message']}",
                "message": config["message"],
                "solution": [
                    f"Add the {header} header to your server configuration.",
                    f"Set the {header} header value to one of the recommended values: {config['present']}"
                ]
            })
        else:
            if isinstance(config["present"], list) and header_value not in config["present"]:
                results.append({
                    "header": header,
                    "value": header_value,
                    "status": "Misconfigured",
                    "severity": config["severity"].value,
                    "description": f"The {header} header is misconfigured. {config['message']}",
                    "solution": [
                        f"Update the {header} header value to one of the recommended values: {config['present']}"
                    ]
                })

    logger.info(f"HTTP header analysis completed. Found {len([r for r in results if r['status'] != 'Present'])} issues.")
    return results

# Add detailed descriptions, solutions, and severity levels to the vulnerability data returned by the analyze_robots_txt function.
def analyze_robots_txt(url):
    url = normalize_url(url)
    results = []

    logger.info(f"Analyzing robots.txt for {url}")

    response = make_request(url, "robots.txt")
    if not response or response.status_code != 200:
        logger.info(f"No robots.txt found at {url}/robots.txt")
        return [{
            "status": "Not Found",
            "severity": Severity.INFO.value,
            "description": "The robots.txt file is missing. This file is used to provide instructions to web crawlers and can sometimes reveal sensitive paths.",
            "solution": [
                "If you do not want to expose sensitive paths, create a robots.txt file and configure it appropriately.",
                "Avoid including sensitive or critical paths in the robots.txt file."
            ]
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
                    "description": f"The path {path} is disallowed in robots.txt. This may indicate sensitive or restricted areas.",
                    "solution": [
                        "Ensure that sensitive paths are not exposed in the robots.txt file.",
                        "Use authentication or IP restrictions to secure sensitive paths."
                    ]
                })

    if not disallowed_paths:
        results.append({
            "status": "Empty",
            "severity": Severity.INFO.value,
            "description": "The robots.txt file exists but does not contain any disallowed paths.",
            "solution": [
                "Review the robots.txt file to ensure it does not unintentionally expose sensitive information."
            ]
        })

    logger.info(f"robots.txt analysis completed. Found {len(disallowed_paths)} disallowed paths.")
    return results

# Add detailed descriptions, solutions, and severity levels to the vulnerability data returned by the scan_forms function.
def scan_forms(url):
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
                "description": "No HTML forms were found on the page. This may indicate a static or non-interactive page.",
                "solution": [
                    "If forms are expected, ensure they are correctly implemented in the HTML."
                ]
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
                        "description": "Password fields with autocomplete enabled may expose sensitive information if the browser stores the credentials.",
                        "solution": [
                            "Set the autocomplete attribute to 'off' for password fields."
                        ]
                    })

            # Check if form submits over HTTPS
            action_url = form_info["action"]
            if action_url:
                if action_url.startswith('http:'):
                    results.append({
                        "form_index": i + 1,
                        "issue": "Insecure Form Submission",
                        "severity": Severity.HIGH.value,
                        "description": "The form submits data over an unencrypted HTTP connection, which can expose sensitive information to attackers.",
                        "solution": [
                            "Ensure that all forms submit data over HTTPS.",
                            "Obtain and configure an SSL/TLS certificate for your website."
                        ]
                    })
                elif not action_url.startswith('https:') and not url.startswith('https:'):
                    results.append({
                        "form_index": i + 1,
                        "issue": "Potentially Insecure Form Submission",
                        "severity": Severity.MEDIUM.value,
                        "description": "The form uses a relative action on a non-HTTPS page, which may lead to insecure submissions.",
                        "solution": [
                            "Ensure that the page and form action use HTTPS."
                        ]
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
                    "description": "The form does not appear to include a CSRF token, which may leave it vulnerable to cross-site request forgery attacks.",
                    "solution": [
                        "Implement CSRF protection by including a CSRF token in the form."
                    ]
                })

        logger.info(f"Form scanning completed. Found {len(forms)} forms with {len(results)} potential issues.")
        return results

    except Exception as e:
        logger.error(f"Error scanning forms: {str(e)}")
        return [{
            "status": "Error",
            "severity": Severity.INFO.value,
            "description": f"An error occurred while scanning forms: {str(e)}",
            "solution": [
                "Check the page structure and ensure it is accessible for scanning."
            ]
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

def run_scan_with_progress(scan_id, url):
    """
    Run a comprehensive scan with progress tracking.

    Args:
        scan_id (str): Unique identifier for the scan.
        url (str): Target URL.

    Returns:
        dict: Complete scan results.
    """
    update_progress(scan_id, 0, "running")

    results = {
        "target_url": url,
        "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "directory_enumeration": [],
        "header_analysis": [],
        "robots_txt_analysis": [],
        "form_analysis": []
    }

    try:
        # Perform the different scans with progress updates
        results["header_analysis"] = analyze_headers(url)
        update_progress(scan_id, 25, "running")

        results["robots_txt_analysis"] = analyze_robots_txt(url)
        update_progress(scan_id, 50, "running")

        results["directory_enumeration"] = enumerate_directories(url)
        update_progress(scan_id, 75, "running")

        results["form_analysis"] = scan_forms(url)
        update_progress(scan_id, 100, "completed")

        logger.info(f"Scan completed for {url}")
        return results

    except Exception as e:
        logger.error(f"Error during scan: {str(e)}")
        update_progress(scan_id, 100, "error")
        return {
            "target_url": url,
            "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "error": f"Error during scan: {str(e)}"
        }