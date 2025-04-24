#!/usr/bin/env python3
"""
utils.py - Utility functions for the Web Security Analyzer
This module contains helper functions used across the application.
"""

import uuid
import json
import threading
import time
from enum import Enum
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Dictionary to store scan results
SCAN_HISTORY = {}

# Dictionary to store running scans
ACTIVE_SCANS = {}

class ScanStatus(Enum):
    """Enum representing the status of a scan."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"

def generate_scan_id():
    """
    Generate a unique scan ID.
    
    Returns:
        str: A unique scan ID
    """
    return str(uuid.uuid4())

def save_scan_result(scan_id, result):
    """
    Save scan result to the scan history.
    
    Args:
        scan_id (str): The scan ID
        result (dict): The scan result
    """
    SCAN_HISTORY[scan_id] = {
        'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
        'result': result
    }
    
    # Clean up active scans
    if scan_id in ACTIVE_SCANS:
        del ACTIVE_SCANS[scan_id]
        
    logger.info(f"Scan {scan_id} completed and results saved")

def get_scan_status(scan_id):
    """
    Get the status and result of a scan.
    
    Args:
        scan_id (str): The scan ID
        
    Returns:
        dict: The scan status and result
    """
    # Check if the scan is still running
    if scan_id in ACTIVE_SCANS:
        return {
            'status': ACTIVE_SCANS[scan_id],
            'scan_id': scan_id
        }
    
    # Check if the scan has completed
    if scan_id in SCAN_HISTORY:
        return {
            'status': ScanStatus.COMPLETED.value,
            'scan_id': scan_id,
            'result': SCAN_HISTORY[scan_id]['result'],
            'timestamp': SCAN_HISTORY[scan_id]['timestamp']
        }
    
    # Scan not found
    return {
        'status': 'not_found',
        'scan_id': scan_id,
        'error': 'Scan not found'
    }

def start_scan_thread(scan_id, url, scanner_function):
    """
    Start a scan in a separate thread.
    
    Args:
        scan_id (str): The scan ID
        url (str): The target URL
        scanner_function (function): The function to run the scan
    """
    def run_scan_thread():
        try:
            ACTIVE_SCANS[scan_id] = ScanStatus.RUNNING.value
            logger.info(f"Starting scan {scan_id} for {url}")
            
            # Run the scan
            result = scanner_function(url)
            
            # Save the result
            save_scan_result(scan_id, result)
        except Exception as e:
            logger.error(f"Error in scan thread: {str(e)}")
            ACTIVE_SCANS[scan_id] = ScanStatus.FAILED.value
            SCAN_HISTORY[scan_id] = {
                'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
                'result': {
                    'error': f"Scan failed: {str(e)}"
                }
            }
    
    # Create and start the thread
    ACTIVE_SCANS[scan_id] = ScanStatus.PENDING.value
    scan_thread = threading.Thread(target=run_scan_thread)
    scan_thread.daemon = True
    scan_thread.start()
    
    logger.info(f"Scan thread started for scan {scan_id}")
    return scan_id

def validate_url(url):
    """
    Validate that the URL is in a proper format.
    
    Args:
        url (str): The URL to validate
        
    Returns:
        tuple: (bool, str) - (is_valid, error_message)
    """
    if not url:
        return False, "URL is required"
    
    if not isinstance(url, str):
        return False, "URL must be a string"
    
    if not url.startswith(('http://', 'https://')):
        # Try to add http:// and return as valid with a warning
        return True, "URL doesn't start with http:// or https://, http:// will be prepended"
    
    return True, ""

def serialize_scan_result(scan_result):
    """
    Serialize scan result to JSON-compatible format.
    
    Args:
        scan_result (dict): The scan result to serialize
        
    Returns:
        dict: JSON-compatible scan result
    """
    # Create a deep copy of the result
    serialized = json.loads(json.dumps(scan_result, default=lambda o: str(o)))
    return serialized