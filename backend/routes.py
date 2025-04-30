#!/usr/bin/env python3
"""
routes.py - API routes for the Web Security Analyzer
This module defines the Flask API endpoints for the application.
"""

from flask import Blueprint, request, jsonify
import logging

from scanner import run_scan, run_scan_with_progress, get_progress
from utils import (
    generate_scan_id, 
    get_scan_status, 
    start_scan_thread, 
    validate_url,
    serialize_scan_result
)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Create a Blueprint for our API routes
api = Blueprint('api', __name__)

@api.route('/scan', methods=['POST'])
def start_scan():
    """
    Start a new vulnerability scan.
    
    Expects JSON body: {"url": "http://example.com"}
    Returns JSON with scan_id.
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'status': 'error',
                'message': 'Request body must be JSON'
            }), 400
        
        url = data.get('url')
        
        # Validate URL
        is_valid, message = validate_url(url)
        if not is_valid:
            return jsonify({
                'status': 'error',
                'message': message
            }), 400
        
        # Generate a unique scan ID
        scan_id = generate_scan_id()
        
        # Start the scan in a separate thread with progress tracking
        start_scan_thread(scan_id, url, lambda url: run_scan_with_progress(scan_id, url))
        
        return jsonify({
            'status': 'success',
            'scan_id': scan_id,
            'message': 'Scan started successfully'
        }), 202  # 202 Accepted
        
    except Exception as e:
        logger.error(f"Error starting scan: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Failed to start scan: {str(e)}'
        }), 500

@api.route('/scan/<scan_id>/progress', methods=['GET'])
def get_scan_progress(scan_id):
    """
    Get the progress of a scan.
    
    Returns JSON with scan progress percentage and status.
    """
    try:
        progress_info = get_progress(scan_id)
        
        if not progress_info:
            return jsonify({
                'status': 'error',
                'message': 'Scan ID not found or no progress information available'
            }), 404
            
        return jsonify({
            'status': 'success',
            'progress': progress_info.get('progress', 0),
            'scan_status': progress_info.get('status', 'pending')
        }), 200
        
    except Exception as e:
        logger.error(f"Error retrieving scan progress: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Failed to retrieve scan progress: {str(e)}'
        }), 500

@api.route('/scan/<scan_id>', methods=['GET'])
def get_scan_result(scan_id):
    """
    Get the status and result of a scan.
    
    Returns JSON with scan status and results if available.
    """
    try:
        scan_status = get_scan_status(scan_id)
        
        if scan_status.get('status') == 'not_found':
            return jsonify({
                'status': 'error',
                'message': 'Scan ID not found'
            }), 404
            
        return jsonify({
            'status': 'success',
            'scan': serialize_scan_result(scan_status)
        }), 200
        
    except Exception as e:
        logger.error(f"Error retrieving scan result: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Failed to retrieve scan result: {str(e)}'
        }), 500

@api.route('/scans', methods=['GET'])
def get_all_scans():
    """
    Get a list of all scan IDs.
    
    Returns JSON with a list of all scan IDs.
    """
    try:
        from utils import SCAN_HISTORY, ACTIVE_SCANS
        
        all_scan_ids = list(set(list(SCAN_HISTORY.keys()) + list(ACTIVE_SCANS.keys())))
        
        return jsonify({
            'status': 'success',
            'scan_ids': all_scan_ids,
            'count': len(all_scan_ids)
        }), 200
        
    except Exception as e:
        logger.error(f"Error retrieving all scan IDs: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Failed to retrieve scan IDs: {str(e)}'
        }), 500

@api.route('/health', methods=['GET'])
def health_check():
    """
    API health check endpoint.
    
    Returns a simple response to confirm the API is running.
    """
    return jsonify({
        'status': 'healthy',
        'message': 'API is running'
    }), 200