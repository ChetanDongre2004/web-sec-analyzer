#!/usr/bin/env python3
"""
app.py - Main application file for the Web Security Analyzer
This module initializes the Flask application and registers API routes.
"""

import os
from flask import Flask, jsonify
from flask_cors import CORS
import logging
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def create_app():
    """
    Create and configure the Flask application.
    
    Returns:
        Flask: The configured Flask application
    """
    app = Flask(__name__)
    
    # Enable CORS for all routes
    CORS(app, resources={r"/*": {"origins": "*"}})
    
    # Register the API routes
    # Use an absolute import instead of relative import
    from routes import api
    app.register_blueprint(api, url_prefix='/api')
    
    # Register a default route
    @app.route('/')
    def index():
        """Default route that returns basic API information."""
        return jsonify({
            'name': 'Web Security Analyzer API',
            'version': '1.0.0',
            'endpoints': [
                {'path': '/api/scan', 'method': 'POST', 'description': 'Start a new scan'},
                {'path': '/api/scan/{scan_id}', 'method': 'GET', 'description': 'Get scan results'},
                {'path': '/api/scans', 'method': 'GET', 'description': 'Get list of all scans'},
                {'path': '/api/health', 'method': 'GET', 'description': 'Health check'}
            ]
        })
    
    # Register error handlers
    @app.errorhandler(404)
    def not_found(e):
        """Handle 404 errors."""
        return jsonify({
            'status': 'error',
            'message': 'Resource not found'
        }), 404
    
    @app.errorhandler(500)
    def server_error(e):
        """Handle 500 errors."""
        logger.error(f"Internal server error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Internal server error'
        }), 500
        
    return app

if __name__ == "__main__":
    # Get port from environment variable or use default
    port = int(os.environ.get("PORT", 5000))
    
    # Create the Flask app
    app = create_app()
    
    # Start the server
    logger.info(f"Starting Web Security Analyzer API on port {port}")
    app.run(host="0.0.0.0", port=port, debug=True)  # Set debug=True during development