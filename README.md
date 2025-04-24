# Web Security Analyzer

A comprehensive web application vulnerability scanner with a Python backend (Flask) and React frontend (with Tailwind CSS). This tool helps identify common web security vulnerabilities and misconfigurations.

## Features

- **Directory Enumeration**: Scans for common sensitive directories and files
- **HTTP Header Analysis**: Checks for security headers and their configurations
- **robots.txt Analysis**: Analyzes robots.txt for sensitive disallowed paths
- **Form Scanning**: Basic security checks for HTML forms (HTTPS, autocomplete, CSRF)
- **Intuitive UI**: Clean interface to view scan results and vulnerabilities by severity

## Project Structure

```
web-sec-analyzer/
│
├── backend/                  # Python Flask API backend
│   ├── app.py               # Main application entry point
│   ├── routes.py            # API route definitions
│   ├── scanner.py           # Core scanning logic
│   ├── utils.py             # Helper utilities
│   └── requirements.txt     # Python dependencies
│
└── frontend/                # React frontend
    ├── src/
    │   ├── components/      # React components
    │   │   ├── ScanForm.jsx    # URL input form
    │   │   └── ScanResults.jsx # Results display
    │   ├── App.jsx         # Main application component
    │   └── ...             # Other React files
    └── ...                 # React configuration files
```

## Installation

### Backend Setup

1. Navigate to the backend directory:
   ```
   cd web-sec-analyzer/backend
   ```

2. Create and activate a Python virtual environment (optional but recommended):
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

### Frontend Setup

1. Navigate to the frontend directory:
   ```
   cd web-sec-analyzer/frontend
   ```

2. Install the required dependencies:
   ```
   npm install
   ```

## Running the Application

### Start the Backend Server

1. Navigate to the backend directory:
   ```
   cd web-sec-analyzer/backend
   ```

2. Start the Flask server:
   ```
   python app.py
   ```

   The backend API will be available at `http://localhost:5000`.

### Start the Frontend Development Server

1. Navigate to the frontend directory:
   ```
   cd web-sec-analyzer/frontend
   ```

2. Start the development server:
   ```
   npm run dev
   ```

   The frontend will be available at `http://localhost:5173` (or whichever port Vite assigns).

## Using the Application

1. Open your browser and navigate to the frontend URL (e.g., `http://localhost:5173`).
2. Enter a target URL to scan in the form (e.g., `https://example.com`).
3. Click "Start Vulnerability Scan" to initiate the scan.
4. View the results as they come in, organized by category and severity.

## Security Considerations

- This tool should only be used against websites you own or have explicit permission to test.
- Running this tool against websites without permission may violate laws and terms of service.
- Rate limiting is implemented to avoid overwhelming the target server, but use with caution.

## Technologies Used

### Backend
- Python 3.x
- Flask (Web framework)
- Requests (HTTP client)
- BeautifulSoup4 (HTML parsing)
- Threading (For asynchronous scanning)

### Frontend
- React (UI library)
- Tailwind CSS (Styling)
- Axios (API requests)
- Vite (Build tool)

## Future Enhancements

- Additional scanning modules (XSS detection, SQLi testing, etc.)
- User authentication and scan history storage
- Scan scheduling and email notifications
- PDF report generation
- Custom scanning profiles

## License

This project is for educational purposes only.

## Disclaimer

This tool is provided for educational and legitimate testing purposes only. The authors are not responsible for any misuse or damage caused by this tool.