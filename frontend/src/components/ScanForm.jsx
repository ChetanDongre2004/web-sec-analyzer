import { useState } from 'react';
import axios from 'axios';

const API_BASE_URL = 'http://localhost:5000/api';

const ScanForm = ({ onScanStart }) => {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    // Reset states
    setError(null);
    setLoading(true);
    
    try {
      // Validate input URL
      if (!url.trim()) {
        throw new Error('Please enter a valid URL');
      }
      
      // Make API call to start scan
      const response = await axios.post(`${API_BASE_URL}/scan`, {
        url: url
      });
      
      // Check response
      if (response.data && response.data.status === 'success') {
        // Call the parent component's callback with the scan ID
        onScanStart(response.data.scan_id, url);
      } else {
        throw new Error('Failed to start scan. Please try again.');
      }
    } catch (err) {
      setError(err.response?.data?.message || err.message || 'An unexpected error occurred');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="bg-white shadow-lg rounded-lg p-6 w-full max-w-md mx-auto">
      <h2 className="text-2xl font-bold mb-6 text-gray-800 text-center">
        Web Security Analyzer
      </h2>
      
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label htmlFor="url" className="block text-sm font-medium text-gray-700 mb-1">
            Target Website URL
          </label>
          <input
            type="text"
            id="url"
            name="url"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com"
            className="w-full px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            disabled={loading}
          />
          <p className="mt-1 text-xs text-gray-500">
            Enter the URL of the website you want to scan for vulnerabilities
          </p>
        </div>
        
        {error && (
          <div className="bg-red-50 border-l-4 border-red-500 p-4">
            <p className="text-red-700 text-sm">{error}</p>
          </div>
        )}
        
        <div className="pt-2">
          <button
            type="submit"
            disabled={loading}
            className={`w-full py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white 
              ${loading ? 'bg-blue-300' : 'bg-blue-600 hover:bg-blue-700'} 
              focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500`}
          >
            {loading ? 'Starting Scan...' : 'Start Vulnerability Scan'}
          </button>
        </div>
      </form>
    </div>
  );
};

export default ScanForm;