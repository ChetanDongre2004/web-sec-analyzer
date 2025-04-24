import { useState, useEffect } from 'react';
import axios from 'axios';

const API_BASE_URL = 'http://localhost:5000/api';
const POLL_INTERVAL = 5000; // Poll every 5 seconds

const ScanResults = ({ scanId, targetUrl, onNewScan }) => {
  const [scanData, setScanData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [polling, setPolling] = useState(false);
  
  // Function to fetch scan results
  const fetchScanResults = async () => {
    try {
      const response = await axios.get(`${API_BASE_URL}/scan/${scanId}`);
      
      if (response.data && response.data.status === 'success') {
        setScanData(response.data.scan);
        
        // If scan is completed, stop polling
        if (response.data.scan.status === 'completed') {
          setPolling(false);
        }
      } else {
        throw new Error('Failed to retrieve scan results');
      }
    } catch (err) {
      setError(err.response?.data?.message || err.message || 'An unexpected error occurred');
      setPolling(false);
    } finally {
      setLoading(false);
    }
  };
  
  // Start polling when component mounts
  useEffect(() => {
    let interval = null;
    
    // Initial fetch
    fetchScanResults();
    setPolling(true);
    
    // Set up polling if scan is not completed
    if (polling) {
      interval = setInterval(fetchScanResults, POLL_INTERVAL);
    }
    
    // Clean up interval on component unmount
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [scanId, polling]);
  
  // Determine the overall severity of findings
  const getSeverityCounts = () => {
    if (!scanData?.result) return { HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    
    const counts = { HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    const result = scanData.result;
    
    // Count findings by severity from different scan modules
    ['header_analysis', 'directory_enumeration', 'robots_txt_analysis', 'form_analysis'].forEach(module => {
      if (Array.isArray(result[module])) {
        result[module].forEach(finding => {
          if (finding.severity && counts[finding.severity] !== undefined) {
            counts[finding.severity]++;
          }
        });
      }
    });
    
    return counts;
  };
  
  // Format the duration of the scan
  const formatScanDuration = () => {
    if (!scanData?.result?.scan_time) return 'Unknown duration';
    
    const scanTime = new Date(scanData.result.scan_time);
    const currentTime = new Date();
    const diff = Math.abs(currentTime - scanTime) / 1000; // in seconds
    
    if (diff < 60) return `${Math.round(diff)} seconds`;
    if (diff < 3600) return `${Math.round(diff / 60)} minutes`;
    return `${Math.round(diff / 3600)} hours`;
  };

  // Render severity badge
  const SeverityBadge = ({ severity }) => {
    const colors = {
      HIGH: 'bg-red-100 text-red-800 border-red-200',
      MEDIUM: 'bg-orange-100 text-orange-800 border-orange-200',
      LOW: 'bg-yellow-100 text-yellow-800 border-yellow-200',
      INFO: 'bg-blue-100 text-blue-800 border-blue-200',
    };
    
    return (
      <span className={`px-2.5 py-0.5 rounded-full text-xs font-medium ${colors[severity] || colors.INFO}`}>
        {severity}
      </span>
    );
  };
  
  // Handle starting a new scan
  const handleNewScan = () => {
    if (onNewScan) onNewScan();
  };
  
  if (loading && !scanData) {
    return (
      <div className="bg-white shadow-lg rounded-lg p-6 w-full max-w-4xl mx-auto">
        <div className="flex flex-col items-center justify-center py-8">
          <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-500"></div>
          <p className="mt-4 text-gray-600">Initializing scan...</p>
        </div>
      </div>
    );
  }
  
  if (error) {
    return (
      <div className="bg-white shadow-lg rounded-lg p-6 w-full max-w-4xl mx-auto">
        <div className="bg-red-50 border-l-4 border-red-500 p-4">
          <h3 className="text-lg font-medium text-red-700">Error</h3>
          <p className="text-red-700">{error}</p>
        </div>
        <div className="mt-6 text-center">
          <button
            onClick={handleNewScan}
            className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700"
          >
            Start New Scan
          </button>
        </div>
      </div>
    );
  }
  
  const severityCounts = getSeverityCounts();
  const isCompleted = scanData?.status === 'completed';
  const isRunning = ['pending', 'running'].includes(scanData?.status);
  
  return (
    <div className="bg-white shadow-lg rounded-lg p-6 w-full max-w-4xl mx-auto">
      <div className="mb-6">
        <h2 className="text-2xl font-bold text-gray-800">Scan Results</h2>
        <p className="text-gray-600">
          Target: <span className="font-medium">{targetUrl || scanData?.result?.target_url || 'Unknown'}</span>
        </p>
        <div className="flex items-center mt-2">
          <p className="text-sm text-gray-500">
            Status:
            <span className={`ml-2 font-semibold ${isRunning ? 'text-yellow-600' : isCompleted ? 'text-green-600' : 'text-gray-600'}`}>
              {scanData?.status || 'Unknown'}
            </span>
          </p>
          {isRunning && (
            <div className="ml-3 animate-spin rounded-full h-4 w-4 border-t-2 border-b-2 border-blue-500"></div>
          )}
        </div>
        {scanData?.timestamp && (
          <p className="text-sm text-gray-500">
            Started: {new Date(scanData.timestamp).toLocaleString()}
          </p>
        )}
      </div>
      
      {/* Summary of findings */}
      {isCompleted && (
        <div className="mb-6 p-4 bg-gray-50 rounded-md">
          <h3 className="text-lg font-semibold text-gray-800 mb-3">Summary</h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="bg-white p-3 rounded shadow-sm border border-gray-200">
              <p className="text-xs text-gray-500">High</p>
              <p className="text-xl font-bold text-red-600">{severityCounts.HIGH}</p>
            </div>
            <div className="bg-white p-3 rounded shadow-sm border border-gray-200">
              <p className="text-xs text-gray-500">Medium</p>
              <p className="text-xl font-bold text-orange-600">{severityCounts.MEDIUM}</p>
            </div>
            <div className="bg-white p-3 rounded shadow-sm border border-gray-200">
              <p className="text-xs text-gray-500">Low</p>
              <p className="text-xl font-bold text-yellow-600">{severityCounts.LOW}</p>
            </div>
            <div className="bg-white p-3 rounded shadow-sm border border-gray-200">
              <p className="text-xs text-gray-500">Info</p>
              <p className="text-xl font-bold text-blue-600">{severityCounts.INFO}</p>
            </div>
          </div>
          <p className="text-sm text-gray-500 mt-3">
            Scan completed in {formatScanDuration()}
          </p>
        </div>
      )}
      
      {/* Detailed results */}
      {isCompleted && scanData?.result && (
        <div className="space-y-6">
          {/* HTTP Header Analysis */}
          <div className="border rounded-md">
            <div className="bg-gray-100 px-4 py-2 rounded-t-md">
              <h3 className="font-semibold">HTTP Header Analysis</h3>
            </div>
            <div className="p-4">
              {scanData.result.header_analysis?.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="min-w-full divide-y divide-gray-200">
                    <thead className="bg-gray-50">
                      <tr>
                        <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 uppercase">Header</th>
                        <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
                        <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 uppercase">Severity</th>
                        <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 uppercase">Message</th>
                      </tr>
                    </thead>
                    <tbody className="bg-white divide-y divide-gray-200">
                      {scanData.result.header_analysis.map((header, index) => (
                        <tr key={index}>
                          <td className="px-3 py-2 text-sm font-medium text-gray-900">{header.header}</td>
                          <td className="px-3 py-2 text-sm text-gray-500">
                            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium
                              ${header.status === 'Present' ? 'bg-green-100 text-green-800' : 
                                header.status === 'Missing' ? 'bg-red-100 text-red-800' : 
                                'bg-yellow-100 text-yellow-800'}`}>
                              {header.status}
                            </span>
                          </td>
                          <td className="px-3 py-2 text-sm text-gray-500">
                            <SeverityBadge severity={header.severity} />
                          </td>
                          <td className="px-3 py-2 text-sm text-gray-500">{header.message}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p className="text-gray-500 text-sm">No header analysis information available</p>
              )}
            </div>
          </div>
          
          {/* Directory Enumeration */}
          <div className="border rounded-md">
            <div className="bg-gray-100 px-4 py-2 rounded-t-md">
              <h3 className="font-semibold">Directory Enumeration</h3>
            </div>
            <div className="p-4">
              {scanData.result.directory_enumeration?.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="min-w-full divide-y divide-gray-200">
                    <thead className="bg-gray-50">
                      <tr>
                        <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 uppercase">Path</th>
                        <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
                        <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 uppercase">Severity</th>
                        <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 uppercase">Message</th>
                      </tr>
                    </thead>
                    <tbody className="bg-white divide-y divide-gray-200">
                      {scanData.result.directory_enumeration.map((dir, index) => (
                        <tr key={index}>
                          <td className="px-3 py-2 text-sm font-medium text-gray-900">{dir.path}</td>
                          <td className="px-3 py-2 text-sm text-gray-500">{dir.status_code}</td>
                          <td className="px-3 py-2 text-sm text-gray-500">
                            <SeverityBadge severity={dir.severity} />
                          </td>
                          <td className="px-3 py-2 text-sm text-gray-500">{dir.message}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p className="text-gray-500 text-sm">No accessible directories found</p>
              )}
            </div>
          </div>
          
          {/* Robots.txt Analysis */}
          <div className="border rounded-md">
            <div className="bg-gray-100 px-4 py-2 rounded-t-md">
              <h3 className="font-semibold">Robots.txt Analysis</h3>
            </div>
            <div className="p-4">
              {scanData.result.robots_txt_analysis?.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="min-w-full divide-y divide-gray-200">
                    <thead className="bg-gray-50">
                      <tr>
                        <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
                        <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 uppercase">Path</th>
                        <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 uppercase">Severity</th>
                        <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 uppercase">Message</th>
                      </tr>
                    </thead>
                    <tbody className="bg-white divide-y divide-gray-200">
                      {scanData.result.robots_txt_analysis.map((item, index) => (
                        <tr key={index}>
                          <td className="px-3 py-2 text-sm font-medium text-gray-900">{item.status}</td>
                          <td className="px-3 py-2 text-sm text-gray-500">{item.path || 'N/A'}</td>
                          <td className="px-3 py-2 text-sm text-gray-500">
                            <SeverityBadge severity={item.severity} />
                          </td>
                          <td className="px-3 py-2 text-sm text-gray-500">{item.message}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p className="text-gray-500 text-sm">No robots.txt analysis information available</p>
              )}
            </div>
          </div>
          
          {/* Form Analysis */}
          <div className="border rounded-md">
            <div className="bg-gray-100 px-4 py-2 rounded-t-md">
              <h3 className="font-semibold">Form Analysis</h3>
            </div>
            <div className="p-4">
              {scanData.result.form_analysis?.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="min-w-full divide-y divide-gray-200">
                    <thead className="bg-gray-50">
                      <tr>
                        <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 uppercase">Form</th>
                        <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 uppercase">Issue</th>
                        <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 uppercase">Severity</th>
                        <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 uppercase">Message</th>
                      </tr>
                    </thead>
                    <tbody className="bg-white divide-y divide-gray-200">
                      {scanData.result.form_analysis.map((form, index) => (
                        <tr key={index}>
                          <td className="px-3 py-2 text-sm font-medium text-gray-900">
                            {form.form_index || form.status || 'Form ' + (index + 1)}
                          </td>
                          <td className="px-3 py-2 text-sm text-gray-500">{form.issue || 'N/A'}</td>
                          <td className="px-3 py-2 text-sm text-gray-500">
                            <SeverityBadge severity={form.severity} />
                          </td>
                          <td className="px-3 py-2 text-sm text-gray-500">{form.message}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p className="text-gray-500 text-sm">No form analysis information available</p>
              )}
            </div>
          </div>
        </div>
      )}
      
      {/* Loading state during polling */}
      {isRunning && (
        <div className="mt-6 text-center p-8">
          <div className="animate-spin mx-auto rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-500"></div>
          <p className="mt-4 text-gray-600">Scan in progress... This may take a minute.</p>
          <p className="text-sm text-gray-500">Results will update automatically</p>
        </div>
      )}
      
      {/* Start new scan button */}
      {isCompleted && (
        <div className="mt-8 text-center">
          <button
            onClick={handleNewScan}
            className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700"
          >
            Start New Scan
          </button>
        </div>
      )}
    </div>
  );
};

export default ScanResults;