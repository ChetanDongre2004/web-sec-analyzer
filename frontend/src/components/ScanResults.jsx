import React, { useState, useEffect } from 'react';
import axios from 'axios';

const API_BASE_URL = 'http://localhost:5000/api';
const POLL_INTERVAL = 2000; // Poll every 2 seconds (reduced from 5s for more responsive UI)

// Error Boundary Component
class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true };
  }

  componentDidCatch(error, errorInfo) {
    console.error('Error caught by ErrorBoundary:', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="bg-white shadow-lg rounded-lg p-6 w-full max-w-4xl mx-auto">
          <h2 className="text-xl font-semibold text-red-600">Something went wrong.</h2>
          <p className="text-gray-600">Please try refreshing the page or starting a new scan.</p>
        </div>
      );
    }

    return this.props.children;
  }
}

const ScanResults = ({ scanId, targetUrl, onNewScan }) => {
  const [scanData, setScanData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [progress, setProgress] = useState(0);
  const [polling, setPolling] = useState(true);
  const [scanStatus, setScanStatus] = useState('pending');

  // Function to fetch scan progress
  const fetchScanProgress = async () => {
    try {
      const response = await axios.get(`${API_BASE_URL}/scan/${scanId}/progress`);
      
      if (response.data && response.data.status === 'success') {
        setProgress(response.data.progress);
        setScanStatus(response.data.scan_status);
        
        // Only fetch full results when scan is completed
        if (response.data.scan_status === 'completed') {
          setPolling(false);
          fetchScanResults();
        }
      }
    } catch (err) {
      console.error('Error fetching scan progress:', err);
      // Don't show error to user yet, keep trying for a bit
      // If it continues to fail, the UI will still be responsive
    }
  };

  // Function to fetch scan results
  const fetchScanResults = async () => {
    try {
      const response = await axios.get(`${API_BASE_URL}/scan/${scanId}`);
      if (response.data && response.data.status === 'success') {
        setScanData(response.data.scan);
        setLoading(false);
      } else {
        throw new Error('Failed to retrieve scan results');
      }
    } catch (err) {
      setError(err.response?.data?.message || err.message || 'An unexpected error occurred');
      setLoading(false);
    }
  };

  // Start polling for progress when component mounts
  useEffect(() => {
    let interval = null;
    
    // Initial fetch
    fetchScanProgress();
    
    // Set up polling
    if (polling) {
      interval = setInterval(fetchScanProgress, POLL_INTERVAL);
    }
    
    // Clean up interval on component unmount or when polling stops
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

  // Calculate severity counts
  const severityCounts = scanData ? getSeverityCounts() : { HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  
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

  // Add collapsible sections for detailed vulnerability information
  const CollapsibleSection = ({ title, children }) => {
    const [isOpen, setIsOpen] = useState(false);
  
    return (
      <div className="border rounded-md mb-4">
        <div
          className="bg-gray-100 px-4 py-2 cursor-pointer flex justify-between items-center"
          onClick={() => setIsOpen(!isOpen)}
        >
          <h3 className="font-semibold">{title}</h3>
          <span className="text-gray-500">{isOpen ? '-' : '+'}</span>
        </div>
        {isOpen && <div className="p-4">{children}</div>}
      </div>
    );
  };
  
  // Show loading state with progress bar during scan
  if (loading && progress < 100) {
    return (
      <div className="bg-white shadow-lg rounded-lg p-6 w-full max-w-4xl mx-auto">
        <div className="flex flex-col items-center justify-center py-8">
          <h2 className="text-xl font-semibold text-gray-800 mb-4">Scanning {targetUrl}</h2>
          
          {/* Always show progress bar, even if progress is 0 */}
          <div className="w-full bg-gray-200 rounded-full h-4 mb-4">
            <div
              className="bg-blue-600 h-4 rounded-full transition-all duration-300"
              style={{ width: `${progress}%` }}
            ></div>
          </div>
          
          <div className="flex items-center mt-2">
            <div className="animate-spin rounded-full h-6 w-6 mr-3 border-t-2 border-b-2 border-blue-500"></div>
            <p className="text-gray-600">
              {progress === 0 
                ? "Initializing scan..." 
                : `Scan in progress: ${progress}% complete`}
            </p>
          </div>
          
          <p className="mt-4 text-sm text-gray-500">
            {getScanStatusMessage(scanStatus, progress)}
          </p>
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

  // Only show results when we have data and the scan is completed
  const isCompleted = progress === 100 && scanData;
  
  return (
    <ErrorBoundary>
      <div className="bg-white shadow-lg rounded-lg p-6 w-full max-w-4xl mx-auto">
        {!isCompleted && (
          <div className="mt-6 text-center">
            <p className="text-gray-600">Scan in progress... Please wait.</p>
            <div className="w-full bg-gray-200 rounded-full h-4 mt-4">
              <div
                className="bg-blue-600 h-4 rounded-full"
                style={{ width: `${progress}%` }}
              ></div>
            </div>
          </div>
        )}
        
        <div className="mb-6">
          <h2 className="text-2xl font-bold text-gray-800">Scan Results</h2>
          <p className="text-gray-600">
            Target: <span className="font-medium">{targetUrl || scanData?.result?.target_url || 'Unknown'}</span>
          </p>
          <div className="flex items-center mt-2">
            <p className="text-sm text-gray-500">
              Status:
              <span className={`ml-2 font-semibold ${scanStatus === 'running' ? 'text-yellow-600' : isCompleted ? 'text-green-600' : 'text-gray-600'}`}>
                {scanStatus || 'Unknown'}
              </span>
            </p>
            {scanStatus === 'running' && (
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
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 border border-gray-300 p-4 rounded-md">
              <div className="flex flex-col items-center bg-red-100 p-4 rounded-md shadow">
                <span className="text-2xl font-bold text-red-600">{severityCounts.HIGH}</span>
                <span className="text-sm text-gray-600">High</span>
              </div>
              <div className="flex flex-col items-center bg-orange-100 p-4 rounded-md shadow">
                <span className="text-2xl font-bold text-orange-600">{severityCounts.MEDIUM}</span>
                <span className="text-sm text-gray-600">Medium</span>
              </div>
              <div className="flex flex-col items-center bg-yellow-100 p-4 rounded-md shadow">
                <span className="text-2xl font-bold text-yellow-600">{severityCounts.LOW}</span>
                <span className="text-sm text-gray-600">Low</span>
              </div>
              <div className="flex flex-col items-center bg-blue-100 p-4 rounded-md shadow">
                <span className="text-2xl font-bold text-blue-600">{severityCounts.INFO}</span>
                <span className="text-sm text-gray-600">Info</span>
              </div>
            </div>
          </div>
        )}
        
        {/* Detailed findings */}
        {isCompleted && (
          <div>
            <CollapsibleSection title="Header Analysis">
              {scanData.result.header_analysis?.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="table-auto border-collapse border border-gray-300 w-full">
                    <thead>
                      <tr className="bg-gray-100">
                        <th className="border border-gray-300 px-4 py-2">Section</th>
                        <th className="border border-gray-300 px-4 py-2">Path/Item</th>
                        <th className="border border-gray-300 px-4 py-2">Status</th>
                        <th className="border border-gray-300 px-4 py-2">Severity</th>
                        <th className="border border-gray-300 px-4 py-2">Message</th>
                      </tr>
                    </thead>
                    <tbody>
                      {scanData?.result?.header_analysis?.map((item, index) => (
                        <tr key={`header-${index}`} className="text-center">
                          <td className="border border-gray-300 px-4 py-2">Header Analysis</td>
                          <td className="border border-gray-300 px-4 py-2">{item.header}</td>
                          <td className="border border-gray-300 px-4 py-2">{item.status}</td>
                          <td className="border border-gray-300 px-4 py-2">
                            <SeverityBadge severity={item.severity} />
                          </td>
                          <td className="border border-gray-300 px-4 py-2">{item.message}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p className="text-gray-500 text-sm">No header analysis information available</p>
              )}
            </CollapsibleSection>
  
            <CollapsibleSection title="Directory Enumeration">
              {scanData.result.directory_enumeration?.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="table-auto border-collapse border border-gray-300 w-full">
                    <thead>
                      <tr className="bg-gray-100">
                        <th className="border border-gray-300 px-4 py-2">Section</th>
                        <th className="border border-gray-300 px-4 py-2">Path/Item</th>
                        <th className="border border-gray-300 px-4 py-2">Status</th>
                        <th className="border border-gray-300 px-4 py-2">Severity</th>
                        <th className="border border-gray-300 px-4 py-2">Message</th>
                      </tr>
                    </thead>
                    <tbody>
                      {scanData?.result?.directory_enumeration?.map((item, index) => (
                        <tr key={`directory-${index}`} className="text-center">
                          <td className="border border-gray-300 px-4 py-2">Directory Enumeration</td>
                          <td className="border border-gray-300 px-4 py-2">{item.path}</td>
                          <td className="border border-gray-300 px-4 py-2">{item.status_code}</td>
                          <td className="border border-gray-300 px-4 py-2">
                            <SeverityBadge severity={item.severity} />
                          </td>
                          <td className="border border-gray-300 px-4 py-2">{item.description}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p className="text-gray-500 text-sm">No accessible directories found</p>
              )}
            </CollapsibleSection>
  
            <CollapsibleSection title="Robots.txt Analysis">
              {scanData.result.robots_txt_analysis?.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="table-auto border-collapse border border-gray-300 w-full">
                    <thead>
                      <tr className="bg-gray-100">
                        <th className="border border-gray-300 px-4 py-2">Section</th>
                        <th className="border border-gray-300 px-4 py-2">Path/Item</th>
                        <th className="border border-gray-300 px-4 py-2">Status</th>
                        <th className="border border-gray-300 px-4 py-2">Severity</th>
                        <th className="border border-gray-300 px-4 py-2">Message</th>
                      </tr>
                    </thead>
                    <tbody>
                      {scanData?.result?.robots_txt_analysis?.map((item, index) => (
                        <tr key={`robots-${index}`} className="text-center">
                          <td className="border border-gray-300 px-4 py-2">Robots.txt Analysis</td>
                          <td className="border border-gray-300 px-4 py-2">{item.path || 'N/A'}</td>
                          <td className="border border-gray-300 px-4 py-2">{item.status}</td>
                          <td className="border border-gray-300 px-4 py-2">
                            <SeverityBadge severity={item.severity} />
                          </td>
                          <td className="border border-gray-300 px-4 py-2">{item.description}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p className="text-gray-500 text-sm">No robots.txt analysis information available</p>
              )}
            </CollapsibleSection>
  
            <CollapsibleSection title="Form Analysis">
              {scanData.result.form_analysis?.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="table-auto border-collapse border border-gray-300 w-full">
                    <thead>
                      <tr className="bg-gray-100">
                        <th className="border border-gray-300 px-4 py-2">Section</th>
                        <th className="border border-gray-300 px-4 py-2">Path/Item</th>
                        <th className="border border-gray-300 px-4 py-2">Status</th>
                        <th className="border border-gray-300 px-4 py-2">Severity</th>
                        <th className="border border-gray-300 px-4 py-2">Message</th>
                      </tr>
                    </thead>
                    <tbody>
                      {scanData?.result?.form_analysis?.map((item, index) => (
                        <tr key={`form-${index}`} className="text-center">
                          <td className="border border-gray-300 px-4 py-2">Form Analysis</td>
                          <td className="border border-gray-300 px-4 py-2">Form {item.form_index}</td>
                          <td className="border border-gray-300 px-4 py-2">{item.issue}</td>
                          <td className="border border-gray-300 px-4 py-2">
                            <SeverityBadge severity={item.severity} />
                          </td>
                          <td className="border border-gray-300 px-4 py-2">{item.description}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p className="text-gray-500 text-sm">No form analysis information available</p>
              )}
            </CollapsibleSection>
          </div>
        )}
        
        {/* Loading state during polling */}
        {scanStatus === 'running' && (
          <div className="mt-6 text-center p-8">
            <div className="animate-spin mx-auto rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-500"></div>
            <p className="mt-4 text-gray-600">Scan in progress... This may take a minute.</p>
            <p className="text-sm text-gray-500">Results will update automatically</p>
          </div>
        )}
        
        {/* Start new scan button */}
        {isCompleted && (
          <div className="text-center mt-8">
            <button
              onClick={handleNewScan}
              className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700"
            >
              Start New Scan
            </button>
          </div>
        )}
      </div>
    </ErrorBoundary>
  );
};

// Helper function to get appropriate message based on scan status
function getScanStatusMessage(status, progress) {
  switch(status) {
    case 'pending':
      return "Preparing to scan website...";
    case 'running':
      if (progress < 25) {
        return "Analyzing HTTP headers...";
      } else if (progress < 50) {
        return "Checking robots.txt file...";
      } else if (progress < 75) {
        return "Scanning directories...";
      } else {
        return "Analyzing HTML forms...";
      }
    case 'completed':
      return "Scan completed! Processing results...";
    case 'error':
      return "An error occurred during the scan.";
    default:
      return "Processing scan...";
  }
}

export default ScanResults;