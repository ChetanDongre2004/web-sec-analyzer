import { useState } from 'react';
import './App.css';
import ScanForm from './components/ScanForm';
import ScanResults from './components/ScanResults';

function App() {
  const [scanState, setScanState] = useState({
    scanId: null,
    targetUrl: null,
    showResults: false,
  });

  // Handle starting a new scan
  const handleScanStart = (scanId, targetUrl) => {
    setScanState({
      scanId,
      targetUrl,
      showResults: true,
    });
  };

  // Handle going back to the form
  const handleNewScan = () => {
    setScanState({
      scanId: null,
      targetUrl: null,
      showResults: false,
    });
  };

  return (
    <div className="min-h-screen bg-gray-100 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-5xl mx-auto">
        <header className="text-center mb-8">
          <h1 className="text-3xl font-extrabold text-gray-900 sm:text-4xl">
            Web Security Analyzer
          </h1>
          <p className="mt-3 text-xl text-gray-500 sm:mt-4">
            Scan websites for common security vulnerabilities
          </p>
        </header>

        <main>
          {!scanState.showResults ? (
            <ScanForm onScanStart={handleScanStart} />
          ) : (
            <ScanResults 
              scanId={scanState.scanId} 
              targetUrl={scanState.targetUrl} 
              onNewScan={() => {
                setScanState({
                  scanId: null,
                  targetUrl: null,
                  showResults: false,
                });
              }} 
            />
          )}

          <div className="mt-12 text-center text-sm text-gray-500">
            <p>This tool is intended for security professionals and website owners to test their own websites.</p>
            <p className="mt-1">Do not use on websites without proper authorization.</p>
          </div>
        </main>

        <footer className="mt-12 text-center text-sm text-gray-500">
          <p>© {new Date().getFullYear()} Web Security Analyzer - Developed by <a href='https://www.linkedin.com/in/bhushan-madankar/' target='_blank' rel='noopener noreferrer'>Bhushan Madankar</a></p>
        </footer>
      </div>
    </div>
  );
}

export default App;
