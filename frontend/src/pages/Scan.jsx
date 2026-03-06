import { useState } from 'react';
import API, { startScan, getScanReport } from '../services/api';
import ScanForm from '../components/ScanForm';
import ResultCard from '../components/ResultCard';
import Loader from '../components/Loader';

function Scan() {
  const [scanResult, setScanResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleScan = async (targetId) => {
    setLoading(true);
    setError(null);
    try {
      const data = await startScan(targetId);
      setScanResult(data);
    } catch (err) {
      setError('Scan failed. Please check the target ID and ensure you are logged in.');
    } finally {
      setLoading(false);
    }
  };

  const downloadReport = () => {
    if (scanResult?.scan_id) {
      const token = localStorage.getItem("token");
      const url = `http://127.0.0.1:8000/scan/${scanResult.scan_id}/report`;
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('Authorization', `Bearer ${token}`);
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    }
  };

  const getSeverityCounts = () => {
    if (!scanResult?.results) return {};
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    scanResult.results.forEach(r => {
      const sev = r.severity || 'INFO';
      if (counts[sev] !== undefined) counts[sev]++;
    });
    return counts;
  };

  const counts = getSeverityCounts();

  return (
    <div className="container">
      <h1>Vulnerability Scan</h1>
      <p>Scan AI systems for potential vulnerabilities.</p>
      
      <ScanForm onScan={handleScan} />
      
      {loading && <Loader message="Scanning target..." />}
      
      {error && <div className="error">{error}</div>}
      
      {scanResult && (
        <div className="scan-results">
          {/* Scan Summary */}
          <div className="scan-header">
            <h2>Scan Complete</h2>
            <p>Scan ID: {scanResult.scan_id?.slice(0, 8)}...</p>
            {scanResult.report_url && (
              <button className="btn-primary" onClick={downloadReport}>
                📄 Download PDF Report
              </button>
            )}
          </div>

          {/* Severity Counts */}
          <div className="severity-summary">
            <h3>Vulnerability Summary</h3>
            <div className="severity-counts">
              {Object.entries(counts).map(([sev, count]) => (
                count > 0 && (
                  <span key={sev} className={`severity-badge severity-${sev.toLowerCase()}`}>
                    {sev}: {count}
                  </span>
                )
              ))}
            </div>
          </div>

          {/* Agent Timeline */}
          <div className="agent-timeline">
            <h3>Agent Timeline</h3>
            <div className="timeline">
              <div className="timeline-item">
                <span className="timeline-icon">🎯</span>
                <span>Target Profiling</span>
                <span className="timeline-status">Completed</span>
              </div>
              <div className="timeline-item">
                <span className="timeline-icon">⚔️</span>
                <span>Attack Strategy</span>
                <span className="timeline-status">Completed</span>
              </div>
              <div className="timeline-item">
                <span className="timeline-icon">🚀</span>
                <span>Attack Execution</span>
                <span className="timeline-status">Completed</span>
              </div>
              <div className="timeline-item">
                <span className="timeline-icon">🔍</span>
                <span>Analysis & XAI</span>
                <span className="timeline-status">Completed</span>
              </div>
            </div>
          </div>

          {/* Rule Pass/Fail */}
          <div className="rule-summary">
            <h3>Rule Assessment</h3>
            <div className="rule-stats">
              <span className="stat fail">
                Failed: {scanResult.results?.filter(r => r.status === 'VULNERABLE').length || 0}
              </span>
              <span className="stat pass">
                Passed: {scanResult.results?.filter(r => r.status !== 'VULNERABLE').length || 0}
              </span>
            </div>
          </div>

          {/* Results */}
          <div className="results">
            <h3>Detailed Findings</h3>
            {scanResult.results?.map((vuln, i) => (
              <ResultCard key={i} vuln={vuln} />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export default Scan;

