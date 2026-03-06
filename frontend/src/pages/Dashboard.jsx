import { Link } from 'react-router-dom';

function Dashboard() {
  const stats = {
    totalScans: 24,
    vulnerabilities: 12,
    critical: 3,
    high: 5,
    medium: 4
  };

  return (
    <div className="container">
      <h1>AI Vulnerability Scanner</h1>
      <p>Scan AI systems for potential vulnerabilities and security weaknesses.</p>
      
      <div className="stats">
        <div><span>Total Scans</span><h3>{stats.totalScans}</h3></div>
        <div><span>Vulnerabilities</span><h3>{stats.vulnerabilities}</h3></div>
        <div><span>Critical</span><h3>{stats.critical}</h3></div>
        <div><span>High</span><h3>{stats.high}</h3></div>
      </div>
      
      <div className="nav-grid">
        <Link to="/scan" className="nav-card">
          <div className="icon">🔍</div>
          <h3>Start Scan</h3>
          <p>Scan AI systems for vulnerabilities</p>
        </Link>
        <Link to="/agents" className="nav-card">
          <div className="icon">🤖</div>
          <h3>Agents</h3>
          <p>Learn about our AI red team agents</p>
        </Link>
        <Link to="/admin" className="nav-card">
          <div className="icon">⚙️</div>
          <h3>Admin</h3>
          <p>Manage vulnerability rules</p>
        </Link>
      </div>
    </div>
  );
}

export default Dashboard;

