/**
 * Demo Scan - Handles the interactive demo on index.html
 * Provides a simplified scan experience for testing the AivulnHunter pipeline
 */

const DEMO_API_BASE = "http://127.0.0.1:8000/api/v1";

// Global state
let currentDemoScanId = null;
let progressWebSocket = null;

// DOM Elements - Demo specific
let demoUrlInput;
let demoScanTypeSelect;
let startDemoBtn;
let demoOutput;
let demoFileUpload;

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
  console.log("Initializing Demo Scan...");
  
  // Get DOM elements
  demoUrlInput = document.getElementById('demoUrlInput');
  demoScanTypeSelect = document.getElementById('scanTarget');
  startDemoBtn = document.getElementById('startDemoBtn');
  demoOutput = document.getElementById('demoOutput');
  demoFileUpload = document.getElementById('demoFileUpload');
  
  if (startDemoBtn) {
    startDemoBtn.addEventListener('click', handleDemoStart);
  }
  
  // Handle scan type change
  if (demoScanTypeSelect) {
    demoScanTypeSelect.addEventListener('change', handleScanTypeChange);
  }
  
  console.log("Demo Scan initialized");
});

function handleScanTypeChange() {
  const type = demoScanTypeSelect ? demoScanTypeSelect.value : 'api';
  
  if (demoFileUpload) {
    if (type === 'dataset') {
      demoFileUpload.classList.remove('hidden');
      if (demoUrlInput) demoUrlInput.style.display = 'none';
    } else {
      demoFileUpload.classList.add('hidden');
      if (demoUrlInput) demoUrlInput.style.display = 'block';
    }
  }
}

async function handleDemoStart() {
  console.log("Demo start clicked");
  
  if (!startDemoBtn) return;
  
  // Get token - for demo, we might need to auto-login or prompt
  let token = localStorage.getItem('token');
  
  if (!token) {
    // Try to login as demo user or prompt
    try {
      token = await demoAutoLogin();
      if (!token) {
        alert('Please login first. Redirecting to login page...');
        window.location.href = 'admin_login.html';
        return;
      }
    } catch (e) {
      console.error('Auto-login failed:', e);
      alert('Please login first. Redirecting to login page...');
      window.location.href = 'admin_login.html';
      return;
    }
  }
  
  const scanType = demoScanTypeSelect ? demoScanTypeSelect.value : 'api';
  let target = '';
  
  if (scanType === 'api') {
    target = demoUrlInput ? demoUrlInput.value.trim() : '';
    if (!target) {
      alert('Please enter a target URL');
      return;
    }
  } else {
    // Dataset handling
    const fileInput = document.getElementById('demoFile');
    if (!fileInput || !fileInput.files.length) {
      alert('Please select a dataset file');
      return;
    }
    // For demo, we'll use a placeholder - actual dataset handling would need more work
    target = 'demo_dataset_upload';
  }
  
  // Disable button and show loading
  startDemoBtn.disabled = true;
  startDemoBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Starting Scan...';
  
  // Reset agent display
  resetAgentDisplay();
  
  try {
    await runDemoScan(target, scanType, token);
  } catch (error) {
    console.error('Demo scan error:', error);
    showDemoError(error.message || 'Scan failed');
    
    // Re-enable button
    if (startDemoBtn) {
      startDemoBtn.disabled = false;
      startDemoBtn.innerHTML = '🚀 Start Demo';
    }
  }
}

async function demoAutoLogin() {
  // Try to auto-login with demo credentials
  try {
    const response = await fetch(`${DEMO_API_BASE}/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        username: 'admin',
        password: 'admin123'
      })
    });
    
    if (response.ok) {
      const data = await response.json();
      if (data.access_token) {
        localStorage.setItem('token', data.access_token);
        return data.access_token;
      }
    }
  } catch (e) {
    console.warn('Auto-login attempt failed:', e);
  }
  return null;
}

async function runDemoScan(target, scanType, token) {
  // Show initial status
  showDemoStatus('Starting vulnerability scan...');
  
  try {
    // Call the scan API
    const response = await fetch(`${DEMO_API_BASE}/scans/`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        target: target,
        scan_type: scanType === 'dataset' ? 'dataset' : 'llm'
      })
    });
    
    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(error.detail || `Scan failed with status ${response.status}`);
    }
    
    const data = await response.json();
    console.log('Scan started:', data);
    
    currentDemoScanId = data.scan_id;
    
    // Show scanning message
    showDemoStatus(`Scan started! ID: ${data.scan_id}<br>Connecting to real-time progress...`);
    
    // Connect to WebSocket for progress updates
    connectDemoWebSocket(data.scan_id, token);
    
  } catch (error) {
    throw error;
  }
}

function connectDemoWebSocket(scanId, token) {
  // Close existing connection
  if (progressWebSocket) {
    progressWebSocket.close();
  }
  
  const wsUrl = `ws://127.0.0.1:8000/api/v1/ws/scan/${scanId}`;
  console.log(`[Demo WS] Connecting to ${wsUrl}`);
  
  try {
    progressWebSocket = new WebSocket(wsUrl);
    
    progressWebSocket.onopen = () => {
      console.log('[Demo WS] Connected');
      showDemoStatus('Connected to scan pipeline. Processing...');
    };
    
    progressWebSocket.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        console.log('[Demo WS] Message:', data);
        
        // Update agent progress
        updateDemoAgent(data);
        
        // Check for completion
        if (data.progress >= 100 || data.status === 'done' || data.status === 'completed') {
          showDemoStatus('Scan completed! Fetching results...');
          fetchDemoResults(scanId, token);
        }
      } catch (e) {
        console.error('[Demo WS] Parse error:', e);
      }
    };
    
    progressWebSocket.onclose = () => {
      console.log('[Demo WS] Disconnected');
      // If we haven't fetched results yet, poll for them
      fetchDemoResults(scanId, token);
    };
    
    progressWebSocket.onerror = (error) => {
      console.error('[Demo WS] Error:', error);
      showDemoStatus('Connection error. Attempting to fetch results...');
      fetchDemoResults(scanId, token);
    };
    
  } catch (e) {
    console.error('[Demo WS] Connection error:', e);
    // Fall back to polling
    fetchDemoResults(scanId, token);
  }
  
  // Also set up polling as fallback
  pollDemoResults(scanId, token);
}

function pollDemoResults(scanId, token) {
  let attempts = 0;
  const maxAttempts = 60; // 2 minutes
  
  const pollInterval = setInterval(async () => {
    attempts++;
    
    try {
      const response = await fetch(`${DEMO_API_BASE}/scans/${scanId}`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      
      if (response.ok) {
        const data = await response.json();
        console.log('[Demo Poll] Status:', data.status);
        
        if (data.status === 'completed') {
          clearInterval(pollInterval);
          renderDemoResults(data.results || []);
        } else if (data.status === 'failed') {
          clearInterval(pollInterval);
          showDemoError('Scan failed on server');
        }
      }
      
      if (attempts >= maxAttempts) {
        clearInterval(pollInterval);
        showDemoError('Scan timed out');
      }
      
    } catch (e) {
      console.error('[Demo Poll] Error:', e);
    }
  }, 2000);
}

async function fetchDemoResults(scanId, token) {
  try {
    // Use the main scan endpoint - results are included in the scan status response
    const scanResponse = await fetch(`${DEMO_API_BASE}/scans/${scanId}`, {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });
    
    if (scanResponse.ok) {
      const data = await scanResponse.json();
      console.log('[Demo] Scan data received:', data);
      renderDemoResults(data.results || []);
    } else {
      showDemoError('Failed to fetch scan results: ' + scanResponse.status);
    }
  } catch (e) {
    console.error('[Demo Results] Error:', e);
    showDemoError('Failed to fetch results: ' + e.message);
  }
}

function updateDemoAgent(data) {
  // Map agent names to demo display IDs
  const agentMap = {
    'TargetProfiling': 'a-profile',
    'Profiling': 'a-profile',
    'Target Profiling': 'a-profile',
    'Strategy': 'a-strategy',
    'AttackStrategy': 'a-strategy',
    'Attack Strategy': 'a-strategy',
    'Executor': 'a-execute',
    'Execution': 'a-execute',
    'Attack Execution': 'a-execute',
    'Observer': 'a-observe',
    'Analysis': 'a-observe',
    'Analysis & XAI': 'a-observe'
  };
  
  const elementId = agentMap[data.agent];
  if (elementId) {
    const el = document.getElementById(elementId);
    if (el) {
      el.classList.remove('waiting', 'done');
      el.classList.add('active');
      
      // If progress is high, mark as done
      if (data.progress >= 100 || data.status === 'done') {
        el.classList.remove('active');
        el.classList.add('done');
      }
    }
  }
  
  // Update status message
  if (data.details || data.message) {
    showDemoStatus(`${data.agent || 'Processing'}: ${data.details || data.message}`);
  }
}

function renderDemoResults(results) {
  console.log('[Demo] Rendering results:', results);
  
  // Re-enable button
  if (startDemoBtn) {
    startDemoBtn.disabled = false;
    startDemoBtn.innerHTML = '🚀 Start Demo';
  }
  
  if (!demoOutput) return;
  
  if (!results || results.length === 0) {
    demoOutput.innerHTML = `
      <div class="result-card passed">
        <h4>✅ No Vulnerabilities Found</h4>
        <p>The security scan completed successfully with no issues detected.</p>
      </div>
    `;
    demoOutput.style.display = 'block';
    return;
  }
  
  let html = '<h3>🚨 Vulnerabilities Detected</h3>';
  
  results.forEach(r => {
    const severityClass = (r.severity || 'low').toLowerCase();
    const icon = severityClass === 'high' ? '🔴' : severityClass === 'medium' ? '🟡' : '🟢';
    
    html += `
      <div class="vuln-card">
        <h4>${icon} ${r.name || r.attack || 'Vulnerability'}</h4>
        <span class="severity ${severityClass}">${r.severity || 'Unknown'} Severity</span>
        
        <details>
          <summary>Why detected?</summary>
          <p>${r.explanation || r.why || 'Analysis completed by Observer agent.'}</p>
        </details>
        
        <details>
          <summary>Mitigation</summary>
          <ul>
            ${r.mitigation ? r.mitigation.split('\n').map(m => `<li>${m}</li>`).join('') : '<li>Apply security best practices</li>'}
          </ul>
        </details>
      </div>
    `;
  });
  
  // Add PDF download button
  html += `
    <button id="downloadPdfBtn" class="btn btn-secondary" style="margin-top: 16px;" onclick="downloadDemoReport()">
      📄 Download Explainable Report (PDF)
    </button>
  `;
  
  demoOutput.innerHTML = html;
  demoOutput.style.display = 'block';
  
  // Store results for PDF generation
  window.latestDemoResult = {
    scan_id: currentDemoScanId,
    results: results
  };
}

function showDemoStatus(message) {
  if (demoOutput) {
    demoOutput.style.display = 'block';
    demoOutput.innerHTML = `
      <div class="info-box">
        <p>${message}</p>
        <div class="loading-spinner"></div>
      </div>
    `;
  }
}

function showDemoError(message) {
  if (demoOutput) {
    demoOutput.style.display = 'block';
    demoOutput.innerHTML = `
      <div class="result-card failed">
        <h4>❌ Error</h4>
        <p>${message}</p>
      </div>
    `;
  }
  
  // Re-enable button
  if (startDemoBtn) {
    startDemoBtn.disabled = false;
    startDemoBtn.innerHTML = '🚀 Start Demo';
  }
}

function resetAgentDisplay() {
  const agents = ['a-profile', 'a-strategy', 'a-execute', 'a-observe'];
  agents.forEach(id => {
    const el = document.getElementById(id);
    if (el) {
      el.classList.remove('active', 'done');
      el.classList.add('waiting');
    }
  });
  
  if (demoOutput) {
    demoOutput.style.display = 'none';
    demoOutput.innerHTML = '';
  }
}

async function downloadDemoReport() {
  const token = localStorage.getItem('token');
  const result = window.latestDemoResult;
  
  if (!result || !result.results) {
    alert('No scan available. Please run a scan first.');
    return;
  }
  
  try {
    const response = await fetch(`${DEMO_API_BASE}/report/generate`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        target: 'Demo Target',
        results: result.results,
        scan_id: result.scan_id
      })
    });
    
    if (response.ok) {
      const data = await response.json();
      if (data.download_url) {
        window.open(data.download_url, '_blank');
      }
    } else {
      alert('Failed to generate PDF report');
    }
  } catch (e) {
    console.error('PDF generation error:', e);
    alert('Failed to generate PDF: ' + e.message);
  }
}

// Export functions for global access
window.downloadDemoReport = downloadDemoReport;
window.handleDemoStart = handleDemoStart;

