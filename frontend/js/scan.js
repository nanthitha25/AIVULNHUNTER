// scan.js - Handles the frontend scan UI logic and API calls
const API_URL = "http://127.0.0.1:8000"; // Assuming backend is on 8000

async function startUnifiedScan() {
    const targetUrl = document.getElementById('scanTarget').value;
    const scanTypeRaw = document.getElementById('scanType').value;
    const scanBtn = document.getElementById('scanBtn');
    const resultsDiv = document.getElementById('scanResults');
    const explainBox = document.getElementById('explainBox');

    if (!targetUrl) {
        alert("Please enter a Target URL");
        return;
    }

    // Map frontend scan type to backend target_type
    let targetType = "LLM";
    if (scanTypeRaw === "API") targetType = "API";

    scanBtn.disabled = true;
    scanBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Scanning...';
    resultsDiv.innerHTML = '<p class="muted">Scan in progress... Please wait.</p>';
    explainBox.style.display = 'none';

    // Reset timeline
    updateTimeline('agent-profile', 'RUNNING');
    updateTimeline('agent-strategy', 'WAITING');
    updateTimeline('agent-execute', 'WAITING');
    updateTimeline('agent-observer', 'WAITING');

    const token = localStorage.getItem('token');

    try {
        const payload = {
            target: targetUrl,
            target_type: targetType
        };

        const response = await fetch(`${API_URL}/scan/`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                ...(token ? { 'Authorization': `Bearer ${token}` } : {})
            },
            body: JSON.stringify(payload)
        });

        if (!response.ok) {
            const errBase = await response.json();
            throw new Error(errBase.detail || "Scan failed or free limit reached. Please log in.");
        }

        // Pseudo progress updates for visual effect
        setTimeout(() => { updateTimeline('agent-profile', 'COMPLETED'); updateTimeline('agent-strategy', 'RUNNING'); }, 1000);
        setTimeout(() => { updateTimeline('agent-strategy', 'COMPLETED'); updateTimeline('agent-execute', 'RUNNING'); }, 2000);
        setTimeout(() => { updateTimeline('agent-execute', 'COMPLETED'); updateTimeline('agent-observer', 'RUNNING'); }, 3500);

        const kickoffData = await response.json();
        const scanId = kickoffData.scan_id;

        setTimeout(async () => {
            try {
                const res = await fetch(`${API_URL}/scan/${scanId}`, {
                    headers: {
                        ...(token ? { 'Authorization': `Bearer ${token}` } : {})
                    }
                });
                const finalData = await res.json();
                currentScanData = finalData;
                updateTimeline('agent-observer', 'COMPLETED');

                // Set total_risk attribute if missing
                if (finalData.risk_summary) {
                    finalData.total_risk = finalData.risk_summary.overall_risk_score;
                } else if (finalData.results) {
                    finalData.total_risk = finalData.results.reduce((acc, r) => acc + (r.risk_score || 0), 0);
                }

                renderResults(finalData);
            } catch (err) {
                console.error("Error fetching results:", err);
                resultsDiv.innerHTML = `<p style="color:red">Failed to load final scan results.</p>`;
            }
            scanBtn.disabled = false;
            scanBtn.innerHTML = '<i class="fa-solid fa-rocket"></i> Start Scan';
        }, 4500);

    } catch (error) {
        resultsDiv.innerHTML = `<p style="color:red">Error: ${error.message}</p>`;
        scanBtn.disabled = false;
        scanBtn.innerHTML = '<i class="fa-solid fa-rocket"></i> Start Scan';

        updateTimeline('agent-profile', 'ERROR');
        updateTimeline('agent-strategy', 'ERROR');
        updateTimeline('agent-execute', 'ERROR');
        updateTimeline('agent-observer', 'ERROR');
    }
}

function renderResults(data) {
    const resultsDiv = document.getElementById('scanResults');
    const explainBox = document.getElementById('explainBox');

    if (!data.results || data.results.length === 0) {
        resultsDiv.innerHTML = `<p class="muted">No vulnerabilities detected! Risk Score: ${data.total_risk || 0}/10</p>`;
        return;
    }

    let html = `<h4>Total Risk Score: ${(data.total_risk || 0).toFixed(1)}/10</h4>`;
    html += `<ul class="vuln-list">`;

    data.results.forEach(res => {
        let severityClass = res.status === 'DETECTED' ? 'high' : 'low';
        html += `
            <li class="vuln-item">
                <span class="tag ${severityClass}">${res.status}</span>
                <strong>${res.rule_name || res.rule_id} (${res.owasp_category || 'General'})</strong>
                <p>${res.details || res.explanation || 'No details'}</p>
                <div class="mitigation"><strong>Mitigation:</strong> ${res.mitigation || 'N/A'}</div>
            </li>
        `;
    });

    html += `</ul>`;
    resultsDiv.innerHTML = html;

    // Show explain box for first detected issue
    const firstVuln = data.results.find(r => r.status === 'DETECTED');
    if (firstVuln) {
        explainBox.style.display = 'block';
        document.getElementById('vulnSeverity').textContent = firstVuln.status;
        document.getElementById('vulnName').textContent = firstVuln.rule_name || firstVuln.rule_id;
        document.getElementById('vulnReason').textContent = firstVuln.details || firstVuln.explanation || "Vulnerability behavior was observed in target response.";
        document.getElementById('aiReasoning').textContent = `Evidence:\n` + (firstVuln.evidence || firstVuln.details || "No explicit evidence collected.");
    }
}

function toggleScanInput() {
    const type = document.getElementById('scanType').value;
    if (type === 'DATASET') {
        document.getElementById('urlInput').style.display = 'none';
        document.getElementById('datasetInput').style.display = 'block';
    } else {
        document.getElementById('urlInput').style.display = 'block';
        document.getElementById('datasetInput').style.display = 'none';
    }
}

// Store the latest scan data globally so we can generate the PDF
let currentScanData = null;

function downloadReport() {
    if (!currentScanData) {
        alert("Please run a scan first to generate a report.");
        return;
    }

    const token = localStorage.getItem('token');

    // We can't fetch files directly via JSON, we need to handle it as a blob
    fetch(`${API_URL}/scan/report`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            ...(token ? { "Authorization": `Bearer ${token}` } : {})
        },
        body: JSON.stringify(currentScanData)
    })
        .then(res => {
            if (!res.ok) throw new Error("Failed to generate PDF report");
            return res.blob();
        })
        .then(blob => {
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = `aivulnhunter_report_${currentScanData.scan_id.substring(0, 8)}.pdf`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            a.remove();
        })
        .catch(err => {
            console.error("PDF generation error:", err);
            alert("Sorry, an error occurred while downloading the report.");
        });
}
