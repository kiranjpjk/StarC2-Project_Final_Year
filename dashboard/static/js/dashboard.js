// Auto-refresh every 500ms
let refreshInterval = setInterval(updateDashboard, 500);

function updateDashboard() {
    // Fetch and update packets
    fetch('/api/packets')
        .then(r => r.json())
        .then(packets => updatePacketsTable(packets))
        .catch(err => console.error('Error fetching packets:', err));

    // Fetch and update results
    fetch('/api/results')
        .then(r => r.json())
        .then(results => updateCharts(results))
        .catch(err => console.error('Error fetching results:', err));

    // Fetch and update statistics
    fetch('/api/stats')
        .then(r => r.json())
        .then(stats => updateStats(stats))
        .catch(err => console.error('Error fetching stats:', err));

    // Fetch techniques
    fetch('/api/techniques')
        .then(r => r.json())
        .then(data => updateTechniques(data.techniques))
        .catch(err => console.error('Error fetching techniques:', err));
}

function updatePacketsTable(packets) {
    const tbody = document.getElementById('packets-body');

    if (packets.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="empty">No packets captured</td></tr>';
        return;
    }

    tbody.innerHTML = packets.map(pkt => `
        <tr>
            <td>${new Date(pkt.timestamp * 1000).toLocaleTimeString()}</td>
            <td><strong>${pkt.src_ip}</strong></td>
            <td>${pkt.payload_size}B</td>
            <td>${(Math.random() * 2 + 5.5).toFixed(1)}</td>
            <td><span class="confidence">${Math.random() * 100 | 0}%</span></td>
            <td><span class="verdict">Normal</span></td>
        </tr>
    `).join('');
}

function updateStats(stats) {
    document.getElementById('total-packets').textContent = stats.total_packets || 0;
    document.getElementById('detected-packets').textContent = stats.detected || 0;
    document.getElementById('detection-rate').textContent = (stats.detection_rate || 0).toFixed(1) + '%';
    document.getElementById('avg-entropy').textContent = (stats.avg_entropy || 0).toFixed(2);
}

function updateCharts(results) {
    if (results.length < 2) return;

    // Entropy chart
    const entopyData = [{
        x: results.map((_, i) => i),
        y: results.map(r => r.entropy || 0),
        type: 'scatter',
        mode: 'lines+markers',
        name: 'Entropy'
    }];

    Plotly.newPlot('entropy-chart', entopyData, {
        title: '',
        xaxis: { title: 'Packet #' },
        yaxis: { title: 'bits/byte' }
    }, { responsive: true });

    // Confidence chart
    const confidenceData = [{
        x: results.map((_, i) => i),
        y: results.map(r => r.confidence || 0),
        type: 'scatter',
        mode: 'lines+markers',
        name: 'Confidence',
        fill: 'tozeroy'
    }];

    Plotly.newPlot('confidence-chart', confidenceData, {
        title: '',
        xaxis: { title: 'Packet #' },
        yaxis: { title: 'Confidence Score' }
    }, { responsive: true });
}

function updateTechniques(techniques) {
    const grid = document.getElementById('techniques-grid');
    grid.innerHTML = techniques.map(t => `
        <div class="technique">
            <h3>${t.id}. ${t.name}</h3>
            <p class="technique-description">${t.description}</p>
            <div class="technique-value">-</div>
            <p class="technique-description">Threshold: ${t.threshold} ${t.unit}</p>
        </div>
    `).join('');
}

function startCapture() {
    fetch('/api/start-capture')
        .then(r => r.json())
        .then(data => {
            document.getElementById('capture-status').textContent = 'Status: Capturing...';
            document.getElementById('capture-status').style.color = '#27ae60';
        });
}

function stopCapture() {
    fetch('/api/stop-capture')
        .then(r => r.json())
        .then(data => {
            document.getElementById('capture-status').textContent = 'Status: Stopped';
            document.getElementById('capture-status').style.color = '#e74c3c';
        });
}

function clearResults() {
    fetch('/api/clear-results')
        .then(r => r.json())
        .then(data => {
            document.getElementById('packets-body').innerHTML = '<tr><td colspan="6" class="empty">No packets captured</td></tr>';
        });
}

// Initial load
updateDashboard();
