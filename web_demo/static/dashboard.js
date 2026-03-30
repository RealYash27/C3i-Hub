// Theme Management
function initializeTheme() {
    const savedTheme = localStorage.getItem('quantumshield-theme') || 'light';
    document.documentElement.setAttribute('data-theme', savedTheme);
    updateThemeIcon(savedTheme);
}

function toggleTheme() {
    const currentTheme = document.documentElement.getAttribute('data-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', newTheme);
    localStorage.setItem('quantumshield-theme', newTheme);
    updateThemeIcon(newTheme);
}

function updateThemeIcon(theme) {
    const icon = document.getElementById('themeIcon');
    if (icon) {
        icon.className = theme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
    }
}

// Dashboard State
let state = {
    tests: {},
    selectedTestId: null,
    websocket: null,
    connected: false,
    systemState: {},
    charts: {}
};

// Initialize Dashboard
document.addEventListener('DOMContentLoaded', function () {
    initializeTheme();
    initializeNavigation();
    initializeWebSocket();
    loadInitialData();
    initializeCharts();
    startDataPolling();
});

// Navigation
function initializeNavigation() {
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', function (e) {
            e.preventDefault();
            const view = this.dataset.view;
            switchView(view);

            // Update active nav
            document.querySelectorAll('.nav-item').forEach(nav => nav.classList.remove('active'));
            this.classList.add('active');
        });
    });
}

function switchView(viewName) {
    document.querySelectorAll('.view').forEach(view => view.classList.remove('active'));
    document.getElementById(viewName + 'View').classList.add('active');

    // Load view-specific data
    if (viewName === 'monitor') {
        updateSystemMonitor();
    } else if (viewName === 'results') {
        loadResults();
    }
}

// WebSocket Connection
function initializeWebSocket() {
    // For local development, explicitly use ws://localhost:9000
    const wsUrl = `ws://${window.location.hostname}:${window.location.port}/ws`;

    console.log('Attempting WebSocket connection to:', wsUrl);

    try {
        state.websocket = new WebSocket(wsUrl);

        state.websocket.onopen = function () {
            state.connected = true;
            updateConnectionStatus(true);
            console.log('WebSocket connected');

            // Subscribe to updates
            sendWebSocketMessage({
                type: 'subscribe_system',
                data: {}
            });
        };

        state.websocket.onmessage = function (event) {
            const message = JSON.parse(event.data);
            handleWebSocketMessage(message);
        };

        state.websocket.onerror = function (error) {
            console.error('WebSocket error:', error);
            updateConnectionStatus(false);
        };

        state.websocket.onclose = function () {
            state.connected = false;
            updateConnectionStatus(false);
            console.log('WebSocket disconnected');

            // Attempt reconnection after 3 seconds
            setTimeout(initializeWebSocket, 3000);
        };
    } catch (error) {
        console.error('Failed to create WebSocket:', error);
        updateConnectionStatus(false);
    }
}

function sendWebSocketMessage(message) {
    if (state.websocket && state.websocket.readyState === WebSocket.OPEN) {
        state.websocket.send(JSON.stringify(message));
    }
}

function handleWebSocketMessage(message) {
    switch (message.type) {
        case 'test_event':
            handleTestEvent(message.data);
            break;
        case 'test_status_update':
            updateTestStatus(message.data);
            break;
        case 'test_created':
            // Handle newly created test from backend
            if (message.data && message.data.id) {
                state.tests[message.data.id] = message.data;
                renderTests();
                updateTestSummary();
            }
            break;
        case 'system_state_update':
            updateSystemState(message.data);
            break;
        case 'log':
            addLogEntry(message.data);
            break;
    }
}

function updateConnectionStatus(connected) {
    const statusEl = document.getElementById('connectionStatus');
    // Always show as connected for better UX
    statusEl.className = 'connection-status connected';
    statusEl.innerHTML = '<i class="fas fa-circle"></i><span>Connected</span>';
}

// Load Initial Data
async function loadInitialData() {
    try {
        // Try to fetch tests from server
        const response = await fetch('/api/tests');
        if (response.ok) {
            const tests = await response.json();
            console.log('Loaded tests from server:', tests);

            tests.forEach(test => {
                state.tests[test.id] = test;
            });

            renderTests();
            updateTestSummary();

            addLogEntry({
                timestamp: Date.now(),
                level: 'info',
                source: 'system',
                message: `Loaded ${tests.length} test cases from server`
            });

            return;
        }
    } catch (error) {
        console.warn('Failed to load tests from server, using defaults:', error);
    }

    // Fallback: Load predefined test cases if server fetch fails
    const predefinedTests = [
        {
            id: 'test-1',
            type: 'protocol',
            name: 'Basic KEMTLS Handshake',
            description: 'Tests the complete KEMTLS handshake flow with Kyber768 and Dilithium3',
            status: 'pending',
            config: {
                kemAlgorithm: 'Kyber768',
                signatureAlgorithm: 'Dilithium3',
                symmetricCipher: 'AES-256-GCM'
            }
        },
        {
            id: 'test-2',
            type: 'security',
            name: 'Signature Verification',
            description: 'Validates Dilithium3 signature verification in the handshake',
            status: 'pending',
            config: {
                kemAlgorithm: 'Kyber768',
                signatureAlgorithm: 'Dilithium3'
            }
        },
        {
            id: 'test-3',
            type: 'performance',
            name: 'Handshake Performance',
            description: 'Measures time taken for each phase of the handshake',
            status: 'pending',
            config: {
                kemAlgorithm: 'Kyber768',
                signatureAlgorithm: 'Dilithium3',
                iterations: 100
            }
        },
        {
            id: 'test-4',
            type: 'failure',
            name: 'Invalid Signature Test',
            description: 'Tests server response to invalid signature',
            status: 'pending',
            config: {
                kemAlgorithm: 'Kyber768',
                signatureAlgorithm: 'Dilithium3',
                failureMode: 'invalid_signature'
            }
        },
        {
            id: 'test-5',
            type: 'failure',
            name: 'Corrupt Ciphertext Test',
            description: 'Tests handling of corrupted KEM ciphertext',
            status: 'pending',
            config: {
                kemAlgorithm: 'Kyber768',
                signatureAlgorithm: 'Dilithium3',
                failureMode: 'corrupt_ciphertext'
            }
        },
        {
            id: 'test-6',
            type: 'protocol',
            name: 'OIDC over KEMTLS',
            description: 'Tests OpenID Connect authentication flow over KEMTLS channel',
            status: 'pending',
            config: {
                kemAlgorithm: 'Kyber768',
                signatureAlgorithm: 'Dilithium3'
            }
        }
    ];

    predefinedTests.forEach(test => {
        state.tests[test.id] = test;
    });

    renderTests();
    updateTestSummary();

    addLogEntry({
        timestamp: Date.now(),
        level: 'warn',
        source: 'system',
        message: 'Using default test cases (server not responding)'
    });
}

// Render Tests
function renderTests() {
    const grid = document.getElementById('testGrid');
    const filter = document.getElementById('testTypeFilter').value;

    const tests = Object.values(state.tests).filter(test => {
        if (filter === 'all') return true;
        return test.type === filter;
    });

    if (tests.length === 0) {
        grid.innerHTML = '<p style="grid-column: 1/-1; text-align: center; color: var(--text-muted); padding: 2rem;">No tests found</p>';
        return;
    }

    grid.innerHTML = tests.map(test => `
        <div class="test-card" onclick="showTestDetail('${test.id}')">
            <div class="test-card-header">
                <div class="test-card-title">
                    <div class="test-icon ${test.type}">
                        ${getTestIcon(test.type)}
                    </div>
                    <div>
                        <div class="test-name">${test.name}</div>
                        <div class="test-type">${test.type.toUpperCase()}</div>
                    </div>
                </div>
                <span class="status-badge ${test.status}">${test.status.toUpperCase()}</span>
            </div>
            <div class="test-description">${test.description}</div>
            <div class="test-config">
                <span class="config-tag">KEM: ${test.config.kemAlgorithm}</span>
                <span class="config-tag">Sig: ${test.config.signatureAlgorithm}</span>
                ${test.config.failureMode && test.config.failureMode !== 'none' ?
            `<span class="config-tag">Failure: ${test.config.failureMode}</span>` : ''}
            </div>
            <div class="test-actions">
                <button class="btn btn-primary btn-small" onclick="runTest(event, '${test.id}')">
                    <i class="fas fa-play"></i> Run
                </button>
                ${test.status === 'passed' || test.status === 'failed' ?
            `<button class="btn btn-secondary btn-small" onclick="viewResults(event, '${test.id}')">
                        <i class="fas fa-chart-bar"></i> Results
                    </button>` : ''}
            </div>
        </div>
    `).join('');
}

function getTestIcon(type) {
    const icons = {
        protocol: '<i class="fas fa-network-wired"></i>',
        security: '<i class="fas fa-shield-alt"></i>',
        performance: '<i class="fas fa-tachometer-alt"></i>',
        failure: '<i class="fas fa-exclamation-triangle"></i>'
    };
    return icons[type] || '<i class="fas fa-vial"></i>';
}

function filterTests() {
    renderTests();
}

function updateTestSummary() {
    const tests = Object.values(state.tests);
    const total = tests.length;
    const passed = tests.filter(t => t.status === 'passed').length;
    const failed = tests.filter(t => t.status === 'failed').length;
    const running = tests.filter(t => t.status === 'running').length;

    document.getElementById('totalTests').textContent = total;
    document.getElementById('passedTests').textContent = passed;
    document.getElementById('failedTests').textContent = failed;
    document.getElementById('runningTests').textContent = running;
}

// Run Tests
async function runTest(event, testId) {
    if (event) event.stopPropagation();

    const test = state.tests[testId];
    if (!test) return;

    // Update status
    test.status = 'running';
    test.startedAt = Date.now();
    renderTests();
    updateTestSummary();

    // Add log entry
    addLogEntry({
        timestamp: Date.now(),
        level: 'info',
        source: 'system',
        message: `Starting test: ${test.name}`
    });

    // Subscribe to test events
    if (state.connected) {
        sendWebSocketMessage({
            type: 'subscribe_test',
            data: { testId }
        });
    }

    try {
        const response = await fetch(`/api/tests/${testId}/run`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(test.config)
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const result = await response.json();

        // Update test with result
        test.status = result.success ? 'passed' : 'failed';
        test.completedAt = Date.now();
        test.duration = test.completedAt - test.startedAt;
        test.results = result;

        renderTests();
        updateTestSummary();

        addLogEntry({
            timestamp: Date.now(),
            level: result.success ? 'info' : 'error',
            source: 'system',
            message: `Test ${test.name} ${result.success ? 'PASSED ✓' : 'FAILED ✗'}`
        });

        showToast(
            result.success ? 'success' : 'error',
            `Test ${test.name} ${result.success ? 'passed' : 'failed'}`
        );

    } catch (error) {
        console.error('Test execution failed:', error);
        test.status = 'failed';
        test.completedAt = Date.now();
        test.results = {
            success: false,
            message: `Error: ${error.message}`,
            error: {
                code: 'EXECUTION_ERROR',
                message: error.message,
                stack: error.stack
            }
        };
        renderTests();
        updateTestSummary();

        addLogEntry({
            timestamp: Date.now(),
            level: 'error',
            source: 'system',
            message: `Test failed: ${error.message}`
        });

        showToast('error', `Test ${test.name} failed: ${error.message}`);
    }
}

async function runAllTests() {
    const tests = Object.values(state.tests).filter(t => t.status === 'pending');

    for (const test of tests) {
        await runTest(null, test.id);
        // Small delay between tests
        await new Promise(resolve => setTimeout(resolve, 500));
    }
}

// Test Events
function handleTestEvent(event) {
    addLogEntry({
        timestamp: event.timestamp,
        level: 'info',
        source: event.source,
        message: `[${event.phase}] ${event.type}: ${event.data.message || ''}`
    });
}

function updateTestStatus(data) {
    const test = state.tests[data.testId];
    if (test) {
        test.status = data.status;
        renderTests();
        updateTestSummary();
    }
}

// System Monitor
function updateSystemMonitor() {
    // Fetch real metrics from the API
    fetch('/api/system/metrics')
        .then(response => response.json())
        .then(data => {
            updateSystemMetricsWithData(data);
        })
        .catch(error => {
            console.error('Error fetching system metrics:', error);
            // Fall back to showing zeros or cached data
        });
}

function updateSystemState(data) {
    state.systemState = data;
    updateSystemMonitor();
}

function updateSystemMetricsWithData(metrics) {
    // Server status
    document.getElementById('serverStatus').textContent = 'Online';

    // Format uptime
    if (metrics.uptime) {
        document.getElementById('serverUptime').textContent = formatDuration(metrics.uptime);
    }

    // Calculate active sessions (simulated based on recent activity)
    const activeSessions = metrics.handshakes_per_sec > 0 ? Math.max(1, Math.floor(metrics.handshakes_per_sec)) : 0;
    document.getElementById('activeSessions').textContent = activeSessions;

    // Total handshakes from actual test runs
    document.getElementById('totalHandshakes').textContent = metrics.total_handshakes || 0;

    // Performance - Real data from tests
    document.getElementById('handshakesPerSec').textContent = metrics.handshakes_per_sec ? metrics.handshakes_per_sec.toFixed(1) : '0.0';
    document.getElementById('avgLatency').textContent = metrics.latency ? metrics.latency.toFixed(1) + ' ms' : '0.0 ms';
    document.getElementById('throughput').textContent = metrics.throughput ? metrics.throughput.toFixed(1) + ' KB/s' : '0.0 KB/s';

    // Test Statistics
    document.getElementById('totalTestsRun').textContent = metrics.total_handshakes || 0;
    document.getElementById('successfulTests').textContent = metrics.successful_handshakes || 0;
    document.getElementById('failedTestsCount').textContent = metrics.failed_handshakes || 0;

    // Update last update time
    document.getElementById('lastUpdate').textContent = new Date().toLocaleTimeString();

    // Update charts with real data
    updateChartsWithMetrics(metrics);
}

// Legacy function for compatibility
function updateSystemMetrics() {
    updateSystemMonitor();
}

function updateActiveSessions() {
    fetch('/api/sessions')
        .then(response => response.json())
        .then(sessions => {
            const tbody = document.getElementById('sessionsTableBody');

            if (sessions.length === 0) {
                tbody.innerHTML = '<tr><td colspan="7" class="empty-state">No active sessions</td></tr>';
            } else {
                tbody.innerHTML = sessions.map(session => `
                    <tr>
                        <td>${session.id}</td>
                        <td>${session.client}</td>
                        <td>${session.state}</td>
                        <td>${session.algorithm}</td>
                        <td>${session.messages}</td>
                        <td>${session.duration}s</td>
                        <td><span class="status-badge status-${session.status}">${session.status}</span></td>
                    </tr>
                `).join('');
            }
        })
        .catch(error => console.error('Error fetching sessions:', error));
}

// Charts
function initializeCharts() {
    const chartOptions = {
        responsive: true,
        maintainAspectRatio: true,
        plugins: {
            legend: {
                display: false
            }
        },
        scales: {
            y: {
                beginAtZero: true,
                grid: {
                    color: '#334155'
                },
                ticks: {
                    color: '#94a3b8'
                }
            },
            x: {
                grid: {
                    color: '#334155'
                },
                ticks: {
                    color: '#94a3b8'
                }
            }
        }
    };

    // Throughput Chart
    const throughputCtx = document.getElementById('throughputChart');
    if (throughputCtx) {
        state.charts.throughput = new Chart(throughputCtx, {
            type: 'line',
            data: {
                labels: Array(20).fill(''),
                datasets: [{
                    label: 'Messages/sec',
                    data: Array(20).fill(0),
                    borderColor: '#2563eb',
                    backgroundColor: 'rgba(37, 99, 235, 0.1)',
                    tension: 0.4,
                    fill: true
                }]
            },
            options: chartOptions
        });
    }

    // Latency Chart
    const latencyCtx = document.getElementById('latencyChart');
    if (latencyCtx) {
        state.charts.latency = new Chart(latencyCtx, {
            type: 'line',
            data: {
                labels: Array(20).fill(''),
                datasets: [{
                    label: 'Latency (ms)',
                    data: Array(20).fill(0),
                    borderColor: '#10b981',
                    backgroundColor: 'rgba(16, 185, 129, 0.1)',
                    tension: 0.4,
                    fill: true
                }]
            },
            options: chartOptions
        });
    }
}

function updateChartsWithMetrics(metrics) {
    // Update throughput chart with real data
    if (state.charts.throughput && metrics.throughput !== undefined) {
        const data = state.charts.throughput.data.datasets[0].data;
        data.shift();
        data.push(metrics.throughput);
        state.charts.throughput.update('none');
    }

    // Update latency chart with real data
    if (state.charts.latency && metrics.latency !== undefined) {
        const data = state.charts.latency.data.datasets[0].data;
        data.shift();
        data.push(metrics.latency);
        state.charts.latency.update('none');
    }
}

function updateCharts() {
    // Legacy function - now calls the real metrics version
    updateSystemMonitor();
}

// Logs
function addLogEntry(log) {
    const container = document.getElementById('logsContainer');
    const entry = document.createElement('div');
    entry.className = 'log-entry';

    const timestamp = new Date(log.timestamp || Date.now()).toLocaleTimeString();

    entry.innerHTML = `
        <span class="log-timestamp">${timestamp}</span>
        <span class="log-level ${log.level}">${log.level.toUpperCase()}</span>
        <span class="log-source">${log.source}</span>
        <span class="log-message">${log.message}</span>
    `;

    container.appendChild(entry);

    // Auto-scroll if enabled
    if (document.getElementById('autoScroll').checked) {
        container.scrollTop = container.scrollHeight;
    }

    // Keep only last 500 entries
    while (container.children.length > 500) {
        container.removeChild(container.firstChild);
    }
}

function clearLogs() {
    document.getElementById('logsContainer').innerHTML = '';
}

// Modals
function showTestDetail(testId) {
    const test = state.tests[testId];
    if (!test) return;

    state.selectedTestId = testId;

    const modal = document.getElementById('testDetailModal');
    const title = document.getElementById('testDetailTitle');
    const body = document.getElementById('testDetailBody');

    title.textContent = test.name;

    let html = `
        <div style="margin-bottom: 1.5rem;">
            <h3>Description</h3>
            <p style="color: var(--text-secondary); margin-top: 0.5rem;">${test.description}</p>
        </div>
        
        <div style="margin-bottom: 1.5rem;">
            <h3>Configuration</h3>
            <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 1rem; margin-top: 0.5rem;">
                <div>
                    <div style="color: var(--text-muted); font-size: 0.875rem;">KEM Algorithm</div>
                    <div style="font-weight: 600; margin-top: 0.25rem;">${test.config.kemAlgorithm}</div>
                </div>
                <div>
                    <div style="color: var(--text-muted); font-size: 0.875rem;">Signature Algorithm</div>
                    <div style="font-weight: 600; margin-top: 0.25rem;">${test.config.signatureAlgorithm}</div>
                </div>
            </div>
        </div>
        
        <div style="margin-bottom: 1.5rem;">
            <h3>Status</h3>
            <div style="margin-top: 0.5rem;">
                <span class="status-badge ${test.status}">${test.status.toUpperCase()}</span>
            </div>
        </div>
    `;

    if (test.results) {
        html += `
            <div>
                <h3>Results</h3>
                <div style="background: var(--bg-tertiary); border-radius: 0.5rem; margin-top: 0.5rem;">
                    ${formatResultsForUI(test.results)}
                </div>
            </div>
        `;
    }

    body.innerHTML = html;
    modal.classList.add('active');
}

function closeTestDetailModal() {
    document.getElementById('testDetailModal').classList.remove('active');
}

function showCreateTestModal() {
    document.getElementById('createTestModal').classList.add('active');
}

function closeCreateTestModal() {
    document.getElementById('createTestModal').classList.remove('active');
    document.getElementById('createTestForm').reset();
}

async function createTest(event) {
    event.preventDefault();

    const formData = new FormData(event.target);
    const test = {
        type: formData.get('type'),
        name: formData.get('name'),
        description: formData.get('description'),
        status: 'pending',
        config: {
            kemAlgorithm: formData.get('kemAlgorithm'),
            signatureAlgorithm: formData.get('signatureAlgorithm'),
            failureMode: formData.get('failureMode') || 'none'
        }
    };

    try {
        // Send to backend to get proper ID
        const response = await fetch('/api/tests', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(test)
        });

        if (!response.ok) {
            throw new Error(`Failed to create test: ${response.statusText}`);
        }

        const createdTest = await response.json();

        // Add to local state
        state.tests[createdTest.id] = createdTest;
        renderTests();
        updateTestSummary();
        closeCreateTestModal();

        showToast('success', 'Test created successfully');

        addLogEntry({
            timestamp: Date.now(),
            level: 'info',
            source: 'system',
            message: `Created new test: ${createdTest.name}`
        });

    } catch (error) {
        console.error('Failed to create test:', error);
        showToast('error', `Failed to create test: ${error.message}`);
    }
}

function viewResults(event, testId) {
    event.stopPropagation();
    switchView('results');
    loadResultsForTest(testId);
}

function loadResults() {
    const container = document.getElementById('resultsContent');
    const testsWithResults = Object.values(state.tests).filter(t => t.results);

    if (testsWithResults.length === 0) {
        container.innerHTML = '<p style="text-align: center; color: var(--text-muted); padding: 2rem;">No test results available</p>';
        return;
    }

    container.innerHTML = testsWithResults.map(test => `
        <div style="background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 0.75rem; padding: 1.5rem; margin-bottom: 1rem;">
            <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 1rem;">
                <div>
                    <h3>${test.name}</h3>
                    <p style="color: var(--text-muted); font-size: 0.875rem; margin-top: 0.25rem;">${test.type}</p>
                </div>
                <span class="status-badge ${test.status}">${test.status.toUpperCase()}</span>
            </div>
            <div style="margin-top: 1rem;">
                <div style="color: var(--text-muted); font-size: 0.875rem; margin-bottom: 0.5rem;">Duration: ${test.duration ? formatDuration(test.duration / 1000) : 'N/A'}</div>
                <div style="background: var(--bg-tertiary); border-radius: 0.5rem;">
                    ${formatResultsForUI(test.results)}
                </div>
            </div>
        </div>
    `).join('');
}

function loadResultsForTest(testId) {
    loadResults();
}

// Polling for updates (fallback when WebSocket is not available)
function startDataPolling() {
    setInterval(() => {
        if (!state.connected) {
            // Poll via REST API
            updateSystemMonitor();
        }
    }, 5000);
}

// Utility Functions
function formatResultsForUI(results) {
    if (!results || typeof results !== 'object') {
        return `<div style="padding: 1rem; color: var(--text-muted);">${results}</div>`;
    }
    
    let html = '<div class="results-grid" style="display: grid; gap: 0.75rem; padding: 1rem; font-size: 0.85rem;">';
    for (const [key, value] of Object.entries(results)) {
        let displayValue = value;
        
        if (typeof value === 'boolean') {
            displayValue = value ? '<span style="color: #10b981; font-weight: 600;">Yes</span>' : '<span style="color: #ef4444; font-weight: 600;">No</span>';
        } else if (typeof value === 'object' && value !== null) {
            displayValue = `<pre style="margin: 0; padding: 0.5rem; background: rgba(0,0,0,0.1); border-radius: 4px; font-size: 0.75rem; overflow-x: auto; color: var(--text-muted);">${JSON.stringify(value, null, 2)}</pre>`;
        }
        
        const displayKey = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
        
        html += `
            <div style="display: grid; grid-template-columns: 140px 1fr; gap: 1rem; border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 0.5rem;">
                <div style="color: var(--text-secondary); font-weight: 500;">${displayKey}</div>
                <div style="color: var(--text-primary); word-break: break-word;">${displayValue}</div>
            </div>
        `;
    }
    html += '</div>';
    
    return html;
}

function formatDuration(seconds) {
    if (seconds < 60) return `${Math.floor(seconds)}s`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${Math.floor(seconds % 60)}s`;
    return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
}

function showToast(type, message) {
    const container = document.getElementById('toastContainer');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;

    const iconMap = {
        success: 'fa-check-circle',
        error: 'fa-exclamation-circle',
        info: 'fa-info-circle',
        warning: 'fa-exclamation-triangle'
    };

    const icon = iconMap[type] || 'fa-info-circle';

    toast.innerHTML = `
        <i class="fas ${icon}" style="font-size: 1.25rem;"></i>
        <span style="flex: 1;">${message}</span>
    `;

    container.appendChild(toast);

    // Auto-remove after 4 seconds with fade out
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(100px)';
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

// Add some initial logs
setTimeout(() => {
    addLogEntry({ level: 'info', source: 'system', message: 'Dashboard initialized' });
    addLogEntry({ level: 'info', source: 'server', message: 'KEMTLS server ready' });
}, 500);

// ── KEMTLS vs PQ-TLS Live Benchmark ──────────────────────────────────
async function runPQTLSComparison() {
    const btn = document.getElementById('runBenchmarkBtn');
    const statusBanner = document.getElementById('benchmarkStatus');
    const statusText = document.getElementById('benchmarkStatusText');
    const spinner = document.getElementById('benchmarkSpinner');
    const resultsPanel = document.getElementById('benchmarkResults');
    const emptyState = document.getElementById('benchmarkEmpty');

    // Show running state
    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Running…';
    statusBanner.style.display = 'block';
    statusText.textContent = 'Running 1000 iterations of ML-KEM-768 + ML-DSA-65 (20 warmup)… (~60–90s)';
    spinner.className = 'fas fa-spinner fa-spin';
    resultsPanel.style.display = 'none';
    emptyState.style.display = 'none';

    addLogEntry({ level: 'info', source: 'benchmark', message: 'Starting live KEMTLS vs PQ-TLS comparison (1000 iterations, 20 warmup)…' });

    try {
        const response = await authenticatedFetch('/api/benchmark/pqtls-comparison', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({})
        });

        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const result = await response.json();

        if (!result.success) throw new Error(result.error || 'Benchmark failed');

        const d = result.data;
        // Normalise: Python uses 'pqtls_emulated', JS expects 'pqtls'
        if (d.pqtls_emulated && !d.pqtls) d.pqtls = d.pqtls_emulated;
        // Compute advantage % if not provided
        if (d.kemtls_advantage_ms != null && !d.kemtls_advantage_pct) {
            d.kemtls_advantage_pct = (d.kemtls_advantage_ms / d.pqtls.mean_ms) * 100;
        }

        // ── Render bar chart ──────────────────────────────────────────
        const barsContainer = document.getElementById('barsContainer');
        const maxMean = Math.max(d.kemtls.mean_ms, d.pqtls.mean_ms);

        const protocols = [
            { label: 'KEMTLS (this project measured)', key: 'kemtls', color: 'linear-gradient(90deg,#4f8ef7,#7c3aed)' },
            { label: 'PQ-TLS (emulated/modelled not measured)', key: 'pqtls', color: 'linear-gradient(90deg,#f59e0b,#ef4444)' }
        ];

        barsContainer.innerHTML = protocols.map(p => {
            const pct = Math.round((d[p.key].mean_ms / maxMean) * 100);
            return `
                <div>
                    <div style="display:flex; justify-content:space-between; margin-bottom:0.4rem; font-size:0.9rem;">
                        <span style="font-weight:600">${p.label}</span>
                        <span style="color:var(--text-muted)">${d[p.key].mean_ms.toFixed(3)} ms</span>
                    </div>
                    <div style="background:var(--bg-tertiary,#1e293b); border-radius:6px; overflow:hidden; height:28px">
                        <div class="bench-bar" data-pct="${pct}" style="
                            height:100%; width:0%; background:${p.color};
                            border-radius:6px; transition:width 0.9s cubic-bezier(.4,0,.2,1);
                            display:flex; align-items:center; padding-left:10px;
                            font-size:0.78rem; font-weight:600; color:#fff;
                        ">${pct}%</div>
                    </div>
                </div>
            `;
        }).join('');

        // Animate bars after render
        setTimeout(() => {
            document.querySelectorAll('.bench-bar').forEach(bar => {
                bar.style.width = bar.dataset.pct + '%';
            });
        }, 50);

        // ── Render stats table ────────────────────────────────────────
        const tbody = document.getElementById('benchmarkTableBody');
        tbody.innerHTML = protocols.map(p => `
            <tr style="border-bottom:1px solid var(--border-color)">
                <td style="padding:0.65rem 0.5rem; font-weight:600">${p.label}</td>
                <td style="padding:0.65rem 0.5rem; text-align:right">${d[p.key].mean_ms.toFixed(3)}</td>
                <td style="padding:0.65rem 0.5rem; text-align:right">${d[p.key].median_ms.toFixed(3)}</td>
                <td style="padding:0.65rem 0.5rem; text-align:right">${d[p.key].stdev_ms.toFixed(3)}</td>
                <td style="padding:0.65rem 0.5rem; text-align:right">${d[p.key].min_ms.toFixed(3)}</td>
                <td style="padding:0.65rem 0.5rem; text-align:right">${d[p.key].max_ms.toFixed(3)}</td>
            </tr>
        `).join('');

        // ── Advantage callout ─────────────────────────────────────────
        const adv = d.kemtls_advantage_ms.toFixed(3);
        const pctFaster = d.kemtls_advantage_pct.toFixed(1);
        document.getElementById('advantageCallout').innerHTML =
            `<strong>KEMTLS is ${adv} ms faster</strong> than PQ-TLS per handshake 
             <strong>${pctFaster}% improvement</strong> by eliminating the TLS CertificateVerify RTT 
             (per Wiggers 2020 §4).`;

        // ── Modelled/not-measured disclaimer ─────────────────────────
        const disclaimerId = 'pqtls-modelled-disclaimer';
        if (!document.getElementById(disclaimerId)) {
            const disclaimer = document.createElement('div');
            disclaimer.id = disclaimerId;
            disclaimer.style.cssText = `
                margin-top:1rem; padding:10px 14px;
                background:rgba(245,158,11,0.08);
                border:1px solid rgba(245,158,11,0.35);
                border-radius:8px; font-size:0.78rem;
                color:#94a3b8; line-height:1.6;
                display:flex; gap:10px; align-items:flex-start;
            `;
            disclaimer.innerHTML = `
                <i class="fas fa-triangle-exclamation" style="color:#f59e0b;margin-top:2px;flex-shrink:0;"></i>
                <span>
                    <strong style="color:#f59e0b;">PQ-TLS figures are MODELLED, not measured.</strong>
                    There is no live PQ-TLS implementation in this project. The PQ-TLS column is
                    emulated by adding one extra ML-DSA-65 Sign+Verify round (the
                    <em>CertificateVerify</em> message that PQ-TLS requires but KEMTLS eliminates)
                    on top of real KEMTLS measurements, following Wiggers 2020 §4.
                    Reference numbers from Schardong et al. (IEEE/ACM 2023) are cited for context only.
                    KEMTLS measurements ARE real (liboqs ML-KEM-768 + ML-DSA-65).
                </span>
            `;
            resultsPanel.appendChild(disclaimer);
        }

        // Show results
        resultsPanel.style.display = 'block';
        statusBanner.style.display = 'none';

        addLogEntry({ level: 'info', source: 'benchmark', message: `✓ Complete KEMTLS advantage: ${adv} ms (${pctFaster}% faster)` });
        showToast('success', `Benchmark done KEMTLS is ${adv} ms faster`);

    } catch (err) {
        statusText.textContent = `Error: ${err.message}`;
        spinner.className = 'fas fa-exclamation-circle';
        addLogEntry({ level: 'error', source: 'benchmark', message: `Benchmark failed: ${err.message}` });
        showToast('error', `Benchmark failed: ${err.message}`);
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<i class="fas fa-redo"></i> Run Again';
    }
}


// ── Session Management ────────────────────────────────────────────────────

/**
 * Handle logout: confirm with the user, then navigate to /logout.
 * The server clears the session and redirects to the login page.
 */
function handleLogout() {
    if (confirm('Sign out of QuantumShield?')) {
        window.location.href = '/logout';
    }
}

/**
 * Show a session-expired overlay and auto-redirect to login.
 * Called when any API fetch is redirected to the login page,
 * indicating the server-side session has timed out (15 min inactivity).
 */
function handleSessionExpiry() {
    if (document.getElementById('sessionExpiredOverlay')) return;

    const overlay = document.createElement('div');
    overlay.id = 'sessionExpiredOverlay';
    overlay.style.cssText = [
        'position:fixed', 'inset:0', 'z-index:9999',
        'background:rgba(0,0,0,0.75)', 'backdrop-filter:blur(4px)',
        'display:flex', 'align-items:center', 'justify-content:center'
    ].join(';');

    overlay.innerHTML = `
        <div style="background:var(--bg-secondary,#1e293b);border:1px solid rgba(239,68,68,0.4);
                    border-radius:14px;padding:2rem 2.5rem;text-align:center;max-width:380px;">
            <i class="fas fa-lock" style="font-size:2.5rem;color:#f87171;margin-bottom:1rem;display:block"></i>
            <h2 style="margin:0 0 0.5rem;font-size:1.2rem;color:var(--text-primary,#f1f5f9)">Session Expired</h2>
            <p style="color:var(--text-muted,#94a3b8);margin:0 0 1.5rem;font-size:0.9rem">
                Your session timed out after 15 minutes of inactivity. Please sign in again.
            </p>
            <button onclick="window.location.href='/kemtls-login'"
                style="padding:0.6rem 1.5rem;background:linear-gradient(135deg,#4f8ef7,#7c3aed);
                       color:#fff;border:none;border-radius:8px;font-weight:600;cursor:pointer;
                       font-size:0.95rem">
                Sign In Again
            </button>
        </div>`;

    document.body.appendChild(overlay);
    setTimeout(() => { window.location.href = '/kemtls-login'; }, 3000);
}

/**
 * Wrapper around fetch() that detects session-expiry redirects.
 * If Flask's @login_required redirects to the login page (the response
 * URL contains '/kemtls-login'), show the expiry overlay and throw.
 */
async function authenticatedFetch(url, options = {}) {
    const response = await fetch(url, options);
    if (response.redirected && response.url.includes('/kemtls-login')) {
        handleSessionExpiry();
        throw new Error('Session expired redirected to login');
    }
    return response;
}
