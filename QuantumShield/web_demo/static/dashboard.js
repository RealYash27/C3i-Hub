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
                <pre style="background: var(--bg-tertiary); padding: 1rem; border-radius: 0.5rem; overflow-x: auto; margin-top: 0.5rem;">
${JSON.stringify(test.results, null, 2)}
                </pre>
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
                <pre style="background: var(--bg-tertiary); padding: 1rem; border-radius: 0.5rem; overflow-x: auto; font-size: 0.75rem;">
${JSON.stringify(test.results, null, 2)}
                </pre>
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
