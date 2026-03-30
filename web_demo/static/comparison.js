/**
 * Comparison Page  TLS vs KEMTLS Benchmark Charts
 * Calls the backend comparison benchmark and renders Chart.js charts.
 */

let benchmarkData = null;

async function runLiveBenchmark() {
    const btn = document.getElementById('runBenchBtn');
    const status = document.getElementById('benchStatus');
    const statusText = document.getElementById('benchStatusText');
    const chartsEmpty = document.getElementById('chartsEmpty');
    const chartsGrid = document.getElementById('chartsGrid');

    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Running...';
    status.style.display = 'flex';
    statusText.textContent = 'Running 50 iterations of TLS + KEMTLS with real crypto... (~30s)';
    chartsEmpty.style.display = 'none';

    try {
        const response = await fetch('/api/benchmark/full-comparison', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
        });

        // Guard: if server returned HTML (login redirect) instead of JSON
        const contentType = response.headers.get('content-type') || '';
        if (!contentType.includes('application/json')) {
            if (response.status === 401 || response.status === 302 || response.redirected) {
                statusText.innerHTML = 'You need to be logged in to run benchmarks. <a href="/" style="color:#60a5fa;text-decoration:underline;margin-left:6px;">Go to Login</a>';
            } else {
                statusText.textContent = `Server error (HTTP ${response.status}). Make sure the server is running.`;
            }
            document.getElementById('benchSpinner').className = 'fas fa-exclamation-triangle';
            return;
        }


        const data = await response.json();

        if (!data.success) {
            statusText.textContent = 'Benchmark failed: ' + (data.error || 'unknown error');
            document.getElementById('benchSpinner').className = 'fas fa-exclamation-triangle';
            return;
        }

        benchmarkData = data.data;
        status.style.display = 'none';
        chartsGrid.classList.add('active');

        renderCharts(benchmarkData);
        renderSizes(benchmarkData);
        renderAuthLatency(benchmarkData);
        renderMessageSizes(benchmarkData);

    } catch (err) {
        statusText.textContent = 'Error: ' + err.message;
        document.getElementById('benchSpinner').className = 'fas fa-exclamation-triangle';
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<i class="fas fa-play"></i> Run Live Benchmark';
    }
}



function renderCharts(data) {
    const chartDefaults = {
        responsive: true,
        maintainAspectRatio: true,
        plugins: {
            legend: { display: false },
        },
        scales: {
            x: {
                grid: { color: 'rgba(255,255,255,0.04)' },
                ticks: { color: '#94a3b8', font: { size: 11 } },
            },
            y: {
                grid: { color: 'rgba(255,255,255,0.04)' },
                ticks: { color: '#94a3b8', font: { size: 11 } },
                beginAtZero: true,
            },
        },
    };

    // Handshake latency
    const hs = data.handshake;
    new Chart(document.getElementById('handshakeChart'), {
        type: 'bar',
        data: {
            labels: ['Classical TLS', 'KEMTLS'],
            datasets: [{
                data: [hs.tls.mean, hs.kemtls.mean],
                backgroundColor: ['rgba(239,68,68,0.7)', 'rgba(79,142,247,0.7)'],
                borderColor: ['#ef4444', '#4f8ef7'],
                borderWidth: 1,
                borderRadius: 6,
            }],
        },
        options: {
            ...chartDefaults,
            plugins: {
                ...chartDefaults.plugins,
                tooltip: {
                    callbacks: {
                        label: (ctx) => `${ctx.raw.toFixed(3)} ms (mean)`,
                    },
                },
            },
        },
    });

    // Token generation
    const tg = data.token_generation;
    new Chart(document.getElementById('tokenGenChart'), {
        type: 'bar',
        data: {
            labels: ['RSA-2048', 'ML-DSA-65'],
            datasets: [{
                data: [tg.rsa_2048.mean, tg.ml_dsa_65.mean],
                backgroundColor: ['rgba(239,68,68,0.7)', 'rgba(79,142,247,0.7)'],
                borderColor: ['#ef4444', '#4f8ef7'],
                borderWidth: 1,
                borderRadius: 6,
            }],
        },
        options: chartDefaults,
    });

    // Token verification
    const tv = data.token_verification;
    new Chart(document.getElementById('tokenVerifyChart'), {
        type: 'bar',
        data: {
            labels: ['RSA-2048', 'ML-DSA-65'],
            datasets: [{
                data: [tv.rsa_2048.mean, tv.ml_dsa_65.mean],
                backgroundColor: ['rgba(239,68,68,0.7)', 'rgba(79,142,247,0.7)'],
                borderColor: ['#ef4444', '#4f8ef7'],
                borderWidth: 1,
                borderRadius: 6,
            }],
        },
        options: chartDefaults,
    });

    // Signature sizes
    const ks = data.key_sizes;
    new Chart(document.getElementById('sigSizeChart'), {
        type: 'bar',
        data: {
            labels: ['RSA-2048', 'ML-DSA-65'],
            datasets: [{
                data: [ks.tls.token_signature, ks.kemtls.token_signature],
                backgroundColor: ['rgba(239,68,68,0.7)', 'rgba(79,142,247,0.7)'],
                borderColor: ['#ef4444', '#4f8ef7'],
                borderWidth: 1,
                borderRadius: 6,
            }],
        },
        options: {
            ...chartDefaults,
            plugins: {
                ...chartDefaults.plugins,
                tooltip: {
                    callbacks: {
                        label: (ctx) => `${ctx.raw} bytes`,
                    },
                },
            },
        },
    });
}

function renderSizes(data) {
    const section = document.getElementById('sizesSection');
    const grid = document.getElementById('sizesGrid');
    section.style.display = 'block';

    const ks = data.key_sizes;
    const items = [
        { label: 'Public Key', tls: ks.tls.rsa_public_key, kemtls: ks.kemtls.kem_public_key },
        { label: 'Key Exchange', tls: ks.tls.ecdhe_share, kemtls: ks.kemtls.kem_ciphertext },
        { label: 'Auth Signature', tls: ks.tls.rsa_signature, kemtls: ks.kemtls.sig_signature },
        { label: 'Token Signature', tls: ks.tls.token_signature, kemtls: ks.kemtls.token_signature },
    ];

    const maxVal = Math.max(...items.map(i => Math.max(i.tls, i.kemtls)));

    grid.innerHTML = items.map(item => {
        const tlsPct = (item.tls / maxVal * 100).toFixed(1);
        const kemtlsPct = (item.kemtls / maxVal * 100).toFixed(1);
        return `
            <div class="size-item">
                <div class="label">${item.label}</div>
                <div class="size-bar">
                    <div class="bar tls" style="width:${tlsPct}%"></div>
                    <span class="val" style="color:#ef4444">${item.tls} B</span>
                </div>
                <div class="size-bar">
                    <div class="bar kemtls" style="width:${kemtlsPct}%"></div>
                    <span class="val" style="color:#4f8ef7">${item.kemtls} B</span>
                </div>
            </div>
        `;
    }).join('');
}

/**
 * renderAuthLatency
 *
 * Renders the full OIDC authentication latency chart and a comparison table
 * against the Schardong & Resende (2025) Post-Quantum OIDC paper reference
 * values.  Called after a live benchmark run.
 *
 * Expected shape:
 *   data.auth_latency = {
 *     tls:    { mean, median, stdev, min, max },
 *     kemtls: { mean, median, stdev, min, max },
 *     kemtls_advantage_ms,
 *     kemtls_faster_pct,
 *     paper_reference: {
 *       source,
 *       classical_tls_auth_latency_ms,
 *       pq_tls_auth_latency_ms,
 *       note,
 *     }
 *   }
 */
function renderAuthLatency(data) {
    const section = document.getElementById('authLatencySection');
    if (!section) return;

    const al = data.auth_latency;
    if (!al) return;

    section.style.display = 'block';
    const lbl = document.getElementById('authLatencyLabel');
    if (lbl) lbl.style.display = 'flex';

    const paper         = al.paper_reference || {};
    const paperClassical = paper.classical_tls_auth_latency_ms || 0.8;
    const paperPQTLS    = paper.pq_tls_auth_latency_ms || 12.4;
    const paperSource   = paper.source || 'Schardong & Resende, Post-Quantum OIDC (2025)';

    // Chart: 4 bars  this-impl TLS, this-impl KEMTLS, paper-TLS, paper-PQ-TLS
    const labels = ['TLS (this impl)', 'KEMTLS (this impl)', 'TLS (Schardong)', 'PQ-TLS (Schardong)'];
    const values = [al.tls.mean, al.kemtls.mean, paperClassical, paperPQTLS];
    const bgColors  = [
        'rgba(239,68,68,0.75)',
        'rgba(79,142,247,0.75)',
        'rgba(239,68,68,0.30)',
        'rgba(79,142,247,0.30)',
    ];
    const borders = ['#ef4444', '#4f8ef7', '#ef4444', '#4f8ef7'];

    new Chart(document.getElementById('authLatencyChart'), {
        type: 'bar',
        data: {
            labels,
            datasets: [{
                data: values,
                backgroundColor: bgColors,
                borderColor: borders,
                borderWidth: 1,
                borderRadius: 6,
            }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: { display: false },
                tooltip: {
                    callbacks: {
                        label: (ctx) => `${ctx.raw.toFixed(3)} ms`,
                    },
                },
            },
            scales: {
                x: {
                    grid: { color: 'rgba(255,255,255,0.04)' },
                    ticks: { color: '#94a3b8', font: { size: 10 } },
                },
                y: {
                    grid: { color: 'rgba(255,255,255,0.04)' },
                    ticks: {
                        color: '#94a3b8',
                        font: { size: 11 },
                        callback: (v) => v + ' ms',
                    },
                    beginAtZero: true,
                },
            },
        },
    });

    // Schardong comparison table
    const tableContainer = document.getElementById('schardongTable');
    if (!tableContainer) return;

    const kemtlsOverheadPct = al.tls.mean > 0
        ? ((al.kemtls.mean / al.tls.mean - 1) * 100).toFixed(1) + '%'
        : 'N/A';
    const paperOverheadPct  = paperClassical > 0
        ? (((paperPQTLS / paperClassical) - 1) * 100).toFixed(1) + '%'
        : 'N/A';

    const hsData = (data.handshake) ? data.handshake : null;

    const rows = [
        {
            metric: 'Full Auth Latency',
            tlsImpl:   al.tls.mean.toFixed(3) + ' ms',
            kemImpl:   al.kemtls.mean.toFixed(3) + ' ms',
            tlsPaper:  paperClassical.toFixed(1) + ' ms',
            pqPaper:   paperPQTLS.toFixed(1) + ' ms',
        },
        {
            metric: 'Overhead vs Classical',
            tlsImpl:   '',
            kemImpl:   kemtlsOverheadPct,
            tlsPaper:  '',
            pqPaper:   paperOverheadPct,
        },
        {
            metric: 'Handshake Component',
            tlsImpl:   hsData ? hsData.tls.mean.toFixed(3) + ' ms' : '',
            kemImpl:   hsData ? hsData.kemtls.mean.toFixed(3) + ' ms' : '',
            tlsPaper:  '~0.9 ms',
            pqPaper:   '~3.2 ms',
        },
        {
            metric: 'Quantum Safe',
            tlsImpl:   '<span style="color:#ef4444">&#10007; No</span>',
            kemImpl:   '<span style="color:#22c55e">&#10003; Yes (NIST Level 3)</span>',
            tlsPaper:  '<span style="color:#ef4444">&#10007; No</span>',
            pqPaper:   '<span style="color:#22c55e">&#10003; Yes</span>',
        },
    ];

    const tdStyle = 'padding:8px 12px;border-bottom:1px solid rgba(255,255,255,0.05);';

    tableContainer.innerHTML = `
        <p style="color:#94a3b8;font-size:0.82rem;margin-bottom:0.75rem;">
            Paper reference: <em>${paperSource}</em>.
            Solid bars = this implementation; faded bars = paper reference values.
        </p>
        <table style="width:100%;border-collapse:collapse;font-size:0.83rem;">
            <thead>
                <tr style="background:rgba(255,255,255,0.04);">
                    <th style="${tdStyle}text-align:left;color:#94a3b8;font-weight:600;">Metric</th>
                    <th style="${tdStyle}text-align:center;color:#ef4444;font-weight:600;">TLS (impl)</th>
                    <th style="${tdStyle}text-align:center;color:#4f8ef7;font-weight:600;">KEMTLS (impl)</th>
                    <th style="${tdStyle}text-align:center;color:#ef4444;font-weight:600;opacity:0.55;">TLS (Schardong)</th>
                    <th style="${tdStyle}text-align:center;color:#4f8ef7;font-weight:600;opacity:0.55;">PQ-TLS (Schardong)</th>
                </tr>
            </thead>
            <tbody>
                ${rows.map((r, i) => `
                <tr style="background:${i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.02)'};">
                    <td style="${tdStyle}color:#e2e8f0;">${r.metric}</td>
                    <td style="${tdStyle}text-align:center;color:#ef4444;">${r.tlsImpl}</td>
                    <td style="${tdStyle}text-align:center;color:#4f8ef7;">${r.kemImpl}</td>
                    <td style="${tdStyle}text-align:center;color:#ef4444;opacity:0.6;">${r.tlsPaper}</td>
                    <td style="${tdStyle}text-align:center;color:#4f8ef7;opacity:0.6;">${r.pqPaper}</td>
                </tr>`).join('')}
            </tbody>
        </table>
    `;
}

/**
 * renderMessageSizes
 *
 * Renders OIDC endpoint payload sizes for each message in the authorization
 * code flow, comparing classical TLS (RSA-2048 JWT) vs KEMTLS (ML-DSA-65 JWT).
 *
 * Expected shape:
 *   data.message_sizes = {
 *     authorize_request_bytes, authorize_response_bytes,
 *     token_request_bytes, tls_token_response_bytes,
 *     kemtls_token_response_bytes, userinfo_response_bytes, note
 *   }
 */
function renderMessageSizes(data) {
    const section = document.getElementById('msgSizesSection');
    if (!section) return;

    const ms = data.message_sizes;
    if (!ms) return;

    // Backend returns nested: message_sizes.oidc_payload_sizes.*
    const ps = ms.oidc_payload_sizes || ms;

    section.style.display = 'block';
    const msgLbl = document.getElementById('msgSizesLabel');
    if (msgLbl) msgLbl.style.display = 'flex';

    const grid = document.getElementById('msgSizesGrid');

    if (!grid) return;

    const items = [
        { label: 'Authorize Request',      tls: ps.authorize_request_bytes,     kemtls: ps.authorize_request_bytes,    note: 'No cryptographic payload' },
        { label: 'Authorize Response',     tls: ps.authorize_response_bytes,    kemtls: ps.authorize_response_bytes,   note: 'Authorization code' },
        { label: 'Token Request',          tls: ps.token_request_bytes,         kemtls: ps.token_request_bytes,        note: 'Code exchange' },
        { label: 'Token Response',         tls: ps.tls_token_response_bytes,    kemtls: ps.kemtls_token_response_bytes, note: 'JWT signature differs' },
        { label: 'UserInfo Response',      tls: ps.userinfo_response_bytes,     kemtls: ps.userinfo_response_bytes,    note: 'Claims payload' },
    ];

    grid.style.display = 'block';
    grid.innerHTML = `
        <table style="width:100%;border-collapse:collapse;font-size:0.84rem;">
            <thead>
                <tr style="border-bottom:1px solid var(--border);">
                    <th style="text-align:left;padding:0.6rem 0.8rem;color:var(--text-muted);font-weight:600;font-size:0.75rem;text-transform:uppercase;letter-spacing:0.04em;">Message</th>
                    <th style="text-align:left;padding:0.6rem 0.8rem;color:var(--text-muted);font-weight:600;font-size:0.75rem;text-transform:uppercase;letter-spacing:0.04em;">Note</th>
                    <th style="text-align:right;padding:0.6rem 0.8rem;color:var(--accent-red);font-weight:600;font-size:0.75rem;">TLS (bytes)</th>
                    <th style="text-align:right;padding:0.6rem 0.8rem;color:var(--accent-blue);font-weight:600;font-size:0.75rem;">KEMTLS (bytes)</th>
                    <th style="text-align:right;padding:0.6rem 0.8rem;color:var(--text-muted);font-weight:600;font-size:0.75rem;text-transform:uppercase;letter-spacing:0.04em;">Diff</th>
                </tr>
            </thead>
            <tbody>
                ${items.map((item, i) => {
                    const diff = (item.kemtls || 0) - (item.tls || 0);
                    const diffText = diff === 0
                        ? '<span style="color:var(--text-muted)">—</span>'
                        : diff > 0
                            ? `<span style="color:var(--accent-amber)">+${diff} B</span>`
                            : `<span style="color:var(--accent-green)">${diff} B</span>`;
                    const rowBg = i % 2 !== 0 ? 'background:var(--card-inner)' : '';
                    return `
                        <tr style="border-bottom:1px solid var(--algo-row-border);${rowBg}">
                            <td style="padding:0.65rem 0.8rem;font-weight:600;color:var(--text-primary);">${item.label}</td>
                            <td style="padding:0.65rem 0.8rem;color:var(--text-muted);font-size:0.78rem;">${item.note}</td>
                            <td style="padding:0.65rem 0.8rem;text-align:right;font-weight:600;color:var(--accent-red);font-variant-numeric:tabular-nums;">${item.tls ?? '—'}</td>
                            <td style="padding:0.65rem 0.8rem;text-align:right;font-weight:600;color:var(--accent-blue);font-variant-numeric:tabular-nums;">${item.kemtls ?? '—'}</td>
                            <td style="padding:0.65rem 0.8rem;text-align:right;">${diffText}</td>
                        </tr>`;
                }).join('')}
            </tbody>
        </table>
        <p style="font-size:0.75rem;color:var(--text-muted);margin-top:0.75rem;padding:0 0.4rem;">
            Token Response differs because ML-DSA-65 signatures (~3,309 B) are significantly larger than RSA-2048 (256 B).
            All other OIDC messages are protocol-identical.
        </p>
    `;
}