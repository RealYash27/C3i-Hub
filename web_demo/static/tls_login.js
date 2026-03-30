/**
 * TLS Login Page  Classical Handshake Visualization
 * Performs TLS handshake simulation and animates the steps.
 */

async function handleTLSLogin(event) {
    event.preventDefault();

    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const loginBtn = document.getElementById('loginBtn');
    const loginError = document.getElementById('loginError');

    loginBtn.classList.add('loading');
    loginError.classList.remove('show');

    // Show flow steps
    document.getElementById('flowIdle').style.display = 'none';
    const flowSteps = document.getElementById('flowSteps');
    flowSteps.classList.add('active');

    try {
        // Call TLS login API over REAL HTTPS (port 9443).
        // Burp intercepting this will show plaintext credentials after
        // its own CA is trusted by the browser  a genuine MITM attack.
        const response = await fetch('/tls/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password }),
        });

        const data = await response.json();

        if (!data.success) {
            loginBtn.classList.remove('loading');
            loginError.classList.add('show');
            document.getElementById('errorText').textContent = data.message || 'Login failed';
            return;
        }

        // Animate handshake steps
        const steps = data.tls_handshake?.steps || [];
        for (let i = 0; i < steps.length; i++) {
            const step = steps[i];
            const stepEl = document.getElementById(`step-${i + 1}`);
            if (!stepEl) continue;

            stepEl.classList.add('active');
            const timingEl = document.getElementById(`timing-${i + 1}`);
            const detailEl = document.getElementById(`detail-${i + 1}`);

            if (timingEl) timingEl.textContent = `${step.duration_ms.toFixed(3)} ms`;
            if (detailEl) detailEl.textContent = step.detail || '';

            await delay(250);
            stepEl.classList.remove('active');
            stepEl.classList.add('done');
        }

        // Animate OIDC step (step 7)
        const oidcStep = document.getElementById('step-7');
        if (oidcStep) {
            oidcStep.classList.add('active');
            const t7 = document.getElementById('timing-7');
            const d7 = document.getElementById('detail-7');
            if (t7) t7.textContent = `${(data.token_info?.sign_time_ms || 0).toFixed(3)} ms`;
            if (d7) d7.textContent = `RSA-2048-PSS signature: ${data.token_info?.signature_size || 256} B`;
            await delay(300);
            oidcStep.classList.remove('active');
            oidcStep.classList.add('done');
        }

        // Show summary
        loginBtn.classList.remove('loading');
        showTLSSummary(data);

    } catch (err) {
        loginBtn.classList.remove('loading');
        loginError.classList.add('show');
        document.getElementById('errorText').textContent = 'Connection failed: ' + err.message;
    }
}

function showTLSSummary(data) {
    const summary = document.getElementById('flowSummary');
    const grid = document.getElementById('summaryGrid');
    summary.classList.add('active');

    const hs = data.tls_handshake || {};
    const metrics = [
        { label: 'Total Handshake', value: `${(hs.total_ms || 0).toFixed(2)} ms` },
        { label: 'Authentication', value: 'RSA-2048-PSS' },
        { label: 'Key Exchange', value: 'ECDHE-P256' },
        { label: 'Token Signature', value: `${data.token_info?.signature_size || 256} B` },
        { label: 'Quantum Safe', value: 'No' },
        { label: 'Security Level', value: 'Classical' },
    ];

    grid.innerHTML = metrics.map(m => `
        <div class="summary-item">
            <div class="label">${m.label}</div>
            <div class="value">${m.value}</div>
        </div>
    `).join('');
}

function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}
