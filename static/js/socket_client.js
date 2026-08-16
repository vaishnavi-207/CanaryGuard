// CanaryGuard Socket.IO Client Gateway
if (typeof io === 'undefined') {
    console.warn('Socket.IO not loaded - real-time updates disabled.');
} else {
    const socket = io();

    socket.on('connect', () => {
        console.log('[CanaryGuard WS] Connected to backend gateway.');
    });

    socket.on('disconnect', () => {
        console.warn('[CanaryGuard WS] Disconnected from server. Reconnecting...');
    });

    socket.on('threat_alert', (payload) => {
        console.warn('[CanaryGuard Threat Alert]', payload);
        showToastNotification(payload);
        appendIncidentToTable(payload);
        if (typeof refreshDashboardMetrics === 'function') {
            refreshDashboardMetrics();
        }
    });

    socket.on('dashboard_update', (data) => {
        console.log('[CanaryGuard WS] Dashboard update received:', data);
        const canaryCountEl = document.getElementById('stat-canary-count');
        if (canaryCountEl && data.canary_count !== undefined) {
            canaryCountEl.textContent = data.canary_count;
        }
        const totalIncidentsEl = document.getElementById('stat-total-incidents');
        if (totalIncidentsEl && data.total_incidents !== undefined) {
            totalIncidentsEl.textContent = data.total_incidents;
        }
        const quarantineCountEl = document.getElementById('stat-quarantine-count');
        if (quarantineCountEl && data.quarantine_count !== undefined) {
            quarantineCountEl.textContent = data.quarantine_count;
        }
        if (typeof refreshDashboardMetrics === 'function') {
            refreshDashboardMetrics();
        }
    });
}

function appendIncidentToTable(payload) {
    const tbody = document.querySelector('.custom-table tbody');
    if (!tbody) return;

    // Check if table currently displays "No active threat incidents"
    if (tbody.children.length === 1 && tbody.children[0].cells.length === 1) {
        tbody.innerHTML = '';
    }

    const tr = document.createElement('tr');
    const now = new Date();
    const timeStr = now.toTimeString().split(' ')[0];
    const isCritical = payload.threat_level === 'CRITICAL';
    const threatBg = isCritical ? 'rgba(239, 68, 68, 0.2)' : 'rgba(245, 158, 11, 0.2)';
    const threatColor = isCritical ? 'var(--accent-red)' : 'var(--accent-yellow)';

    tr.innerHTML = `
        <td>${timeStr}</td>
        <td>
            <span style="padding: 0.25rem 0.5rem; border-radius: 4px; font-weight: bold; background: ${threatBg}; color: ${threatColor};">
                ${payload.threat_level || 'UNKNOWN'}
            </span>
        </td>
        <td>${payload.process_name || 'N/A'} (PID: ${payload.pid || '?'})</td>
        <td style="max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${payload.src_path}</td>
        <td><strong style="color: var(--accent-green);">${payload.action_taken}</strong></td>
    `;
    tbody.insertBefore(tr, tbody.firstChild);
}

function showToastNotification(payload) {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast ${payload.threat_level ? payload.threat_level.toLowerCase() : 'critical'}`;
    toast.style.cssText = `
        background: rgba(15, 23, 42, 0.95);
        border: 1px solid ${payload.threat_level === 'CRITICAL' ? '#ef4444' : '#00f3ff'};
        color: #fff;
        padding: 1rem 1.5rem;
        border-radius: 8px;
        margin-bottom: 0.75rem;
        box-shadow: 0 5px 20px rgba(0,0,0,0.5);
        backdrop-filter: blur(10px);
        font-family: var(--font-main);
        animation: slideIn 0.3s forwards;
    `;
    
    toast.innerHTML = `
        <div style="font-weight: 700; color: ${payload.threat_level === 'CRITICAL' ? '#ef4444' : '#00f3ff'}; margin-bottom: 0.25rem;">
            ⚠️ ${payload.threat_level || 'THREAT'} ALERT DETECTED
        </div>
        <div style="font-size: 0.85rem; font-family: var(--font-mono);">
            File: ${payload.src_path}<br>
            Process: ${payload.process_name} (PID: ${payload.pid || 'N/A'})<br>
            Action: <strong>${payload.action_taken}</strong>
        </div>
    `;

    container.appendChild(toast);
    setTimeout(() => {
        toast.remove();
    }, 8000);
}
