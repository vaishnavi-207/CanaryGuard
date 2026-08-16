// CanaryGuard Dashboard Client Controller

function toIST(utcStr) {
    if (!utcStr) return 'N/A';
    const d = new Date(utcStr);
    return d.toLocaleString('en-IN', {
        timeZone: 'Asia/Kolkata',
        day: '2-digit',
        month: 'short',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: true
    });
}

document.addEventListener('DOMContentLoaded', () => {
    initControls();
});

function initControls() {
    const btnStart = document.getElementById('btn-start-monitor');
    const btnStop = document.getElementById('btn-stop-monitor');
    const btnDeploy = document.getElementById('btn-deploy-canaries');

    if (btnStart) {
        btnStart.addEventListener('click', async () => {
            const res = await fetch('/api/start-monitor', { method: 'POST' });
            const data = await res.json();
            alert(data.message || 'Monitoring Started');
            window.location.reload();
        });
    }

    if (btnStop) {
        btnStop.addEventListener('click', async () => {
            const res = await fetch('/api/stop-monitor', { method: 'POST' });
            const data = await res.json();
            alert(data.message || 'Monitoring Stopped');
            window.location.reload();
        });
    }

    if (btnDeploy) {
        btnDeploy.addEventListener('click', async () => {
            const res = await fetch('/api/deploy-canaries', { method: 'POST' });
            const data = await res.json();
            alert(data.message || 'Canaries Deployed');
            window.location.reload();
        });
    }
}

async function quarantineProcess(pid) {
    if (!confirm(`Are you sure you want to forcibly terminate PID ${pid}?`)) return;
    const res = await fetch('/api/quarantine', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pid: pid, reason: 'Operator Manual Request' })
    });
    const data = await res.json();
    if (res.ok) {
        alert(`Process PID ${pid} terminated successfully.`);
        window.location.reload();
    } else {
        alert(`Failed to quarantine process PID ${pid}: ${data.error || 'Unknown error'}`);
    }
}

async function loadLogType(logType) {
    const logBox = document.getElementById('log-terminal-output');
    if (!logBox) return;

    logBox.innerHTML = '<div class="log-entry">Loading log entries...</div>';
    const res = await fetch(`/api/logs?type=${logType}`);
    const data = await res.json();

    if (data.lines && data.lines.length > 0) {
        logBox.innerHTML = data.lines.map(line => {
            let cls = 'log-entry';
            if (line.includes('[CRITICAL]')) cls += ' critical';
            else if (line.includes('[ERROR]')) cls += ' error';
            else if (line.includes('[WARNING]')) cls += ' warning';
            return `<div class="${cls}">${escapeHtml(line)}</div>`;
        }).join('');
        logBox.scrollTop = logBox.scrollHeight;
    } else {
        logBox.innerHTML = '<div class="log-entry">No log records found for this category.</div>';
    }
}

function escapeHtml(text) {
    return text
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
