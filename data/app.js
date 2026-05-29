(function () {
    let currentData = {};
    let localEventCount = -1;
    let pollErrors = 0;
    let polling = false;

    const POLL_INTERVAL_MS = 2000;
    const ERROR_THRESHOLD  = 5;
    const FETCH_TIMEOUT_MS = 3000;

    const fetchWithTimeout = (url, options = {}) => {
        const controller = new AbortController();
        const id = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
        return fetch(url, { ...options, signal: controller.signal })
            .finally(() => clearTimeout(id));
    };

    const beep = () => {
        try {
            const ctx = new (window.AudioContext || window.webkitAudioContext)();
            const osc = ctx.createOscillator();
            osc.type = 'square';
            osc.frequency.setValueAtTime(200, ctx.currentTime);
            osc.connect(ctx.destination);
            osc.start();
            osc.stop(ctx.currentTime + 0.05);
        } catch (e) {}
    };

    const setOverlay = (visible) => {
        const el = document.getElementById('connection-lost');
        el.classList.toggle('d-none', !visible);
        el.classList.toggle('d-flex', visible);
    };

    const updateDashboard = (data) => {
        currentData = data;

        document.getElementById('uptime').innerText = data.uptime + 's';

        const badge = document.getElementById('threat-badge');
        badge.innerText = data.threat;
        badge.className = `threat-${data.threat} fw-bold fs-3`;

        if (data.threat === 'HIGH') {
            document.body.classList.add('body-threat-high');
            beep();
        } else {
            document.body.classList.remove('body-threat-high');
        }

        document.getElementById('sensor-motion').innerText   = data.motion ? 'DETECTED' : 'CLEAR';
        document.getElementById('sensor-distance').innerText = data.distance;

        const syncCard = (id, active, text) => {
            const el = document.getElementById(id);
            el.innerText = text;
            el.className = `fs-4 fw-bold ${active ? 'text-active' : 'text-inactive'}`;
        };

        syncCard('system-status',     data.system,            data.system            ? 'ARMED'   : 'DISARMED');
        syncCard('pir-status',        data.pirEnabled,        data.pirEnabled        ? 'ONLINE'  : 'OFFLINE');
        syncCard('ultrasonic-status', data.ultrasonicEnabled, data.ultrasonicEnabled ? 'ONLINE'  : 'OFFLINE');
        syncCard('auto-alarm-status', data.alarmEnabled,      data.alarmEnabled      ? 'ENABLED' : 'DISABLED');
        syncCard('buzzer-status',     data.buzzerEnabled,     data.buzzerEnabled     ? 'ENABLED' : 'MUTED');
        syncCard('alarm-status',      data.alarm,             data.alarm             ? 'ACTIVE'  : 'IDLE');

        if (data.eventCount !== localEventCount) {
            localEventCount = data.eventCount;
            requestLogs();
        }
    };

    const requestLogs = async () => {
        try {
            const res  = await fetchWithTimeout('/logs');
            const data = await res.json();
            const tbody = document.getElementById('log-body');
            tbody.innerHTML = '';
            [...data].reverse().forEach(log => {
                const tr = document.createElement('tr');
                tr.innerHTML = `<td>${log.timestamp || '-'}</td><td><strong>${log.type || '-'}</strong></td><td>${log.value || '-'}</td>`;
                tbody.appendChild(tr);
            });
        } catch (e) {
            console.error('Log fetch error:', e.message);
        }
    };

    const sendControl = async (payload) => {
        try {
            await fetchWithTimeout('/control', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
        } catch (e) {
            console.error('Control error:', e.message);
        }
    };

    window.toggleOption = (option) => {
        const map = {
            system:       !currentData.system,
            pir:          !currentData.pirEnabled,
            ultrasonic:   !currentData.ultrasonicEnabled,
            alarmEnabled: !currentData.alarmEnabled,
            buzzerEnabled: !currentData.buzzerEnabled,
            alarm:        !currentData.alarm
        };
        if (option in map) sendControl({ [option]: map[option] });
    };

    window.exportLogs = () => { window.location.href = '/export'; };

    window.clearLogs = async () => {
        try {
            await fetchWithTimeout('/clearlogs', { method: 'POST' });
            localEventCount = -1;
            requestLogs();
        } catch (e) {}
    };

    window.rebootSystem = async () => {
        try { await fetchWithTimeout('/restart', { method: 'POST' }); } catch (e) {}
    };

    const syncTime = async () => {
        try {
            await fetchWithTimeout('/synctime', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ time: Math.floor(Date.now() / 1000) })
            });
        } catch (e) {
            console.warn('Time sync fail:', e.message);
        }
    };

    const poll = async () => {
        if (polling) return;
        polling = true;
        try {
            const res  = await fetchWithTimeout('/status');
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const data = await res.json();
            pollErrors = 0;
            setOverlay(false);
            updateDashboard(data);
        } catch (e) {
            pollErrors++;
            console.warn(`Poll fail #${pollErrors}:`, e.message);
            if (pollErrors >= ERROR_THRESHOLD) setOverlay(true);
        } finally {
            polling = false;
        }
    };

    syncTime();
    setInterval(poll, POLL_INTERVAL_MS);
    poll();
})();