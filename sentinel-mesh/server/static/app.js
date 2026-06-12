/* ═══════════════════════════════════════════════════════════════
   SENTINEL MESH — Real-time Dashboard Client
   ═══════════════════════════════════════════════════════════════ */

(function () {
    'use strict';

    /* ─── CONFIGURATION ─── */
    const CONFIG = {
        WS_PATH: '/stream',
        API_SUMMARY: '/api/summary',
        RECONNECT_BASE: 1000,
        RECONNECT_MAX: 15000,
        MAX_FEED_ENTRIES: 50,
        PING_INTERVAL: 25000,
        TOAST_DURATION: 6000,
        COUNTER_ANIMATION_MS: 600,
    };

    /* ─── STATE ─── */
    const state = {
        ws: null,
        reconnectAttempts: 0,
        reconnectTimer: null,
        pingTimer: null,
        countdownTimer: null,
        isConnected: false,
        stats: { total_events: 0, anomaly_count: 0, critical_count: 0, normal_count: 0, sensors_online: 0 },
        attackDistribution: {},
    };

    /* ─── DOM REFS ─── */
    const $ = (sel) => document.querySelector(sel);
    const dom = {
        connectionBadge: $('#connection-status'),
        statusText: $('#connection-status .status-text'),
        sensorsOnline: $('#sensors-online-count'),
        kpiTotal: $('#kpi-total-value'),
        kpiAnomaly: $('#kpi-anomaly-value'),
        kpiCritical: $('#kpi-critical-value'),
        kpiNormal: $('#kpi-normal-value'),
        attackChart: $('#attack-distribution-chart'),
        sensorContent: $('#sensor-status-content'),
        feedList: $('#live-feed-list'),
        toastContainer: $('#toast-container'),
        footerClock: $('#footer-clock'),
        liveIndicator: $('#feed-live-indicator'),
        btnReset: $('#btn-reset'),
    };

    /* ═══════════════════════════════════════
       UTILITY HELPERS
       ═══════════════════════════════════════ */

    /** Format number with Turkish locale (1.234) */
    function fmtNum(n) {
        return Number(n).toLocaleString('tr-TR');
    }

    /** Format timestamp to HH:MM:SS */
    function fmtTime(ts) {
        if (!ts) return '--:--:--';
        const d = new Date(ts);
        if (isNaN(d.getTime())) return ts;
        return d.toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    }

    /** Classify threat score */
    function threatClass(score) {
        const s = Number(score) || 0;
        if (s >= 70) return 'high';
        if (s >= 35) return 'medium';
        return 'low';
    }

    /** Threat label in Turkish */
    function threatLabel(score) {
        const s = Number(score) || 0;
        if (s >= 70) return 'Kritik';
        if (s >= 35) return 'Orta';
        return 'Düşük';
    }

    /** Escape HTML to prevent XSS */
    function esc(str) {
        const div = document.createElement('div');
        div.appendChild(document.createTextNode(String(str || '')));
        return div.innerHTML;
    }

    /* ═══════════════════════════════════════
       COUNTING ANIMATION
       ═══════════════════════════════════════ */
    function animateCounter(el, targetValue) {
        const target = Number(targetValue) || 0;
        const current = Number(el.dataset.value) || 0;
        if (current === target) return;

        el.dataset.value = target;
        const diff = target - current;
        const startTime = performance.now();
        const duration = CONFIG.COUNTER_ANIMATION_MS;

        function step(now) {
            const elapsed = now - startTime;
            const progress = Math.min(elapsed / duration, 1);
            // ease-out cubic
            const eased = 1 - Math.pow(1 - progress, 3);
            const value = Math.round(current + diff * eased);
            el.textContent = fmtNum(value);
            if (progress < 1) requestAnimationFrame(step);
        }

        requestAnimationFrame(step);
    }

    /* ═══════════════════════════════════════
       KPI UPDATE
       ═══════════════════════════════════════ */
    function updateKPIs(stats) {
        if (!stats) return;
        state.stats = { ...state.stats, ...stats };
        animateCounter(dom.kpiTotal, state.stats.total_events);
        animateCounter(dom.kpiAnomaly, state.stats.anomaly_count);
        animateCounter(dom.kpiCritical, state.stats.critical_count);
        animateCounter(dom.kpiNormal, state.stats.normal_count);
        updateSensorCount(state.stats.sensors_online);
    }

    function updateSensorCount(n) {
        const count = Number(n) || 0;
        dom.sensorsOnline.textContent = count;
        state.stats.sensors_online = count;
    }

    /* ═══════════════════════════════════════
       ATTACK DISTRIBUTION CHART
       ═══════════════════════════════════════ */
    function updateAttackDistribution(data) {
        if (!data || typeof data !== 'object') return;
        state.attackDistribution = { ...state.attackDistribution, ...data };
        renderAttackChart();
    }

    function renderAttackChart() {
        const entries = Object.entries(state.attackDistribution)
            .sort((a, b) => b[1] - a[1]);

        if (entries.length === 0) {
            dom.attackChart.innerHTML = '<div class="chart-empty-state">Veri bekleniyor…</div>';
            return;
        }

        const maxVal = Math.max(...entries.map(e => e[1]), 1);
        let html = '';

        for (const [label, count] of entries) {
            const pct = Math.max((count / maxVal) * 100, 1);
            html += `
                <div class="chart-bar-row">
                    <span class="chart-bar-label" title="${esc(label)}">${esc(label)}</span>
                    <div class="chart-bar-track">
                        <div class="chart-bar-fill" style="width:${pct.toFixed(1)}%"></div>
                    </div>
                    <span class="chart-bar-count">${fmtNum(count)}</span>
                </div>`;
        }

        dom.attackChart.innerHTML = html;
    }

    /* ═══════════════════════════════════════
       SENSOR STATUS
       ═══════════════════════════════════════ */
    function updateSensorStatus(count) {
        const n = Number(count) || 0;
        updateSensorCount(n);

        if (n === 0) {
            dom.sensorContent.innerHTML = `
                <div class="sensor-empty-state">
                    <div class="sensor-radar" aria-hidden="true">
                        <div class="radar-ring"></div>
                        <div class="radar-ring ring-2"></div>
                        <div class="radar-ring ring-3"></div>
                        <div class="radar-dot"></div>
                    </div>
                    <span>Sensörler taranıyor…</span>
                </div>`;
            return;
        }

        let html = '';
        for (let i = 1; i <= n; i++) {
            html += `
                <div class="sensor-card">
                    <span class="sensor-card-dot" aria-hidden="true"></span>
                    <span class="sensor-card-name">Sensor-${String(i).padStart(2, '0')}</span>
                    <span class="sensor-card-ip">Raspberry Pi</span>
                </div>`;
        }
        dom.sensorContent.innerHTML = html;
    }

    /* ═══════════════════════════════════════
       LIVE FEED
       ═══════════════════════════════════════ */
    function clearFeedEmptyState() {
        const empty = dom.feedList.querySelector('.feed-empty-state');
        if (empty) empty.remove();
    }

    function addFeedEntry(event, prepend = true) {
        clearFeedEmptyState();

        const d = event || {};
        const tClass = threatClass(d.threat_score);
        const methodClass = (d.method || '').toLowerCase() === 'xgboost' ? 'method-xgboost' : 'method-rule';
        const methodLabel = (d.method || '').toLowerCase() === 'xgboost' ? 'XGBoost' : 'Kural';

        const entry = document.createElement('div');
        entry.className = `feed-entry threat-${tClass}`;
        entry.innerHTML = `
            <div class="feed-entry-type">
                <span class="feed-entry-attack">${esc(d.attack_type || d.label || 'Bilinmiyor')}</span>
            </div>
            <div class="feed-entry-info">
                <span class="feed-entry-ips">
                    <span class="ip-src">${esc(d.source_ip || '?.?.?.?')}</span>
                    <span class="arrow">→</span>
                    <span class="ip-dst">${esc(d.destination_ip || '?.?.?.?')}</span>
                </span>
                <div class="feed-entry-meta">
                    <span class="method-badge ${methodClass}">${methodLabel}</span>
                </div>
            </div>
            <div class="feed-entry-right">
                <span class="threat-badge threat-${tClass}">${threatLabel(d.threat_score)} ${Math.round(d.threat_score || 0)}</span>
                <span class="feed-entry-time">${fmtTime(d.timestamp || d.server_time)}</span>
            </div>`;

        if (prepend) {
            dom.feedList.prepend(entry);
        } else {
            dom.feedList.appendChild(entry);
        }

        // Trim excess
        while (dom.feedList.children.length > CONFIG.MAX_FEED_ENTRIES) {
            dom.feedList.lastElementChild.remove();
        }
    }

    function loadRecentLogs(logs) {
        if (!Array.isArray(logs) || logs.length === 0) return;
        dom.feedList.innerHTML = '';
        // Oldest first so prepend order is correct, or just append in order
        for (const log of logs) {
            addFeedEntry(log, false);
        }
    }

    /* ═══════════════════════════════════════
       TOAST NOTIFICATIONS
       ═══════════════════════════════════════ */
    function showToast(title, message) {
        const toast = document.createElement('div');
        toast.className = 'toast';
        toast.innerHTML = `
            <div class="toast-icon">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--danger)" stroke-width="2">
                    <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
                    <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
                </svg>
            </div>
            <div class="toast-body">
                <div class="toast-title">${esc(title)}</div>
                <div class="toast-message">${esc(message)}</div>
            </div>
            <button class="toast-close" aria-label="Kapat">&times;</button>`;

        toast.querySelector('.toast-close').addEventListener('click', () => dismissToast(toast));
        dom.toastContainer.appendChild(toast);

        setTimeout(() => dismissToast(toast), CONFIG.TOAST_DURATION);
    }

    function dismissToast(el) {
        if (!el || el.classList.contains('toast-out')) return;
        el.classList.add('toast-out');
        el.addEventListener('animationend', () => el.remove());
    }

    /* ═══════════════════════════════════════
       CONNECTION STATUS
       ═══════════════════════════════════════ */
    function setConnectionState(status, extraText) {
        dom.connectionBadge.className = 'connection-badge ' + status;

        const labels = {
            online: 'ONLINE',
            offline: 'OFFLINE',
            reconnecting: 'YENİDEN BAĞLANIYOR',
        };

        dom.statusText.textContent = extraText || labels[status] || status.toUpperCase();
        state.isConnected = (status === 'online');

        // Live indicator visibility
        if (dom.liveIndicator) {
            dom.liveIndicator.style.opacity = state.isConnected ? '1' : '0.3';
        }
    }

    /* ═══════════════════════════════════════
       WEBSOCKET
       ═══════════════════════════════════════ */
    function buildWsUrl() {
        const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
        return `${proto}//${location.host}${CONFIG.WS_PATH}`;
    }

    function connectWebSocket() {
        if (state.ws && (state.ws.readyState === WebSocket.CONNECTING || state.ws.readyState === WebSocket.OPEN)) {
            return;
        }

        clearTimeout(state.reconnectTimer);
        clearTimeout(state.countdownTimer);

        const url = buildWsUrl();
        console.log('[Sentinel] WebSocket bağlanıyor:', url);
        setConnectionState('reconnecting', 'BAĞLANIYOR…');

        try {
            state.ws = new WebSocket(url);
        } catch (e) {
            console.error('[Sentinel] WebSocket oluşturulamadı:', e);
            scheduleReconnect();
            return;
        }

        state.ws.onopen = () => {
            console.log('[Sentinel] WebSocket bağlandı');
            state.reconnectAttempts = 0;
            setConnectionState('online');
            startPing();
        };

        state.ws.onmessage = (evt) => {
            handleMessage(evt.data);
        };

        state.ws.onclose = (evt) => {
            console.log('[Sentinel] WebSocket kapandı:', evt.code, evt.reason);
            stopPing();
            setConnectionState('offline');
            scheduleReconnect();
        };

        state.ws.onerror = (err) => {
            console.error('[Sentinel] WebSocket hatası:', err);
        };
    }

    function scheduleReconnect() {
        const delay = Math.min(
            CONFIG.RECONNECT_BASE * Math.pow(2, state.reconnectAttempts),
            CONFIG.RECONNECT_MAX
        );
        state.reconnectAttempts++;
        console.log(`[Sentinel] ${delay}ms sonra yeniden denenecek (deneme ${state.reconnectAttempts})`);

        // Countdown display
        let remaining = Math.ceil(delay / 1000);
        setConnectionState('reconnecting', `${remaining}s`);

        state.countdownTimer = setInterval(() => {
            remaining--;
            if (remaining > 0) {
                setConnectionState('reconnecting', `${remaining}s`);
            } else {
                clearInterval(state.countdownTimer);
            }
        }, 1000);

        state.reconnectTimer = setTimeout(() => {
            clearInterval(state.countdownTimer);
            connectWebSocket();
        }, delay);
    }

    function startPing() {
        stopPing();
        state.pingTimer = setInterval(() => {
            if (state.ws && state.ws.readyState === WebSocket.OPEN) {
                try {
                    state.ws.send(JSON.stringify({ type: 'ping' }));
                } catch (_) { /* silent */ }
            }
        }, CONFIG.PING_INTERVAL);
    }

    function stopPing() {
        if (state.pingTimer) {
            clearInterval(state.pingTimer);
            state.pingTimer = null;
        }
    }

    /* ─── MESSAGE HANDLER ─── */
    function handleMessage(raw) {
        let msg;
        try {
            msg = JSON.parse(raw);
        } catch (e) {
            console.warn('[Sentinel] Geçersiz JSON:', raw);
            return;
        }

        const type = msg.type || msg.event;

        switch (type) {
            case 'init':
                handleInit(msg);
                break;

            case 'reset':
                handleReset(msg);
                break;

            case 'event':
                handleEvent(msg);
                break;

            case 'sensor_status':
                updateSensorStatus(msg.online);
                break;

            case 'alert':
                handleAlert(msg);
                break;

            case 'pong':
                // heartbeat ack
                break;

            default:
                console.log('[Sentinel] Bilinmeyen mesaj tipi:', type, msg);
        }
    }

    function handleInit(msg) {
        console.log('[Sentinel] Init alındı');
        if (msg.stats) updateKPIs(msg.stats);
        if (msg.attack_distribution) updateAttackDistribution(msg.attack_distribution);
        if (msg.recent_logs) loadRecentLogs(msg.recent_logs);
        if (msg.stats && msg.stats.sensors_online != null) {
            updateSensorStatus(msg.stats.sensors_online);
        }
    }

    function handleEvent(msg) {
        const d = msg.data || msg;

        // Update KPIs incrementally
        state.stats.total_events++;
        const isAnomaly = d.label === 'ANOMALY';
        if (isAnomaly) {
            state.stats.anomaly_count++;
            if (Number(d.threat_score) >= 70) {
                state.stats.critical_count++;
            }
        } else {
            state.stats.normal_count++;
        }

        updateKPIs(state.stats);

        // Update attack distribution (only for anomalies)
        if (isAnomaly && d.attack_type && d.attack_type !== 'BENIGN') {
            state.attackDistribution[d.attack_type] = (state.attackDistribution[d.attack_type] || 0) + 1;
            renderAttackChart();
        }

        // Add to feed
        addFeedEntry(d, true);
    }

    function handleAlert(msg) {
        const title = msg.title || 'Kritik Uyarı';
        const body = msg.body || '';
        showToast(title, body);
    }

    function handleReset(msg) {
        console.log('[Sentinel] Sıfırlama dalgası alındı');
        state.stats = { 
            total_events: 0, 
            anomaly_count: 0, 
            critical_count: 0, 
            normal_count: 0, 
            sensors_online: state.stats.sensors_online 
        };
        state.attackDistribution = {};
        animateCounter(dom.kpiTotal, 0);
        animateCounter(dom.kpiAnomaly, 0);
        animateCounter(dom.kpiCritical, 0);
        animateCounter(dom.kpiNormal, 0);
        renderAttackChart();
        dom.feedList.innerHTML = `
            <div class="feed-empty-state">
                <div class="typing-dots" aria-hidden="true">
                    <span></span><span></span><span></span>
                </div>
                <span>Olaylar bekleniyor…</span>
            </div>`;
    }

    /* ═══════════════════════════════════════
       HTTP FALLBACK
       ═══════════════════════════════════════ */
    async function fetchSummary() {
        try {
            const res = await fetch(CONFIG.API_SUMMARY);
            if (!res.ok) return;
            const data = await res.json();
            if (data.stats) updateKPIs(data.stats);
            if (data.attack_distribution) updateAttackDistribution(data.attack_distribution);
            if (data.recent_logs) loadRecentLogs(data.recent_logs);
            if (data.stats && data.stats.sensors_online != null) {
                updateSensorStatus(data.stats.sensors_online);
            }
            console.log('[Sentinel] HTTP özet yüklendi');
        } catch (e) {
            console.log('[Sentinel] HTTP özet alınamadı:', e.message);
        }
    }

    /* ═══════════════════════════════════════
       CLOCK
       ═══════════════════════════════════════ */
    function updateClock() {
        if (dom.footerClock) {
            const now = new Date();
            dom.footerClock.textContent = now.toLocaleTimeString('tr-TR', {
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
            });
        }
    }

    /* ═══════════════════════════════════════
       INIT
       ═══════════════════════════════════════ */
    function init() {
        console.log('[Sentinel] Dashboard başlatılıyor…');

        // Start clock
        updateClock();
        setInterval(updateClock, 1000);

        // HTTP fallback first
        fetchSummary();

        // Reset button listener
        if (dom.btnReset) {
            dom.btnReset.addEventListener('click', async () => {
                if (confirm('Tüm istatistikleri ve canlı akışı sıfırlamak istediğinize emin misiniz?')) {
                    try {
                        const res = await fetch('/api/reset', { method: 'POST' });
                        if (res.ok) {
                            console.log('[Sentinel] Sıfırlama talebi başarıyla gönderildi');
                        }
                    } catch (e) {
                        console.error('[Sentinel] Sıfırlama hatası:', e);
                    }
                }
            });
        }

        // WebSocket connection
        connectWebSocket();
    }

    // Boot
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

})();


/* ═══════════════════════════════════════════════════════════════
   GÜVENLİK ASİSTANI (CHATBOT) — Gemini destekli, /api/chat ile konuşur
   ═══════════════════════════════════════════════════════════════ */
(function () {
    'use strict';

    const fab = document.getElementById('chat-fab');
    const panel = document.getElementById('chat-panel');
    const closeBtn = document.getElementById('chat-close');
    const form = document.getElementById('chat-form');
    const input = document.getElementById('chat-input');
    const messages = document.getElementById('chat-messages');
    const sendBtn = form ? form.querySelector('.chat-send') : null;
    if (!fab || !panel || !form) return;

    const history = [];   // {role:'user'|'bot', text}
    let busy = false;

    function esc(s) {
        const d = document.createElement('div');
        d.textContent = String(s || '');
        return d.innerHTML;
    }

    function openPanel() {
        panel.classList.add('open');
        fab.classList.add('open');
        panel.setAttribute('aria-hidden', 'false');
        setTimeout(() => input.focus(), 150);
    }
    function closePanel() {
        panel.classList.remove('open');
        fab.classList.remove('open');
        panel.setAttribute('aria-hidden', 'true');
    }

    fab.addEventListener('click', () =>
        panel.classList.contains('open') ? closePanel() : openPanel());
    closeBtn.addEventListener('click', closePanel);

    function addMessage(text, who) {
        const el = document.createElement('div');
        el.className = 'chat-msg ' + who;
        el.innerHTML = esc(text).replace(/\n/g, '<br>');
        messages.appendChild(el);
        messages.scrollTop = messages.scrollHeight;
        return el;
    }

    function addTyping() {
        const el = document.createElement('div');
        el.className = 'chat-msg bot typing';
        el.innerHTML = '<span></span><span></span><span></span>';
        messages.appendChild(el);
        messages.scrollTop = messages.scrollHeight;
        return el;
    }

    async function send(text) {
        if (busy || !text) return;
        busy = true;
        if (sendBtn) sendBtn.disabled = true;

        const priorHistory = history.slice(-10);   // mevcut mesajı dahil etmeden gönder
        addMessage(text, 'user');
        history.push({ role: 'user', text });

        const typing = addTyping();
        try {
            const res = await fetch('/api/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: text, history: priorHistory }),
            });
            const data = await res.json();
            typing.remove();
            const reply = (data && data.reply) || 'Şu an yanıt veremiyorum.';
            addMessage(reply, 'bot');
            history.push({ role: 'bot', text: reply });
        } catch (e) {
            typing.remove();
            addMessage('Bağlantı hatası — lütfen biraz sonra tekrar deneyin.', 'bot');
        } finally {
            busy = false;
            if (sendBtn) sendBtn.disabled = false;
            input.focus();
        }
    }

    form.addEventListener('submit', (e) => {
        e.preventDefault();
        const t = input.value.trim();
        if (!t) return;
        input.value = '';
        send(t);
    });

    document.querySelectorAll('.chat-chip').forEach((chip) =>
        chip.addEventListener('click', () => send(chip.textContent.trim())));

})();
