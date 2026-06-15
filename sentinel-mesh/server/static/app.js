/* ═══════════════════════════════════════════════════════════════
   HIDS DASHBOARD — Real-time Client
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

    /* MITRE ATT&CK eşlemesi (canlı veri 'mitre' taşımazsa istemci tarafı yedek) */
    const MITRE_MAP = {
        PortScan: 'T1046', Recon_Scan: 'T1046',
        SYN_Flood: 'T1498', DoS_Flood: 'T1498', DDoS_HTTP: 'T1498', Mirai_Botnet: 'T1498',
        BruteForce: 'T1110', Slowloris: 'T1499', ML_Detected: 'T1190',
    };
    const MITRE_NAME = {
        T1046: 'Network Service Discovery', T1498: 'Network Denial of Service',
        T1110: 'Brute Force', T1499: 'Endpoint Denial of Service',
        T1190: 'Exploit Public-Facing Application',
    };
    /* Saldırı türüne göre önerilen müdahale adımları (SOC playbook) */
    const PLAYBOOK = {
        PortScan: ['Kaynak IP\'yi gözlem listesine al / geçici engelle', 'Açık portları ve gereksiz servisleri gözden geçir', 'Güvenlik duvarı kurallarını sıkılaştır'],
        SYN_Flood: ['SYN cookie\'leri etkinleştir', 'Kaynak IP\'yi rate-limit/engelle', 'Upstream DDoS korumasını uyar'],
        DoS_Flood: ['Trafiği rate-limit et', 'Kaynak IP\'yi engelle', 'Bant genişliği/kaynak kullanımını izle'],
        DDoS_HTTP: ['WAF / istek rate-limit uygula', 'Şüpheli IP bloklarını engelle'],
        BruteForce: ['Hedef hesabı geçici kilitle', 'fail2ban/oran sınırı uygula', 'Güçlü parola + 2FA zorunlu kıl'],
        Mirai_Botnet: ['IoT cihaz varsayılan parolalarını değiştir', 'Telnet (23) portunu kapat', 'Cihaz firmware\'ini güncelle'],
        Slowloris: ['Bağlantı zaman aşımı/limitlerini ayarla', 'mod_reqtimeout / WAF kuralı uygula'],
        Recon_Scan: ['Kaynak IP davranışını izle', 'Saldırı yüzeyini (açık servisler) azalt'],
        ML_Detected: ['Akışı manuel incele', 'Kaynak IP\'yi gözlem listesine al', 'Benzer akışlarla korelasyon kur'],
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
        modeBadge: $('#mode-badge'),
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
        eventModal: $('#event-modal'),
        eventModalBody: $('#event-modal-body'),
        eventModalClose: $('#event-modal-close'),
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

    /* Veri kaynağı rozeti: gerçek sensör (CANLI) mu, örnek veri (DEMO) mu */
    function updateModeBadge(isDemo) {
        if (!dom.modeBadge) return;
        const demo = !!isDemo;
        dom.modeBadge.className = 'mode-badge ' + (demo ? 'demo' : 'live');
        const txt = dom.modeBadge.querySelector('.mode-text');
        if (txt) txt.textContent = demo ? 'DEMO' : 'CANLI';
        dom.modeBadge.title = demo
            ? 'DEMO: örnek (simüle) veri gösteriliyor — gerçek sensör bağlı değil'
            : 'CANLI: gerçek sensörden gelen veriler';
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
        const mitre = d.mitre || MITRE_MAP[d.attack_type] || '';

        // Açıklanabilirlik: XGBoost SHAP öznitelikleri (canlı) ya da kural/demo gerekçesi
        let whyText = '';
        if (Array.isArray(d.shap_top) && d.shap_top.length) {
            whyText = 'Neden: ' + d.shap_top.slice(0, 3)
                .map(s => esc(s.feature)).join(', ');
        } else if (d.reason) {
            whyText = 'Neden: ' + esc(d.reason);
        }
        const whyHtml = whyText
            ? `<div class="feed-entry-why" title="Modelin/kuralın kararını açıklayan göstergeler">${whyText}</div>`
            : '';

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
                    ${mitre ? `<span class="mitre-badge" title="MITRE ATT&CK tekniği">${esc(mitre)}</span>` : ''}
                </div>
                ${whyHtml}
            </div>
            <div class="feed-entry-right">
                <span class="threat-badge threat-${tClass}">${threatLabel(d.threat_score)} ${Math.round(d.threat_score || 0)}</span>
                <span class="feed-entry-time">${fmtTime(d.timestamp || d.server_time)}</span>
            </div>`;

        entry.classList.add('clickable');
        entry.addEventListener('click', () => openEventDetail(d));

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
       OLAY DETAY PANELİ (SHAP + MITRE + müdahale)
       ═══════════════════════════════════════ */
    function buildShapHtml(shap) {
        if (!Array.isArray(shap) || !shap.length) return '';
        const maxAbs = Math.max(...shap.map(s => Math.abs(Number(s.value) || 0)), 1e-9);
        let rows = '';
        for (const s of shap) {
            const v = Number(s.value) || 0;
            const pct = Math.max(Math.abs(v) / maxAbs * 100, 2);
            const dir = v >= 0 ? 'shap-pos' : 'shap-neg';
            rows += `
                <div class="shap-row">
                    <span class="shap-feat" title="${esc(s.feature)}">${esc(s.feature)}</span>
                    <div class="shap-track"><div class="shap-fill ${dir}" style="width:${pct.toFixed(0)}%"></div></div>
                    <span class="shap-val">${v >= 0 ? '+' : ''}${v.toFixed(3)}</span>
                </div>`;
        }
        return `<div class="modal-section">
                    <h4>Açıklanabilirlik — SHAP (kararı en çok etkileyen öznitelikler)</h4>
                    <div class="shap-list">${rows}</div>
                    <p class="shap-note">Kırmızı (+): saldırı olasılığını artıran · Yeşil (−): azaltan öznitelik.</p>
                </div>`;
    }

    function openEventDetail(d) {
        if (!dom.eventModal || !d) return;
        const tClass = threatClass(d.threat_score);
        const mitre = d.mitre || MITRE_MAP[d.attack_type] || '';
        const mitreName = MITRE_NAME[mitre] || '';
        const methodLabel = (d.method || '').toLowerCase() === 'xgboost' ? 'XGBoost (akış-bazlı ML)' : 'Kural tabanlı';

        let whyHtml = buildShapHtml(d.shap_top);
        if (!whyHtml && d.reason) {
            whyHtml = `<div class="modal-section"><h4>Neden</h4><p>${esc(d.reason)}</p></div>`;
        } else if (!whyHtml) {
            whyHtml = `<div class="modal-section"><h4>Neden</h4><p>Bilinen saldırı imzası/kuralı eşleşti (${esc(d.attack_type || '-')}).</p></div>`;
        }

        const actions = PLAYBOOK[d.attack_type] || ['Olayı incele', 'Kaynak IP davranışını izle'];
        const actionsHtml = actions.map(a => `<li>${esc(a)}</li>`).join('');

        const conf = d.confidence != null ? `${(Number(d.confidence) * 100).toFixed(1)}%` : '—';
        const inf = (d.inference_ms != null && Number(d.inference_ms) > 0) ? `${Number(d.inference_ms).toFixed(2)} ms` : '—';
        const rows = [
            ['Kaynak', esc(d.source_ip || '?')],
            ['Hedef', esc(d.destination_ip || '?')],
            ['Yöntem', methodLabel],
            ['Tehdit skoru', `${Math.round(d.threat_score || 0)}/100 (${threatLabel(d.threat_score)})`],
            ['Güven', conf],
            ['Akış paketi', d.flow_packets != null ? d.flow_packets : '—'],
            ['Çıkarım süresi', inf],
            ['Zaman', esc(d.timestamp || d.server_time || d.ts_iso || '—')],
        ].map(([k, v]) => `<div class="kv"><span class="kv-k">${k}</span><span class="kv-v">${v}</span></div>`).join('');

        dom.eventModalBody.innerHTML = `
            <div class="modal-head threat-${tClass}">
                <h3 id="event-modal-title">${esc(d.attack_type || d.label || 'Olay')}</h3>
                <span class="threat-badge threat-${tClass}">${threatLabel(d.threat_score)} ${Math.round(d.threat_score || 0)}</span>
            </div>
            ${mitre ? `<div class="modal-mitre">MITRE ATT&CK: <strong>${esc(mitre)}</strong>${mitreName ? ` — ${esc(mitreName)}` : ''}</div>` : ''}
            <div class="modal-kv">${rows}</div>
            ${whyHtml}
            <div class="modal-section"><h4>Önerilen müdahale</h4><ul class="modal-actions">${actionsHtml}</ul></div>`;

        dom.eventModal.classList.add('open');
        dom.eventModal.setAttribute('aria-hidden', 'false');
    }

    function closeEventDetail() {
        if (!dom.eventModal) return;
        dom.eventModal.classList.remove('open');
        dom.eventModal.setAttribute('aria-hidden', 'true');
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
        console.log('[Dashboard] WebSocket bağlanıyor:', url);
        setConnectionState('reconnecting', 'BAĞLANIYOR…');

        try {
            state.ws = new WebSocket(url);
        } catch (e) {
            console.error('[Dashboard] WebSocket oluşturulamadı:', e);
            scheduleReconnect();
            return;
        }

        state.ws.onopen = () => {
            console.log('[Dashboard] WebSocket bağlandı');
            state.reconnectAttempts = 0;
            setConnectionState('online');
            startPing();
        };

        state.ws.onmessage = (evt) => {
            handleMessage(evt.data);
        };

        state.ws.onclose = (evt) => {
            console.log('[Dashboard] WebSocket kapandı:', evt.code, evt.reason);
            stopPing();
            setConnectionState('offline');
            scheduleReconnect();
        };

        state.ws.onerror = (err) => {
            console.error('[Dashboard] WebSocket hatası:', err);
        };
    }

    function scheduleReconnect() {
        const delay = Math.min(
            CONFIG.RECONNECT_BASE * Math.pow(2, state.reconnectAttempts),
            CONFIG.RECONNECT_MAX
        );
        state.reconnectAttempts++;
        console.log(`[Dashboard] ${delay}ms sonra yeniden denenecek (deneme ${state.reconnectAttempts})`);

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
            console.warn('[Dashboard] Geçersiz JSON:', raw);
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
                if ('demo_mode' in msg) updateModeBadge(msg.demo_mode);
                break;

            case 'alert':
                handleAlert(msg);
                break;

            case 'pong':
                // heartbeat ack
                break;

            default:
                console.log('[Dashboard] Bilinmeyen mesaj tipi:', type, msg);
        }
    }

    function handleInit(msg) {
        console.log('[Dashboard] Init alındı');
        if (msg.stats) updateKPIs(msg.stats);
        if (msg.attack_distribution) updateAttackDistribution(msg.attack_distribution);
        if (msg.recent_logs) loadRecentLogs(msg.recent_logs);
        if (msg.stats && msg.stats.sensors_online != null) {
            updateSensorStatus(msg.stats.sensors_online);
        }
        if ('demo_mode' in msg) updateModeBadge(msg.demo_mode);
    }

    /* ─── Throttled rendering: flood altında tarayıcı donmasın ───
       Sayaçlar her olayda anında güncellenir (state), ama pahalı DOM işleri
       (feed satırı, grafik, KPI animasyonu) 250 ms'de bir TOPLU yapılır. */
    let _feedBuffer = [];
    let _flushTimer = null;
    let _kpiDirty = false;
    let _chartDirty = false;

    function scheduleFlush() {
        if (_flushTimer) return;
        _flushTimer = setTimeout(flushRender, 250);
    }

    function flushRender() {
        _flushTimer = null;
        if (_feedBuffer.length) {
            const batch = _feedBuffer.splice(0, _feedBuffer.length);
            // Yalnızca en yeni MAX_FEED_ENTRIES kadarını render et (DOM thrash önle)
            const toRender = batch.slice(-CONFIG.MAX_FEED_ENTRIES);
            for (const d of toRender) addFeedEntry(d, true);
        }
        if (_kpiDirty) { _kpiDirty = false; updateKPIs(state.stats); }
        if (_chartDirty) { _chartDirty = false; renderAttackChart(); }
    }

    function handleEvent(msg) {
        const d = msg.data || msg;

        // Sayaçları anında güncelle (ucuz)
        state.stats.total_events++;
        const isAnomaly = d.label === 'ANOMALY';
        if (isAnomaly) {
            state.stats.anomaly_count++;
            if (Number(d.threat_score) >= 70) state.stats.critical_count++;
            if (d.attack_type && d.attack_type !== 'BENIGN') {
                state.attackDistribution[d.attack_type] = (state.attackDistribution[d.attack_type] || 0) + 1;
                _chartDirty = true;
            }
        } else {
            state.stats.normal_count++;
        }

        // Pahalı render'ları kuyruğa al (throttle)
        _kpiDirty = true;
        _feedBuffer.push(d);
        if (_feedBuffer.length > 300) _feedBuffer = _feedBuffer.slice(-300);
        scheduleFlush();
    }

    function handleAlert(msg) {
        const title = msg.title || 'Kritik Uyarı';
        const body = msg.body || '';
        showToast(title, body);
    }

    function handleReset(msg) {
        console.log('[Dashboard] Sıfırlama dalgası alındı');
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
            if ('demo_mode' in data) updateModeBadge(data.demo_mode);
            console.log('[Dashboard] HTTP özet yüklendi');
        } catch (e) {
            console.log('[Dashboard] HTTP özet alınamadı:', e.message);
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
        console.log('[Dashboard] Dashboard başlatılıyor…');

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
                            console.log('[Dashboard] Sıfırlama talebi başarıyla gönderildi');
                        }
                    } catch (e) {
                        console.error('[Dashboard] Sıfırlama hatası:', e);
                    }
                }
            });
        }

        // Olay detay paneli kapatma (X, arka plan, Esc)
        if (dom.eventModalClose) dom.eventModalClose.addEventListener('click', closeEventDetail);
        if (dom.eventModal) {
            const backdrop = dom.eventModal.querySelector('.event-modal-backdrop');
            if (backdrop) backdrop.addEventListener('click', closeEventDetail);
        }
        document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeEventDetail(); });

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
