/**
 * GRC Risk Analysis Engine — Frontend Logic
 * Handles form submission, API calls, gauge animation,
 * and analysis history tracking.
 */

(function () {
    'use strict';

    // ─── DOM Elements ───────────────────────────────────────────
    const form = document.getElementById('analysisForm');
    const analyzeBtn = document.getElementById('analyzeBtn');
    const gaugeScore = document.getElementById('gaugeScore');
    const gaugeFill = document.getElementById('gaugeFill');
    const riskBadge = document.getElementById('riskBadge');
    const riskLevel = document.getElementById('riskLevel');
    const anomalyCard = document.getElementById('anomalyCard');
    const anomalyStatus = document.getElementById('anomalyStatus');
    const confidenceCard = document.getElementById('confidenceCard');
    const summaryCard = document.getElementById('summaryCard');
    const summaryText = document.getElementById('summaryText');
    const actionsCard = document.getElementById('actionsCard');
    const actionsList = document.getElementById('actionsList');
    const historyPanel = document.getElementById('historyPanel');
    const historyBody = document.getElementById('historyBody');
    const clearHistoryBtn = document.getElementById('clearHistoryBtn');

    // Range input value displays
    const criticalitySlider = document.getElementById('asset_criticality');
    const sensitivitySlider = document.getElementById('data_sensitivity');
    const criticalityValue = document.getElementById('criticalityValue');
    const sensitivityValue = document.getElementById('sensitivityValue');

    // Analysis history
    let history = [];
    let analysisCount = 0;

    // Gauge constants
    const GAUGE_CIRCUMFERENCE = 2 * Math.PI * 85; // ~534

    // ─── Initialize ─────────────────────────────────────────────
    function init() {
        // Range sliders
        criticalitySlider.addEventListener('input', () => {
            criticalityValue.textContent = criticalitySlider.value;
        });
        sensitivitySlider.addEventListener('input', () => {
            sensitivityValue.textContent = sensitivitySlider.value;
        });

        // Form submission
        form.addEventListener('submit', handleSubmit);

        // Clear history
        clearHistoryBtn.addEventListener('click', clearHistory);

        // Check API health
        checkHealth();
    }

    // ─── Health Check ───────────────────────────────────────────
    async function checkHealth() {
        try {
            const resp = await fetch('/api/health');
            const data = await resp.json();
            const badge = document.getElementById('statusBadge');
            if (data.status === 'healthy') {
                badge.className = 'status-badge online';
                badge.querySelector('span:last-child').textContent = 'System Online';
            }
        } catch (e) {
            const badge = document.getElementById('statusBadge');
            badge.className = 'status-badge';
            badge.style.background = 'rgba(239, 68, 68, 0.1)';
            badge.style.color = '#ef4444';
            badge.style.borderColor = 'rgba(239, 68, 68, 0.2)';
            badge.querySelector('span:last-child').textContent = 'System Offline';
        }
    }

    // ─── Form Submission ────────────────────────────────────────
    async function handleSubmit(e) {
        e.preventDefault();

        // Collect form data
        const payload = {
            cvss_score: parseFloat(document.getElementById('cvss_score').value),
            vulnerability_type: document.getElementById('vulnerability_type').value,
            exploit_available: document.getElementById('exploit_available').checked ? 1 : 0,
            cve_age_days: parseInt(document.getElementById('cve_age_days').value),
            asset_criticality: parseInt(document.getElementById('asset_criticality').value),
            internet_exposed: document.getElementById('internet_exposed').checked ? 1 : 0,
            data_sensitivity: parseInt(document.getElementById('data_sensitivity').value),
            failed_logins: parseInt(document.getElementById('failed_logins').value),
            request_rate: parseFloat(document.getElementById('request_rate').value),
            traffic_spike: document.getElementById('traffic_spike').checked ? 1 : 0,
        };

        // Loading state
        analyzeBtn.classList.add('loading');

        try {
            const resp = await fetch('/api/analyze', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            });

            if (!resp.ok) {
                const err = await resp.json();
                throw new Error(err.error || 'Analysis failed');
            }

            const result = await resp.json();
            displayResults(result);
            addToHistory(result);

        } catch (err) {
            console.error('Analysis error:', err);
            alert('Analysis Error: ' + err.message);
        } finally {
            analyzeBtn.classList.remove('loading');
        }
    }

    // ─── Display Results ────────────────────────────────────────
    function displayResults(result) {
        // 1. Animate gauge
        animateGauge(result.risk_score, result.risk_level);

        // 2. Update risk badge
        updateRiskBadge(result.risk_level);

        // 3. Update anomaly card
        updateAnomalyCard(result.anomaly_detected);

        // 4. Update confidence bars
        if (result.confidence) {
            updateConfidence(result.confidence);
        }

        // 5. Show vulnerability summary
        summaryCard.style.display = 'block';
        summaryText.textContent = result.vulnerability_summary;
        summaryCard.style.animation = 'none';
        summaryCard.offsetHeight; // trigger reflow
        summaryCard.style.animation = 'fadeInUp 0.5s ease';

        // 6. Show recommended actions
        actionsCard.style.display = 'block';
        actionsList.innerHTML = '';
        result.recommended_actions.forEach(action => {
            const li = document.createElement('li');
            li.innerHTML = `<span class="action-check">►</span> ${escapeHtml(action)}`;
            actionsList.appendChild(li);
        });
        actionsCard.style.animation = 'none';
        actionsCard.offsetHeight;
        actionsCard.style.animation = 'fadeInUp 0.5s ease 0.1s both';
    }

    // ─── Gauge Animation ────────────────────────────────────────
    function animateGauge(score, level) {
        const offset = GAUGE_CIRCUMFERENCE - (score / 100) * GAUGE_CIRCUMFERENCE;
        const color = getRiskColor(level);

        gaugeFill.style.strokeDasharray = GAUGE_CIRCUMFERENCE;
        gaugeFill.style.strokeDashoffset = offset;
        gaugeFill.style.stroke = color;

        // Animate number
        animateNumber(gaugeScore, score);
        gaugeScore.style.color = color;
    }

    function animateNumber(el, target) {
        const duration = 1200;
        const start = parseInt(el.textContent) || 0;
        const diff = target - start;
        const startTime = performance.now();

        function update(now) {
            const elapsed = now - startTime;
            const progress = Math.min(elapsed / duration, 1);
            // Ease out cubic
            const eased = 1 - Math.pow(1 - progress, 3);
            el.textContent = Math.round(start + diff * eased);
            if (progress < 1) requestAnimationFrame(update);
        }

        requestAnimationFrame(update);
    }

    // ─── Risk Badge ─────────────────────────────────────────────
    function updateRiskBadge(level) {
        riskBadge.className = 'risk-badge ' + level.toLowerCase();
        riskLevel.textContent = level;
    }

    // ─── Anomaly Card ───────────────────────────────────────────
    function updateAnomalyCard(detected) {
        if (detected) {
            anomalyCard.className = 'anomaly-card detected';
            anomalyStatus.textContent = 'Anomalous behavior detected!';
            anomalyStatus.style.color = '#ef4444';
        } else {
            anomalyCard.className = 'anomaly-card normal';
            anomalyStatus.textContent = 'No anomalies detected';
            anomalyStatus.style.color = '#22c55e';
        }
    }

    // ─── Confidence Bars ────────────────────────────────────────
    function updateConfidence(conf) {
        confidenceCard.style.display = 'block';

        setTimeout(() => {
            document.getElementById('confLow').style.width = conf.low + '%';
            document.getElementById('confLowPct').textContent = conf.low.toFixed(1) + '%';
            document.getElementById('confMed').style.width = conf.medium + '%';
            document.getElementById('confMedPct').textContent = conf.medium.toFixed(1) + '%';
            document.getElementById('confHigh').style.width = conf.high + '%';
            document.getElementById('confHighPct').textContent = conf.high.toFixed(1) + '%';
        }, 100);
    }

    // ─── History ────────────────────────────────────────────────
    function addToHistory(result) {
        analysisCount++;
        history.unshift(result);

        // Keep only last 20
        if (history.length > 20) history.pop();

        renderHistory();
        historyPanel.style.display = 'block';
    }

    function renderHistory() {
        historyBody.innerHTML = '';
        history.forEach((item, idx) => {
            const input = item.input || {};
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${history.length - idx}</td>
                <td>${item.timestamp || '—'}</td>
                <td>${escapeHtml(input.vulnerability_type || '—')}</td>
                <td>${input.cvss_score || '—'}</td>
                <td><strong>${item.risk_score}</strong></td>
                <td><span class="level-badge ${item.risk_level.toLowerCase()}">${item.risk_level}</span></td>
                <td class="${item.anomaly_detected ? 'anomaly-true' : 'anomaly-false'}">
                    ${item.anomaly_detected ? '⚠ Yes' : '✓ No'}
                </td>
            `;
            historyBody.appendChild(tr);
        });
    }

    function clearHistory() {
        history = [];
        analysisCount = 0;
        historyBody.innerHTML = '';
        historyPanel.style.display = 'none';
    }

    // ─── Utilities ──────────────────────────────────────────────
    function getRiskColor(level) {
        const colors = {
            'Low': '#22c55e',
            'Medium': '#f59e0b',
            'High': '#ef4444',
        };
        return colors[level] || '#64748b';
    }

    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    // ─── Start ──────────────────────────────────────────────────
    document.addEventListener('DOMContentLoaded', init);
})();
