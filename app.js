/* ================================================================
   app.js — ScamShield UI Controller
   ================================================================ */

'use strict';

// ================================================================
// GLOBAL STATE
// ================================================================
let qrDecodedContent = null;
let currentReport    = null;

// ================================================================
// INIT
// ================================================================
document.addEventListener('DOMContentLoaded', () => {
  initNavbarScroll();
  initTabs();
  initURLPreview();
  initQRDragDrop();
  initCharCounter();
});

// ================================================================
// NAVBAR SCROLL EFFECT
// ================================================================
function initNavbarScroll() {
  const nav = document.getElementById('navbar');
  if (!nav) return;
  window.addEventListener('scroll', () => {
    if (window.scrollY > 40) {
      nav.style.background = 'rgba(7,9,26,0.97)';
    } else {
      nav.style.background = 'rgba(7,9,26,0.8)';
    }
  }, { passive: true });
}

// ================================================================
// TABS
// ================================================================
function initTabs() {
  const buttons = document.querySelectorAll('.tab-btn');
  buttons.forEach(btn => {
    btn.addEventListener('click', () => {
      const tab = btn.dataset.tab;

      buttons.forEach(b => {
        b.classList.remove('active');
        b.setAttribute('aria-selected', 'false');
      });
      btn.classList.add('active');
      btn.setAttribute('aria-selected', 'true');

      document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
      const panel = document.getElementById('panel-' + tab);
      if (panel) panel.classList.add('active');

      hideResults();
    });
  });
}

// ================================================================
// URL PREVIEW
// ================================================================
function initURLPreview() {
  const input = document.getElementById('url-input');
  const breakdown = document.getElementById('url-breakdown');
  if (!input || !breakdown) return;

  input.addEventListener('input', () => {
    const val = input.value.trim();
    if (val.length > 4) {
      try {
        let url = val;
        if (!/^https?:\/\//i.test(url)) url = 'https://' + url;
        const u = new URL(url);
        document.getElementById('bp-protocol').textContent = u.protocol + '//';
        document.getElementById('bp-domain').textContent = u.hostname;
        document.getElementById('bp-path').textContent = u.pathname + u.search;
        breakdown.style.display = 'block';
      } catch (e) {
        breakdown.style.display = 'none';
      }
    } else {
      breakdown.style.display = 'none';
    }
  });

  input.addEventListener('keydown', e => {
    if (e.key === 'Enter') analyzeURL();
  });
}

// ================================================================
// QR DRAG & DROP
// ================================================================
function initQRDragDrop() {
  const zone = document.getElementById('qr-upload-zone');
  if (!zone) return;

  zone.addEventListener('dragover', e => {
    e.preventDefault();
    zone.classList.add('drag-over');
  });

  zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));

  zone.addEventListener('drop', e => {
    e.preventDefault();
    zone.classList.remove('drag-over');
    const file = e.dataTransfer.files[0];
    if (file) handleQRFile(file);
  });
}

// ================================================================
// CHAR COUNTER
// ================================================================
function initCharCounter() {
  const ta = document.getElementById('message-input');
  const counter = document.getElementById('msg-char-count');
  if (!ta || !counter) return;

  ta.addEventListener('input', () => {
    const len = ta.value.length;
    counter.textContent = `${len} / 3000`;
    counter.style.color = len > 2700 ? 'var(--high)' : 'var(--text-3)';
  });
}

// ================================================================
// EXAMPLE PRESETS
// ================================================================
const EXAMPLES = {
  // Message examples
  msg_amazon: `URGENT: Your Amazon account has been compromised and your refund of ₹2,499 is pending. Click here immediately to receive it: http://amaz0n-refund.xyz/claim?ref=ABC123. Our executive will call you — please share the OTP you receive to verify your identity. Act now or your refund will be cancelled within 24 hours.`,

  msg_hdfc: `Dear Customer, Your HDFC Bank account has been suspended due to suspicious activity. Call our helpline at 9876543210 immediately to unlock your account. Our executive will ask for your OTP to verify your identity. Action required within 2 hours or your account will be permanently blocked.`,

  msg_lottery: `Congratulations! You have been selected as the Lucky Winner of ₹10,00,000 in the Government of India Digital Payment Lottery 2026. To claim your prize, you need to pay a small processing fee of ₹499. Send it to our UPI ID: refund.lottery.india@paytm. The full amount will be credited within 30 minutes.`,

  msg_otp: `RBI Official Notice: Your bank account shows an unauthorized transaction of ₹24,999. To reverse this, our senior executive needs you to share the OTP sent to your mobile. Please call 1800-XXX-XXXX and provide the OTP to recover your funds. Do not delay — this expires in 15 minutes.`,

  // URL examples
  url_phishing: `http://hdfc-bank-secure-update.xyz/login?verify=customer&id=84729`,
  url_ip: `http://192.168.1.105/payment/checkout?order=12345&token=abc`,
  url_subdomain: `https://amazon.refund-claim.online/verify?user=customer123`,
  url_legit: `https://www.amazon.in/gp/css/order-history`,

  // QR examples
  qr_upi_scam: `upi://pay?pa=scammer.refund@ybl&pn=Amazon Refund Dept&am=499&tn=Processing Fee Refund&cu=INR`,
  qr_url_scam: `https://hdfc-bank-secure.xyz/otp-verify?user=customer&ref=84729`,
  qr_legit: `upi://pay?pa=coffeeshop@oksbi&pn=City Coffee&mc=5812&tid=TXN001`,
};

function loadExample(key) {
  const text = EXAMPLES[key];
  if (!text) return;

  if (key.startsWith('msg_')) {
    const ta = document.getElementById('message-input');
    if (ta) {
      ta.value = text;
      ta.dispatchEvent(new Event('input'));
    }
  } else if (key.startsWith('url_')) {
    const inp = document.getElementById('url-input');
    if (inp) {
      inp.value = text;
      inp.dispatchEvent(new Event('input'));
    }
  } else if (key.startsWith('qr_')) {
    const inp = document.getElementById('qr-manual-input');
    if (inp) inp.value = text;
  }
}

function loadCombinedExample(scenario) {
  if (scenario === 'full_scam') {
    const msg = document.getElementById('combined-message');
    const url = document.getElementById('combined-url');
    const amt = document.getElementById('combined-amount');
    const pay = document.getElementById('combined-payee');
    if (msg) msg.value = 'Your Amazon refund of ₹2499 is ready. Click the link to claim. Share OTP to verify.';
    if (url) url.value = 'http://amaz0n-refund.xyz/claim?verify=customer';
    if (amt) amt.value = '499';
    if (pay) pay.value = 'Amazon Refund Helpline';
  } else if (scenario === 'legitimate') {
    const msg = document.getElementById('combined-message');
    const url = document.getElementById('combined-url');
    const amt = document.getElementById('combined-amount');
    const pay = document.getElementById('combined-payee');
    if (msg) msg.value = 'Your order has been dispatched and will arrive by tomorrow.';
    if (url) url.value = 'https://www.amazon.in/gp/css/order-history';
    if (amt) amt.value = '1299';
    if (pay) pay.value = 'Amazon Seller Services';
  }
}

// ================================================================
// ANALYSIS ORCHESTRATORS
// ================================================================

async function analyzeMessage() {
  const text = document.getElementById('message-input').value.trim();
  if (!text) { showToast('⚠️', 'Please enter a message to analyze'); return; }

  showLoading();
  await wait(300);
  activateStep('lstep-text');

  const textResult = TextAnalyzer.analyze(text);

  await wait(500);
  doneStep('lstep-text');
  activateStep('lstep-risk');

  const score = RiskEngine.computeFinalScore([{ score: textResult.score, weight: 3 }]);

  await wait(450);
  doneStep('lstep-risk');
  activateStep('lstep-explain');

  const report = RiskEngine.generateReport(textResult.signals, score);

  await wait(400);
  doneStep('lstep-explain');
  await wait(200);

  hideLoading();
  displayResults(report);
}

async function analyzeURL() {
  const url = document.getElementById('url-input').value.trim();
  if (!url) { showToast('⚠️', 'Please enter a URL to analyze'); return; }

  showLoading();
  await wait(300);
  activateStep('lstep-url');

  const urlResult = URLAnalyzer.analyze(url);

  await wait(700);
  doneStep('lstep-url');
  activateStep('lstep-risk');

  const score = RiskEngine.computeFinalScore([{ score: urlResult.score, weight: 3 }]);

  await wait(400);
  doneStep('lstep-risk');
  activateStep('lstep-explain');

  const report = RiskEngine.generateReport(urlResult.signals, score);

  await wait(400);
  doneStep('lstep-explain');
  await wait(200);

  hideLoading();
  displayResults(report);
}

// ---- QR file upload ----
function handleQRUpload(event) {
  const file = event.target.files && event.target.files[0];
  if (file) handleQRFile(file);
  // Reset input so same file can be re-selected
  event.target.value = '';
}

function handleQRFile(file) {
  if (!file.type.startsWith('image/')) {
    showToast('❌', 'Please upload an image file (PNG, JPG, WebP)');
    return;
  }

  const reader = new FileReader();
  reader.onload = function (e) {
    const img = new Image();
    img.onload = async function () {
      // Show preview
      const previewImg = document.getElementById('qr-preview-img');
      if (previewImg) previewImg.src = e.target.result;

      document.getElementById('qr-upload-zone').style.display   = 'none';
      document.getElementById('qr-preview-box').style.display   = 'flex';
      document.getElementById('qr-manual-section').style.display = 'none';

      const decodeTextEl = document.getElementById('qr-decode-text');
      const decodeTypeEl = document.getElementById('qr-decode-type');

      if (decodeTextEl) decodeTextEl.textContent = 'Decoding...';
      if (decodeTypeEl) decodeTypeEl.textContent  = '';

      // Attempt decode
      const decoded = await QRAnalyzer.decodeFromImage(img);

      if (decoded) {
        qrDecodedContent = decoded;
        if (decodeTextEl) decodeTextEl.textContent = decoded;

        // Show content type label
        let typeLabel = '';
        if (/^upi:\/\/pay/i.test(decoded)) typeLabel = '🔵 UPI Payment QR';
        else if (/^https?:\/\//i.test(decoded)) typeLabel = '🔗 URL QR';
        else typeLabel = '📄 Text QR';
        if (decodeTypeEl) decodeTypeEl.textContent = typeLabel;
      } else {
        qrDecodedContent = null;
        if (decodeTextEl) decodeTextEl.textContent = '⚠️ Could not decode this QR code. Try the manual input below.';
        // Show manual fallback
        document.getElementById('qr-manual-section').style.display = 'block';
      }
    };
    img.src = e.target.result;
  };
  reader.readAsDataURL(file);
}

async function analyzeQR() {
  if (!qrDecodedContent) {
    showToast('⚠️', 'No QR code decoded yet. Please upload a valid QR image.');
    return;
  }
  await runQRAnalysis(qrDecodedContent);
}

async function analyzeQRManual() {
  const content = document.getElementById('qr-manual-input').value.trim();
  if (!content) {
    showToast('⚠️', 'Please enter the QR code content');
    return;
  }
  await runQRAnalysis(content);
}

async function runQRAnalysis(content) {
  showLoading();
  await wait(300);
  activateStep('lstep-qr');

  const qrResult = QRAnalyzer.analyze(content);

  await wait(600);
  doneStep('lstep-qr');
  activateStep('lstep-risk');

  const score = RiskEngine.computeFinalScore([{ score: qrResult.score, weight: 3 }]);

  await wait(450);
  doneStep('lstep-risk');
  activateStep('lstep-explain');

  const report = RiskEngine.generateReport(qrResult.signals, score);

  await wait(400);
  doneStep('lstep-explain');
  await wait(200);

  hideLoading();
  displayResults(report);
}

async function analyzeAll() {
  const message = document.getElementById('combined-message').value.trim();
  const url     = document.getElementById('combined-url').value.trim();
  const amount  = document.getElementById('combined-amount').value.trim();
  const payee   = document.getElementById('combined-payee').value.trim();

  if (!message && !url && !amount && !payee) {
    showToast('⚠️', 'Please fill in at least one field');
    return;
  }

  showLoading();
  await wait(300);

  const results    = [];
  const allSignals = [];

  // Text analysis
  activateStep('lstep-text');
  if (message) {
    const r = TextAnalyzer.analyze(message);
    results.push({ score: r.score, weight: 3 });
    allSignals.push(...r.signals);
  }
  await wait(500);
  doneStep('lstep-text');

  // URL analysis
  activateStep('lstep-url');
  if (url) {
    const r = URLAnalyzer.analyze(url);
    results.push({ score: r.score, weight: 3 });
    allSignals.push(...r.signals);
  }
  await wait(500);
  doneStep('lstep-url');

  // Behavioural analysis
  activateStep('lstep-qr');
  if (amount || payee) {
    const r = BehaviouralAnalyzer.analyze({
      amount,
      payeeName: payee,
      purpose: message ? message.substring(0, 80) : '',
    });
    results.push({ score: r.score, weight: 2 });
    allSignals.push(...r.signals);
  }
  await wait(450);
  doneStep('lstep-qr');

  // Risk computation
  activateStep('lstep-risk');
  const dedupedSignals = deduplicateSignals(allSignals);
  const score = RiskEngine.computeFinalScore(results.length ? results : [{ score: 0, weight: 1 }]);
  await wait(400);
  doneStep('lstep-risk');

  // Explanation
  activateStep('lstep-explain');
  const report = RiskEngine.generateReport(dedupedSignals, score);
  await wait(400);
  doneStep('lstep-explain');
  await wait(200);

  hideLoading();
  displayResults(report);
}

// ================================================================
// DISPLAY RESULTS
// ================================================================
function displayResults(report) {
  currentReport = report;
  const { score, level, display, allSignals, summary, actionSteps, explanation, safeAlternatives } = report;

  const panel = document.getElementById('results-panel');
  panel.style.display = 'flex';

  // ── Risk overview card ──────────────────────────────────────
  const overviewCard = document.getElementById('risk-overview-card');
  overviewCard.className = `result-card risk-card ${display.cardClass}`;

  // Badge
  const badge = document.getElementById('risk-badge');
  badge.className = `risk-badge ${display.badgeClass}`;
  document.getElementById('risk-badge-icon').textContent  = display.icon;
  document.getElementById('risk-badge-label').textContent = display.label;
  document.getElementById('risk-subtitle').textContent    = `${allSignals.length} signal${allSignals.length !== 1 ? 's' : ''} detected`;

  // Summary
  const summaryEl = document.getElementById('risk-summary');
  summaryEl.textContent = summary;
  summaryEl.className   = `risk-summary ${display.summaryClass}`;

  // Animate gauge
  animateGauge(score);

  // ── Signals ─────────────────────────────────────────────────
  const signalsList = document.getElementById('signals-list');
  const countBadge  = document.getElementById('signal-count-badge');
  signalsList.innerHTML = '';
  countBadge.textContent = `${allSignals.length} signal${allSignals.length !== 1 ? 's' : ''}`;

  if (allSignals.length === 0) {
    signalsList.innerHTML = `
      <div class="signal-item sev-low" style="border-left-color:var(--low)">
        <div class="si-icon">✅</div>
        <div class="si-body">
          <div class="si-name">No Suspicious Signals Detected</div>
          <div class="si-desc">This content passed all our checks. No major scam indicators were found.</div>
        </div>
        <span class="si-sev sev-low">LOW</span>
      </div>`;
  } else {
    // Sort: critical first, then high, medium, low
    const sevOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    const sorted = [...allSignals].sort((a, b) => (sevOrder[a.severity] || 4) - (sevOrder[b.severity] || 4));

    sorted.forEach((sig, i) => {
      const quotesHTML = sig.quotes && sig.quotes.length
        ? `<div class="si-quotes">${sig.quotes.map(q => `<span class="si-quote">${escHTML(q)}</span>`).join('')}</div>`
        : '';

      const el = document.createElement('div');
      el.className = `signal-item sev-${sig.severity}`;
      el.style.animationDelay = `${i * 70}ms`;
      el.innerHTML = `
        <div class="si-icon">${sig.icon}</div>
        <div class="si-body">
          <div class="si-name">${escHTML(sig.name)}</div>
          <div class="si-desc">${escHTML(sig.description)}</div>
          ${quotesHTML}
        </div>
        <span class="si-sev sev-${sig.severity}">${sig.severity.toUpperCase()}</span>
      `;
      signalsList.appendChild(el);
    });
  }

  // ── Action steps ─────────────────────────────────────────────
  const actionList = document.getElementById('action-list');
  actionList.innerHTML = actionSteps.map((step, i) => `
    <div class="action-step" style="animation-delay:${i * 55}ms">
      <div class="step-num">${i + 1}</div>
      <span>${escHTML(step)}</span>
    </div>
  `).join('');

  // ── Explanation ───────────────────────────────────────────────
  document.getElementById('explain-text').innerHTML = explanation;

  // ── Safe alternatives ─────────────────────────────────────────
  const safeList = document.getElementById('safe-list');
  safeList.innerHTML = safeAlternatives.map((alt, i) => `
    <div class="safe-item" style="animation-delay:${i * 55}ms">
      <span class="safe-icon">${alt.icon}</span>
      <span>${escHTML(alt.text)}</span>
    </div>
  `).join('');

  // Scroll to results
  setTimeout(() => {
    panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, 120);
}

// ================================================================
// GAUGE ANIMATION
// ================================================================
function animateGauge(score) {
  const arc       = document.getElementById('gauge-arc');
  const scoreText = document.getElementById('gauge-score-text');
  if (!arc || !scoreText) return;

  // Large-arc semicircle path (large-arc=1, sweep=1): arc goes from left (25,110)
  // clockwise the long way around through the top to right (175,110).
  // Arc length ≈ (3/4) × 2π × 80 ≈ 377 for 270° arc.
  // But our actual arc from (25,110) to (175,110) with large-arc=1 sweep=1
  // covers 270° → length = 1.5π × 80 ≈ 377
  const ARC_LENGTH = 377;
  const targetOffset = ARC_LENGTH - (ARC_LENGTH * score / 100);

  // Start from empty
  arc.style.transition = 'none';
  arc.setAttribute('stroke-dasharray', ARC_LENGTH);
  arc.setAttribute('stroke-dashoffset', ARC_LENGTH);
  scoreText.textContent = '0';

  // Force reflow so transition applies
  void arc.getBoundingClientRect();

  arc.style.transition = 'stroke-dashoffset 1.6s cubic-bezier(0.25,0.46,0.45,0.94)';
  arc.style.strokeDashoffset = targetOffset;

  // Animate number
  let current = 0;
  const steps = 60;
  const increment = score / steps;
  const interval = setInterval(() => {
    current = Math.min(current + increment, score);
    scoreText.textContent = Math.round(current);
    if (current >= score) clearInterval(interval);
  }, 1600 / steps);
}

// ================================================================
// LOADING STATE
// ================================================================
function showLoading() {
  // Reset all steps
  document.querySelectorAll('.lstep').forEach(s => s.classList.remove('active', 'done'));

  document.getElementById('loading-panel').style.display = 'block';
  document.getElementById('results-panel').style.display = 'none';

  document.getElementById('loading-panel').scrollIntoView({ behavior: 'smooth', block: 'center' });
}

function hideLoading() {
  document.getElementById('loading-panel').style.display = 'none';
}

function activateStep(id) {
  const el = document.getElementById(id);
  if (!el) return;
  el.classList.remove('done');
  el.classList.add('active');
}

function doneStep(id) {
  const el = document.getElementById(id);
  if (!el) return;
  el.classList.remove('active');
  el.classList.add('done');
}

function hideResults() {
  document.getElementById('results-panel').style.display  = 'none';
  document.getElementById('loading-panel').style.display  = 'none';
}

// ================================================================
// RESULT BUTTON HANDLERS
// ================================================================
function resetAnalysis() {
  hideResults();
  currentReport    = null;
  qrDecodedContent = null;

  // Clear inputs
  ['message-input', 'url-input', 'qr-manual-input', 'combined-message',
   'combined-url', 'combined-amount', 'combined-payee'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });

  // Reset char counter
  const counter = document.getElementById('msg-char-count');
  if (counter) counter.textContent = '0 / 3000';

  // Reset URL breakdown
  const breakdown = document.getElementById('url-breakdown');
  if (breakdown) breakdown.style.display = 'none';

  // Reset QR preview
  document.getElementById('qr-upload-zone').style.display    = 'block';
  document.getElementById('qr-preview-box').style.display    = 'none';
  document.getElementById('qr-manual-section').style.display = 'block';

  // Scroll to analyzer
  document.getElementById('analyzer').scrollIntoView({ behavior: 'smooth', block: 'start' });
  showToast('✅', 'Ready for a new analysis');
}

function copyReport() {
  if (!currentReport) { showToast('⚠️', 'No report to copy'); return; }

  const { score, display, allSignals } = currentReport;
  let text = `🛡️ ScamShield Analysis Report\n`;
  text += `Generated: ${new Date().toLocaleString('en-IN')}\n\n`;
  text += `Risk Level: ${display.label}\n`;
  text += `Risk Score: ${score} / 100\n\n`;
  text += `Triggered Signals (${allSignals.length}):\n`;
  allSignals.forEach(s => {
    text += `  • [${s.severity.toUpperCase()}] ${s.name}\n`;
    text += `    ${s.description}\n`;
    if (s.quotes && s.quotes.length) text += `    Evidence: ${s.quotes.join(' | ')}\n`;
    text += '\n';
  });
  text += `Analyzed by ScamShield — detect payment scams before you pay.\n`;
  text += `Report cybercrime: 1930 | cybercrime.gov.in`;

  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text)
      .then(() => showToast('📋', 'Report copied to clipboard!'))
      .catch(() => fallbackCopy(text));
  } else {
    fallbackCopy(text);
  }
}

function fallbackCopy(text) {
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.style.position = 'fixed';
  ta.style.opacity  = '0';
  document.body.appendChild(ta);
  ta.select();
  try {
    document.execCommand('copy');
    showToast('📋', 'Report copied!');
  } catch (e) {
    showToast('❌', 'Could not copy. Try manually selecting the content.');
  }
  document.body.removeChild(ta);
}

function reportScam() {
  showToast('🚨', 'Opening cybercrime.gov.in...');
  setTimeout(() => {
    window.open('https://cybercrime.gov.in', '_blank', 'noopener,noreferrer');
  }, 600);
}

// ================================================================
// UTILITIES
// ================================================================

/** HTML-escape a string. */
function escHTML(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/** Promise-based delay. */
function wait(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/** Remove duplicate signals by id, keeping the first occurrence. */
function deduplicateSignals(signals) {
  const seen = new Set();
  return signals.filter(s => {
    if (seen.has(s.id)) return false;
    seen.add(s.id);
    return true;
  });
}

/** Show toast notification. */
function showToast(icon, message) {
  const toast   = document.getElementById('toast');
  const iconEl  = document.getElementById('toast-icon');
  const msgEl   = document.getElementById('toast-msg');
  if (!toast || !iconEl || !msgEl) return;

  iconEl.textContent = icon;
  msgEl.textContent  = message;
  toast.classList.add('show');

  clearTimeout(toast._hideTimer);
  toast._hideTimer = setTimeout(() => toast.classList.remove('show'), 3200);
}
