/* ================================================================
   risk-engine.js — ScamShield Risk Scoring & Report Generator
   ================================================================ */

'use strict';

const RiskEngine = {

  // ── Score fusion ────────────────────────────────────────────
  /**
   * Fuse multiple module scores into a single final score.
   * Strategy: 60% max-signal (any critical module drives overall risk)
   *           40% weighted average (rewards breadth of signals)
   * @param {Array<{score:number, weight?:number}>} results
   * @returns {number} 0-100
   */
  computeFinalScore(results) {
    if (!results || results.length === 0) return 0;
    const valid = results.filter(r => typeof r.score === 'number' && r.score >= 0);
    if (valid.length === 0) return 0;

    const maxScore = Math.max(...valid.map(r => r.score));
    const totalWeight = valid.reduce((s, r) => s + (r.weight || 1), 0);
    const weightedAvg = valid.reduce((s, r) => s + r.score * (r.weight || 1), 0) / totalWeight;

    return Math.min(100, Math.round(0.6 * maxScore + 0.4 * weightedAvg));
  },

  // ── Risk level ──────────────────────────────────────────────
  /**
   * @param {number} score
   * @returns {'low'|'medium'|'high'|'critical'}
   */
  getRiskLevel(score) {
    if (score >= 75) return 'critical';
    if (score >= 50) return 'high';
    if (score >= 25) return 'medium';
    return 'low';
  },

  /** All display metadata keyed by risk level. */
  riskDisplay: {
    low: {
      icon: '✅',
      label: 'LOW RISK',
      badgeClass: 'b-low',
      cardClass: 'r-low',
      summaryClass: 's-low',
      gaugeColor: '#00e676',
    },
    medium: {
      icon: '⚠️',
      label: 'MEDIUM RISK',
      badgeClass: 'b-medium',
      cardClass: 'r-medium',
      summaryClass: 's-medium',
      gaugeColor: '#ffc107',
    },
    high: {
      icon: '🟠',
      label: 'HIGH RISK',
      badgeClass: 'b-high',
      cardClass: 'r-high',
      summaryClass: 's-high',
      gaugeColor: '#ff6d00',
    },
    critical: {
      icon: '🔴',
      label: 'CRITICAL — LIKELY SCAM',
      badgeClass: 'b-critical',
      cardClass: 'r-critical',
      summaryClass: 's-critical',
      gaugeColor: '#ff1744',
    },
  },

  // ── Risk summary text ───────────────────────────────────────
  buildSummary(level, score, signalCount) {
    const summaries = {
      low: `Risk score: ${score}/100. No major red flags were detected (${signalCount} minor signal${signalCount !== 1 ? 's' : ''}). This content appears relatively safe, but always verify through official channels before making any payment.`,
      medium: `Risk score: ${score}/100. Some suspicious patterns detected (${signalCount} signal${signalCount !== 1 ? 's' : ''}). Proceed with caution — independently verify this request before making any payment.`,
      high: `Risk score: ${score}/100. Multiple high-severity signals detected (${signalCount} signals). This content shows strong characteristics of a payment scam. Do NOT proceed without thorough independent verification.`,
      critical: `⚠️ CRITICAL ALERT — Risk score: ${score}/100. Overwhelming evidence of fraud (${signalCount} signals triggered). This is almost certainly a scam. Do NOT make any payment or share any information.`,
    };
    return summaries[level];
  },

  // ── Action steps ────────────────────────────────────────────
  buildActionSteps(signals, level) {
    const steps = [];
    const ids = new Set(signals.map(s => s.id));

    steps.push('Do NOT make any payment or share any personal information until you have verified this request through official channels independently.');

    if (ids.has('otpRequest')) {
      steps.push('Never share your OTP, PIN, or password with anyone — including someone claiming to be from your bank. Banks never ask for OTPs.');
    }

    if (ids.has('impersonation') || ids.has('ctx_payee_impersonation') || ids.has('lookalike_domain') || ids.has('brand_in_subdomain') || ids.has('qr_suspicious_payee')) {
      steps.push('Do not call any number provided in this message. Find the official contact number on the company\'s official website or the back of your bank card.');
    }

    if (ids.has('refundBait') || ids.has('advanceFee') || ids.has('ctx_advance_fee')) {
      steps.push('No legitimate refund, prize, or government benefit requires you to pay a fee upfront. This is called "advance fee fraud" — once you pay, the money is gone and the promise is never fulfilled.');
    }

    if (ids.has('qr_is_payment') || ids.has('qr_fixed_amount') || ids.has('qrTrick')) {
      steps.push('QR codes in UPI ALWAYS initiate a payment FROM you. There is no such thing as "scan to receive money." If someone tells you to scan a QR to get your refund, it is 100% a scam.');
    }

    if (ids.has('lookalike_domain') || ids.has('ip_url') || ids.has('suspicious_tld') || ids.has('brand_in_subdomain')) {
      steps.push('Do not click the link. Open your browser and manually type the official website address to navigate directly.');
    }

    if (ids.has('remoteAccess')) {
      steps.push('Never install AnyDesk, TeamViewer, or any remote access tool at a stranger\'s request. This gives them full control of your device and access to all your accounts and passwords.');
    }

    if (level === 'critical' || level === 'high') {
      steps.push('Report this scam immediately: National Cyber Crime Helpline 1930 or visit cybercrime.gov.in to file a complaint.');
      steps.push('Alert your bank\'s fraud team if you believe your account details may have been compromised.');
    }

    steps.push('When in doubt, stop and call the official helpline. A legitimate organisation will not pressure you. A few minutes of caution can save you your entire savings.');

    return steps;
  },

  // ── Explanation ─────────────────────────────────────────────
  buildExplanation(signals, level) {
    if (signals.length === 0) {
      return 'No significant suspicious signals were detected. This content appears to be relatively safe based on the patterns we checked. However, always exercise caution when making digital payments.';
    }

    const bySev = {
      critical: signals.filter(s => s.severity === 'critical'),
      high:     signals.filter(s => s.severity === 'high'),
      medium:   signals.filter(s => s.severity === 'medium'),
      low:      signals.filter(s => s.severity === 'low'),
    };

    let html = '';

    if (level === 'critical') {
      html += '<strong>Why this is almost certainly a scam:</strong><br><br>';
    } else if (level === 'high') {
      html += '<strong>Why this content is highly suspicious:</strong><br><br>';
    } else {
      html += '<strong>What triggered our warnings:</strong><br><br>';
    }

    if (bySev.critical.length > 0) {
      html += `The most severe red flag${bySev.critical.length > 1 ? 's' : ''}: `;
      html += bySev.critical.map(s => `<strong>${s.name}</strong> — ${s.description}`).join('; ');
      html += '.<br><br>';
    }

    if (bySev.high.length > 0) {
      html += `High-severity signals also detected: `;
      html += bySev.high.map(s => `<strong>${s.name}</strong>`).join(', ');
      html += '.<br><br>';
    }

    // Identify scam type(s)
    const ids = new Set(signals.map(s => s.id));
    const scamTypes = [];
    if (ids.has('impersonation') || ids.has('ctx_payee_impersonation') || ids.has('lookalike_domain') || ids.has('brand_in_subdomain')) {
      scamTypes.push('Social engineering / Brand impersonation fraud');
    }
    if (ids.has('refundBait') || ids.has('advanceFee') || ids.has('ctx_advance_fee')) {
      scamTypes.push('Advance fee / Fake refund fraud');
    }
    if (ids.has('otpRequest')) {
      scamTypes.push('OTP phishing / Credential theft');
    }
    if (['ip_url', 'suspicious_tld', 'lookalike_domain', 'homoglyphs', 'brand_in_subdomain'].some(id => ids.has(id))) {
      scamTypes.push('Phishing via fake website');
    }
    if (['qr_is_payment', 'qr_fixed_amount', 'qr_suspicious_payee', 'qrTrick'].some(id => ids.has(id))) {
      scamTypes.push('UPI QR code payment fraud');
    }
    if (ids.has('remoteAccess')) {
      scamTypes.push('Remote access / Tech support scam');
    }

    if (scamTypes.length > 0) {
      html += `The combined signal pattern is characteristic of: <strong>${scamTypes.join('</strong> and <strong>')}</strong>.`;
    }

    return html;
  },

  // ── Safe alternatives ────────────────────────────────────────
  buildSafeAlternatives(signals) {
    const alts = [];
    const ids = new Set(signals.map(s => s.id));

    alts.push({
      icon: '🌐',
      text: 'Always navigate directly to official websites by typing the exact URL in your browser (e.g., amazon.in, hdfcbank.com). Never follow links from messages.',
    });

    if (ids.has('impersonation') || ids.has('ctx_payee_impersonation')) {
      alts.push({
        icon: '📞',
        text: 'To reach customer care, call the number on the back of your bank card or printed on official documents. Never use a number provided in a message.',
      });
    }

    if (ids.has('lookalike_domain') || ids.has('ip_url') || ids.has('suspicious_tld')) {
      alts.push({
        icon: '🔒',
        text: 'Before entering any information on a website, verify: (1) it starts with "https://", (2) the domain name is spelled exactly correctly, and (3) there is a padlock icon in your browser.',
      });
    }

    if (ids.has('qr_is_payment') || ids.has('qr_fixed_amount') || ids.has('qrTrick')) {
      alts.push({
        icon: '📷',
        text: 'Only scan QR codes from physical, trusted locations (shops, ATMs, restaurant menus). Never scan QR codes received via WhatsApp, SMS, or email from unknown parties.',
      });
    }

    if (ids.has('remoteAccess')) {
      alts.push({
        icon: '🖥️',
        text: 'Never install AnyDesk, TeamViewer, or similar tools at a stranger\'s request. Legitimate bank and company support will never need to access your screen.',
      });
    }

    alts.push({
      icon: '🚨',
      text: 'Report scams: National Cyber Crime Helpline 1930 | cybercrime.gov.in | Your bank\'s 24/7 fraud hotline (number on back of your card).',
    });

    alts.push({
      icon: '💡',
      text: 'The golden rule: No legitimate organisation will ever ask for your OTP, ask you to pay to receive a refund, or ask for remote access to your device.',
    });

    return alts;
  },

  // ── Full report ─────────────────────────────────────────────
  /**
   * Generate a complete analysis report.
   * @param {Array} allSignals - All signals from all analyzers
   * @param {number} finalScore - The fused 0-100 risk score
   * @returns {object}
   */
  generateReport(allSignals, finalScore) {
    const level = this.getRiskLevel(finalScore);
    const display = this.riskDisplay[level];
    const summary = this.buildSummary(level, finalScore, allSignals.length);
    const actionSteps = this.buildActionSteps(allSignals, level);
    const explanation = this.buildExplanation(allSignals, level);
    const safeAlternatives = this.buildSafeAlternatives(allSignals);

    return {
      score: finalScore,
      level,
      display,
      allSignals,
      summary,
      actionSteps,
      explanation,
      safeAlternatives,
    };
  },
};
