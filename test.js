// ScamShield Logic Verification Test
// Run: node test.js
'use strict';

const fs   = require('fs');
const path = require('path');

// ── Load analyzers and risk-engine by concatenating + wrapping them ──
const analyzersCode  = fs.readFileSync(path.join(__dirname, 'js', 'analyzers.js'),  'utf8');
const riskEngineCode = fs.readFileSync(path.join(__dirname, 'js', 'risk-engine.js'), 'utf8');

// Strip 'use strict' directives and eval in function scope to expose globals
const fullCode = `
${analyzersCode.replace(/['"']use strict['"'];?/g, '')}
${riskEngineCode.replace(/['"']use strict['"'];?/g, '')}
`;

// Use Function constructor to execute in global scope of this module
// (safer than eval for getting globals)
const globals = {};
const fn = new Function(
  'exports_out',
  `${fullCode}
  exports_out.TextAnalyzer       = TextAnalyzer;
  exports_out.URLAnalyzer        = URLAnalyzer;
  exports_out.QRAnalyzer         = QRAnalyzer;
  exports_out.BehaviouralAnalyzer= BehaviouralAnalyzer;
  exports_out.RiskEngine         = RiskEngine;
  `
);
fn(globals);

const { TextAnalyzer, URLAnalyzer, QRAnalyzer, BehaviouralAnalyzer, RiskEngine } = globals;

// ── Test helpers ──────────────────────────────────────────────────────
let passed = 0, failed = 0;

function assert(label, condition, info = '') {
  if (condition) {
    console.log(`  \x1b[32m✓\x1b[0m ${label}${info ? ' — ' + info : ''}`);
    passed++;
  } else {
    console.log(`  \x1b[31m✗\x1b[0m ${label}${info ? ' — ' + info : ''}`);
    failed++;
  }
}

function riskLabel(score) {
  if (score >= 75) return '\x1b[31mCRITICAL\x1b[0m';
  if (score >= 50) return '\x1b[33mHIGH\x1b[0m';
  if (score >= 25) return '\x1b[93mMEDIUM\x1b[0m';
  return '\x1b[32mLOW\x1b[0m';
}

function printSignals(signals) {
  signals.forEach(s => console.log(`  \x1b[90m  → [${s.severity.toUpperCase()}] ${s.name} +${s.score_contribution}pts\x1b[0m`));
}

console.log('\n\x1b[36m══════════════════════════════════════════════════════════\x1b[0m');
console.log('\x1b[36m   ScamShield — Full Engine Verification Test Suite\x1b[0m');
console.log('\x1b[36m══════════════════════════════════════════════════════════\x1b[0m\n');

// ══ TEST 1: Fake Amazon Refund ═════════════════════════════════════
console.log('\x1b[1mTEST 1 — Fake Amazon Refund Message\x1b[0m');
const msg1 = 'URGENT: Your Amazon account has been compromised and your refund of 2499 is pending. Click here immediately. Our executive will call you — please share the OTP you receive to verify your identity. Act now or your refund will be cancelled within 24 hours.';
const r1 = TextAnalyzer.analyze(msg1);
console.log(`  Score: \x1b[1m${r1.score}/100\x1b[0m  Risk: ${riskLabel(r1.score)}`);
printSignals(r1.signals);
assert('Score >= 75 (CRITICAL)',              r1.score >= 75, `score=${r1.score}`);
assert('Detects urgency signal',             r1.signals.some(s => s.id === 'urgency'));
assert('Detects OTP request signal',         r1.signals.some(s => s.id === 'otpRequest'));
assert('Detects Amazon impersonation',       r1.signals.some(s => s.id === 'impersonation'));

// ══ TEST 2: HDFC Bank Impersonation ═══════════════════════════════
console.log('\n\x1b[1mTEST 2 — HDFC Bank Impersonation SMS\x1b[0m');
const msg2 = 'Dear Customer, Your HDFC Bank account has been suspended. Call our HDFC helpline immediately. Our executive will ask for your OTP to verify your identity. Action required within 2 hours or your account will be permanently blocked.';
const r2 = TextAnalyzer.analyze(msg2);
console.log(`  Score: \x1b[1m${r2.score}/100\x1b[0m  Risk: ${riskLabel(r2.score)}`);
printSignals(r2.signals);
assert('Score >= 75 (CRITICAL)',             r2.score >= 75, `score=${r2.score}`);
assert('Detects HDFC impersonation',         r2.signals.some(s => s.id === 'impersonation'));
assert('Detects OTP request',                r2.signals.some(s => s.id === 'otpRequest'));
assert('Detects urgency',                    r2.signals.some(s => s.id === 'urgency'));

// ══ TEST 3: Lottery Prize / Advance Fee ═══════════════════════════
console.log('\n\x1b[1mTEST 3 — Lottery Prize / Advance Fee Scam\x1b[0m');
const msg3 = 'Congratulations! You have been selected as the Lucky Winner of Rs 10,00,000. To claim your prize, pay a small processing fee of Rs 499. Registration amount must be sent before we release your lottery winnings.';
const r3 = TextAnalyzer.analyze(msg3);
console.log(`  Score: \x1b[1m${r3.score}/100\x1b[0m  Risk: ${riskLabel(r3.score)}`);
printSignals(r3.signals);
assert('Score >= 75 (CRITICAL)',             r3.score >= 75, `score=${r3.score}`);
assert('Detects refund/prize bait',          r3.signals.some(s => s.id === 'refundBait'));
assert('Detects advance fee',                r3.signals.some(s => s.id === 'advanceFee'));

// ══ TEST 4: Phishing URL ══════════════════════════════════════════
console.log('\n\x1b[1mTEST 4 — Phishing URL (HTTP + .xyz + suspicious path)\x1b[0m');
const url1 = 'http://hdfc-bank-secure-update.xyz/login?verify=customer&id=84729';
const r4 = URLAnalyzer.analyze(url1);
console.log(`  URL: ${url1}`);
console.log(`  Score: \x1b[1m${r4.score}/100\x1b[0m  Risk: ${riskLabel(r4.score)}`);
printSignals(r4.signals);
assert('Score >= 75 (CRITICAL)',             r4.score >= 75, `score=${r4.score}`);
assert('Detects no HTTPS',                   r4.signals.some(s => s.id === 'no_https'));
assert('Detects suspicious TLD (.xyz)',      r4.signals.some(s => s.id === 'suspicious_tld'));
assert('Detects suspicious path',            r4.signals.some(s => s.id === 'suspicious_path'));

// ══ TEST 5: IP-based URL ══════════════════════════════════════════
console.log('\n\x1b[1mTEST 5 — Raw IP Address URL\x1b[0m');
const url2 = 'http://192.168.1.105/payment/checkout?order=12345';
const r5 = URLAnalyzer.analyze(url2);
console.log(`  Score: \x1b[1m${r5.score}/100\x1b[0m  Risk: ${riskLabel(r5.score)}`);
printSignals(r5.signals);
assert('Score >= 75 (CRITICAL)',             r5.score >= 75, `score=${r5.score}`);
assert('Detects IP URL',                     r5.signals.some(s => s.id === 'ip_url'));

// ══ TEST 6: Brand in subdomain URL ════════════════════════════════
console.log('\n\x1b[1mTEST 6 — Brand Name in Subdomain\x1b[0m');
const url3 = 'https://amazon.refund-claim.online/verify?user=customer123';
const r6 = URLAnalyzer.analyze(url3);
console.log(`  URL: ${url3}`);
console.log(`  Score: \x1b[1m${r6.score}/100\x1b[0m  Risk: ${riskLabel(r6.score)}`);
printSignals(r6.signals);
assert('Score >= 50 (HIGH/CRITICAL)',        r6.score >= 50, `score=${r6.score}`);

// ══ TEST 7: Legitimate URL ════════════════════════════════════════
console.log('\n\x1b[1mTEST 7 — Legitimate URL (should be LOW)\x1b[0m');
const url4 = 'https://www.amazon.in/gp/css/order-history';
const r7 = URLAnalyzer.analyze(url4);
console.log(`  Score: \x1b[1m${r7.score}/100\x1b[0m  Risk: ${riskLabel(r7.score)}`);
if (r7.signals.length === 0) console.log('  \x1b[32m  → No suspicious signals detected\x1b[0m');
else printSignals(r7.signals);
assert('Score <= 10 (clean / LOW)',          r7.score <= 10, `score=${r7.score}`);
assert('Zero signals',                       r7.signals.length === 0, `signals=${r7.signals.length}`);

// ══ TEST 8: QR Code UPI Scam ══════════════════════════════════════
console.log('\n\x1b[1mTEST 8 — UPI QR Code Scam\x1b[0m');
const qrContent = 'upi://pay?pa=scammer.refund@ybl&pn=Amazon Refund Dept&am=499&tn=Processing Fee Refund&cu=INR';
const r8 = QRAnalyzer.analyze(qrContent);
console.log(`  QR: ${qrContent.substring(0, 75)}`);
console.log(`  Score: \x1b[1m${r8.score}/100\x1b[0m  Risk: ${riskLabel(r8.score)}`);
printSignals(r8.signals);
assert('Score >= 50 (HIGH/CRITICAL)',        r8.score >= 50, `score=${r8.score}`);
assert('Detects UPI payment direction',      r8.signals.some(s => s.id === 'qr_is_payment'));
assert('Detects pre-set amount',             r8.signals.some(s => s.id === 'qr_fixed_amount'));
assert('Detects suspicious payee name',      r8.signals.some(s => s.id === 'qr_suspicious_payee'));

// ══ TEST 9: Behavioural context analysis ══════════════════════════
console.log('\n\x1b[1mTEST 9 — Behavioural Analysis (Advance Fee Context)\x1b[0m');
const r9 = BehaviouralAnalyzer.analyze({
  amount: '499',
  payeeName: 'Amazon Refund Helpline',
  purpose: 'Processing Fee to claim your refund',
});
console.log(`  Score: \x1b[1m${r9.score}/100\x1b[0m  Risk: ${riskLabel(r9.score)}`);
printSignals(r9.signals);
assert('Score >= 50 (HIGH/CRITICAL)',        r9.score >= 50, `score=${r9.score}`);
assert('Detects advance fee pattern',        r9.signals.some(s => s.id === 'ctx_advance_fee'));
assert('Detects brand impersonation',        r9.signals.some(s => s.id === 'ctx_payee_impersonation'));

// ══ TEST 10: Risk engine fusion + full report ══════════════════════
console.log('\n\x1b[1mTEST 10 — Risk Engine Fusion & XAI Report\x1b[0m');
const allSignals = [...r1.signals, ...r4.signals];
const fusedScore = RiskEngine.computeFinalScore([
  { score: r1.score, weight: 3 },
  { score: r4.score, weight: 3 },
]);
const report = RiskEngine.generateReport(allSignals, fusedScore);
console.log(`  Msg score: ${r1.score}, URL score: ${r4.score} → Fused: ${fusedScore}/100  Risk: ${riskLabel(fusedScore)}`);
console.log(`  Signals: ${report.allSignals.length}, Action steps: ${report.actionSteps.length}, Alternatives: ${report.safeAlternatives.length}`);
assert('Fused score >= 75 (CRITICAL)',       fusedScore >= 75, `fused=${fusedScore}`);
assert('Level is CRITICAL',                  report.level === 'critical');
assert('Summary string > 20 chars',          typeof report.summary === 'string' && report.summary.length > 20);
assert('Action steps >= 4',                  report.actionSteps.length >= 4);
assert('Safe alternatives >= 3',             report.safeAlternatives.length >= 3);
assert('Explanation string > 20 chars',      report.explanation.length > 20);

// ══ TEST 11: RBI OTP Phishing ═════════════════════════════════════
console.log('\n\x1b[1mTEST 11 — RBI OTP Phishing Message\x1b[0m');
const msg4 = 'RBI Official Notice: Your bank account shows an unauthorized transaction of 24999. To reverse this, our senior executive needs you to share the OTP sent to your mobile. Call 1800-XXX-XXXX and provide the OTP to recover your funds. Expires in 15 minutes.';
const r11 = TextAnalyzer.analyze(msg4);
console.log(`  Score: \x1b[1m${r11.score}/100\x1b[0m  Risk: ${riskLabel(r11.score)}`);
printSignals(r11.signals);
assert('Score >= 75 (CRITICAL)',             r11.score >= 75, `score=${r11.score}`);
assert('Detects RBI impersonation',          r11.signals.some(s => s.id === 'impersonation'));
assert('Detects OTP request',                r11.signals.some(s => s.id === 'otpRequest'));
assert('Detects urgency',                    r11.signals.some(s => s.id === 'urgency'));

// ══ TEST 12: Legitimate, safe message ════════════════════════════
console.log('\n\x1b[1mTEST 12 — Legitimate Message (should be LOW)\x1b[0m');
const msg5 = 'Your order #OD123456789 has been shipped. Expected delivery by tomorrow between 10 AM and 2 PM. Track your order on the app.';
const r12 = TextAnalyzer.analyze(msg5);
console.log(`  Score: \x1b[1m${r12.score}/100\x1b[0m  Risk: ${riskLabel(r12.score)}`);
if (r12.signals.length === 0) console.log('  \x1b[32m  → No suspicious signals — SAFE\x1b[0m');
else printSignals(r12.signals);
assert('Score = 0 (LOW/safe)',               r12.score === 0, `score=${r12.score}`);
assert('Zero signals',                       r12.signals.length === 0);

// ══ SUMMARY ═══════════════════════════════════════════════════════
const total = passed + failed;
console.log('\n\x1b[36m══════════════════════════════════════════════════════════\x1b[0m');
if (failed === 0) {
  console.log(`\x1b[32m  ✅  ALL ${total} ASSERTIONS PASSED — ScamShield Engine Verified\x1b[0m`);
} else {
  console.log(`\x1b[31m  ❌  ${failed} / ${total} ASSERTIONS FAILED\x1b[0m`);
  process.exitCode = 1;
}
console.log('\x1b[36m══════════════════════════════════════════════════════════\x1b[0m\n');
