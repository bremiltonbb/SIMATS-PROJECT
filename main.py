# ScamShield Backend API
# Requirements: pip install fastapi uvicorn
# Optional:     pip install tldextract   (for enhanced URL analysis)
# Run:          uvicorn main:app --reload --port 8000

import pathlib
import re
from typing import Optional, List
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

app = FastAPI(
    title="ScamShield API",
    description="Privacy-conscious payment scam detection REST API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ================================================================
# MODELS
# ================================================================

class AnalysisRequest(BaseModel):
    text: Optional[str] = None
    url: Optional[str] = None
    qr_content: Optional[str] = None
    amount: Optional[float] = None
    payee_name: Optional[str] = None

class Signal(BaseModel):
    id: str
    name: str
    icon: str
    severity: str
    description: str
    quotes: List[str] = []
    score_contribution: int
    category: str

class AnalysisResponse(BaseModel):
    score: int
    risk_level: str
    signals: List[Signal]
    signal_count: int
    summary: str

# ================================================================
# TEXT ANALYZER
# ================================================================

TEXT_PATTERNS = {
    "urgency": {
        "name": "Urgency / Fear Language",
        "icon": "⏰",
        "severity": "high",
        "weight": 25,
        "description": "Uses urgency and fear tactics to prevent calm thinking.",
        "patterns": [
            r"\b(urgent|immediately|right\s*now|act\s*now|hurry|asap|emergency|critical)\b",
            r"\b(last\s*chance|final\s*notice|limited\s*time|expires?\s*(soon|today|now))\b",
            r"\b(your\s*account\s*(will\s*be\s*|has\s*been\s*)?(blocked|suspended|closed|disabled|frozen))\b",
            r"\b(action\s*required|response\s*required|verify\s*(now|immediately))\b",
            r"\b(within\s*\d+\s*(hour|minute|day|hr|min)s?)\b",
        ],
    },
    "impersonation": {
        "name": "Brand / Authority Impersonation",
        "icon": "🎭",
        "severity": "critical",
        "weight": 35,
        "description": "Claims to be from a trusted organisation.",
        "patterns": [
            r"\b(amazon|flipkart|paytm|phonepe|googlepay|gpay)\s*(customer\s*care|support|helpline|refund|team|official)\b",
            r"\b(hdfc|sbi|icici|axis|kotak|yes\s*bank)\s*(bank)?\s*(helpline|support|care|team|executive)\b",
            r"\b(rbi|reserve\s*bank|income\s*tax|government|ministry)\s*(of\s*india)?\s*(official|team|notice|mandate)\b",
            r"\b(microsoft|apple|google|facebook)\s*(support|care|helpline|team|official)\b",
        ],
    },
    "otp_request": {
        "name": "OTP / Credential Request",
        "icon": "🔐",
        "severity": "critical",
        "weight": 42,
        "description": "No legitimate service ever asks for OTP or password.",
        "patterns": [
            r"\b(share|send|provide|tell|give|enter|submit)\s*(your\s*)?(otp|one[\s-]time\s*password|pin|password|cvv)\b",
            r"\b(otp|one[\s-]time\s*(password|pin))\s*(to\s*(verify|confirm|validate|authenticate))\b",
            r"\b(verify\s*(your)?\s*(account|identity)\s*(by\s*)?(sharing|entering|sending)\s*(the\s*)?(otp|pin|code))\b",
        ],
    },
    "refund_bait": {
        "name": "Fake Refund / Prize Bait",
        "icon": "💰",
        "severity": "high",
        "weight": 30,
        "description": "Promise of money to extract credentials or fees.",
        "patterns": [
            r"\b(refund|cashback|reward|bonus|prize)\s*(of\s*)?₹?\s*\d[\d,]*\s*(is\s*)?(ready|processed|approved|pending)\b",
            r"\b(you\s*('ve|have|are)\s*(won|qualified|selected|eligible|been\s*chosen))\b",
            r"\b(lottery|lucky\s*(draw|winner)|contest\s*winner|cash\s*prize)\b",
            r"\b(claim\s*your\s*(prize|reward|refund|money|cashback))\b",
        ],
    },
    "advance_fee": {
        "name": "Advance Fee / Processing Fee Scam",
        "icon": "💳",
        "severity": "critical",
        "weight": 45,
        "description": "Paying to receive money is classic advance-fee fraud.",
        "patterns": [
            r"\b(pay|transfer|send)\s*(₹?\s*\d[\d,]*)\s*(to\s*)?(receive|get|claim|unlock|process)\b",
            r"\b(small\s*fee|processing\s*(fee|charge)|handling\s*fee|activation\s*fee|registration\s*amount)\b",
            r"\b(advance\s*(payment|fee|amount)|security\s*deposit\s*(to\s*receive))\b",
        ],
    },
    "remote_access": {
        "name": "Remote Access / Suspicious Call",
        "icon": "📞",
        "severity": "high",
        "weight": 28,
        "description": "Granting remote access lets scammers steal credentials live.",
        "patterns": [
            r"\b(call\s*(us|our|this)\s*(helpline|number|executive|customer\s*care))\b",
            r"\b(download|install)\s*(anydesk|teamviewer|quicksupport|rustdesk|remote\s*(desktop|access))\b",
            r"\b(remote\s*(access|desktop|support)\s*(software|app|tool))\b",
        ],
    },
}


def analyze_text(text: str) -> dict:
    if not text or len(text.strip()) < 3:
        return {"score": 0, "signals": []}

    signals = []
    total_score = 0

    for key, cfg in TEXT_PATTERNS.items():
        matches = []
        for pattern in cfg["patterns"]:
            found = re.findall(pattern, text, re.IGNORECASE)
            if found:
                for f in found[:2]:
                    matches.append(f if isinstance(f, str) else (f[0] if f else ''))

        if matches:
            confidence = min(1.0, 0.5 + len(matches) * 0.25)
            contribution = round(cfg["weight"] * confidence)
            total_score += contribution

            signals.append({
                "id": key,
                "name": cfg["name"],
                "icon": cfg["icon"],
                "severity": cfg["severity"],
                "description": cfg["description"],
                "quotes": list(set(m.strip() for m in matches if m.strip()))[:2],
                "score_contribution": contribution,
                "category": "text",
            })

    return {"score": min(100, total_score), "signals": signals}


# ================================================================
# URL ANALYZER
# ================================================================

KNOWN_BRANDS = [
    'amazon', 'flipkart', 'paytm', 'phonepe', 'googlepay', 'bhim',
    'hdfc', 'sbi', 'icici', 'axis', 'kotak', 'rbi', 'microsoft',
    'google', 'apple', 'facebook', 'netflix', 'zomato', 'swiggy',
    'airtel', 'jio', 'vodafone', 'myntra', 'razorpay', 'indiapost',
]

SUSPICIOUS_TLDS = [
    '.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.click',
    '.link', '.online', '.site', '.club', '.buzz', '.bid', '.win',
    '.loan', '.date', '.download', '.stream', '.party',
]

URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
    'is.gd', 'tiny.cc', 'rebrand.ly', 'shorturl.at', 'cutt.ly', 'rb.gy',
]


def levenshtein(a: str, b: str) -> int:
    a, b = a.lower(), b.lower()
    dp = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        dp[i][0] = i
    for j in range(len(b) + 1):
        dp[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            dp[i][j] = (dp[i - 1][j - 1] if a[i - 1] == b[j - 1]
                        else 1 + min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]))
    return dp[len(a)][len(b)]


def analyze_url(raw_url: str) -> dict:
    if not raw_url or len(raw_url.strip()) < 3:
        return {"score": 0, "signals": []}

    signals = []
    total_score = 0
    url = raw_url.strip()
    if not re.match(r'^https?://', url, re.IGNORECASE):
        url = 'https://' + url

    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        hostname = (parsed.hostname or '').lower()
        pathname = parsed.path or ''
        query    = parsed.query or ''
        scheme   = parsed.scheme

        # Try tldextract for better domain parsing
        try:
            import tldextract
            ext = tldextract.extract(url)
            domain_name = ext.domain.lower()
            subdomain   = ext.subdomain.lower()
            suffix      = ext.suffix
        except ImportError:
            parts       = hostname.split('.')
            domain_name = parts[-2].lower() if len(parts) >= 2 else hostname
            subdomain   = '.'.join(parts[:-2]).lower() if len(parts) > 2 else ''
            suffix      = parts[-1] if len(parts) >= 1 else ''

        # 1. IP-based URL
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname):
            signals.append({
                "id": "ip_url",
                "name": "Raw IP Address Used as URL",
                "icon": "🌐",
                "severity": "critical",
                "description": "Legitimate payment portals always use domain names, never raw IP addresses.",
                "quotes": [hostname],
                "score_contribution": 45,
                "category": "url",
            })
            total_score += 45

        # 2. No HTTPS
        if scheme != 'https':
            signals.append({
                "id": "no_https",
                "name": "Insecure Connection (HTTP)",
                "icon": "🔓",
                "severity": "high",
                "description": "All legitimate payment pages enforce HTTPS.",
                "quotes": [f"{scheme}://{hostname}"],
                "score_contribution": 32,
                "category": "url",
            })
            total_score += 32

        # 3. Suspicious TLD
        for tld in SUSPICIOUS_TLDS:
            if hostname.endswith(tld):
                signals.append({
                    "id": "suspicious_tld",
                    "name": "High-Risk Top-Level Domain",
                    "icon": "🏴",
                    "severity": "high",
                    "description": f'The TLD "{tld}" is predominantly used in phishing sites.',
                    "quotes": [hostname],
                    "score_contribution": 35,
                    "category": "url",
                })
                total_score += 35
                break

        # 4. URL Shortener
        for s in URL_SHORTENERS:
            if hostname == s or hostname.endswith('.' + s):
                signals.append({
                    "id": "url_shortener",
                    "name": "URL Shortener / Redirect Used",
                    "icon": "🔀",
                    "severity": "medium",
                    "description": "Shortened URLs hide the real destination.",
                    "quotes": [raw_url[:55]],
                    "score_contribution": 25,
                    "category": "url",
                })
                total_score += 25
                break

        # 5. Lookalike domain
        for brand in KNOWN_BRANDS:
            if brand == domain_name:
                continue
            dist = levenshtein(domain_name, brand)
            max_len = max(len(domain_name), len(brand))
            if max_len == 0:
                continue
            similarity = 1 - dist / max_len
            if similarity >= 0.6 and similarity < 1 and dist <= 3:
                signals.append({
                    "id": "lookalike_domain",
                    "name": "Lookalike / Impersonation Domain",
                    "icon": "🎭",
                    "severity": "critical",
                    "description": f'Domain "{domain_name}.{suffix}" mimics "{brand}" ({round(similarity*100)}% similar, dist={dist}).',
                    "quotes": [f"{domain_name}.{suffix}", f"Mimics: {brand}"],
                    "score_contribution": 52,
                    "category": "url",
                })
                total_score += 52
                break

        # 6. Brand in subdomain
        if subdomain:
            for brand in KNOWN_BRANDS:
                if brand in subdomain and brand not in domain_name:
                    signals.append({
                        "id": "brand_in_subdomain",
                        "name": "Brand Name Used Deceptively in Subdomain",
                        "icon": "🎭",
                        "severity": "critical",
                        "description": f'"{brand}" in subdomain is deceptive. Real domain: "{domain_name}.{suffix}".',
                        "quotes": [hostname],
                        "score_contribution": 50,
                        "category": "url",
                    })
                    total_score += 50
                    break

        # 7. Suspicious path keywords
        suspicious_kw = ['refund', 'claim', 'prize', 'reward', 'verify', 'otp', 'kyc', 'winner']
        path_query = (pathname + query).lower()
        found_kw = [kw for kw in suspicious_kw if kw in path_query]
        if found_kw:
            signals.append({
                "id": "suspicious_path",
                "name": "Suspicious Keywords in URL Path",
                "icon": "📍",
                "severity": "medium",
                "description": f'URL path contains: "{", ".join(found_kw)}".',
                "quotes": [pathname[:70]],
                "score_contribution": 20,
                "category": "url",
            })
            total_score += 20

    except Exception as e:
        signals.append({
            "id": "parse_error",
            "name": "URL Parse Error",
            "icon": "⚠️",
            "severity": "medium",
            "description": f"Could not fully analyze this URL.",
            "quotes": [raw_url[:60]],
            "score_contribution": 15,
            "category": "url",
        })
        total_score += 15

    return {"score": min(100, total_score), "signals": signals}


# ================================================================
# RISK ENGINE
# ================================================================

def compute_final_score(results: list) -> int:
    if not results:
        return 0
    valid = [r for r in results if isinstance(r.get('score'), (int, float))]
    if not valid:
        return 0
    max_score = max(r['score'] for r in valid)
    total_w   = sum(r.get('weight', 1) for r in valid)
    avg_score = sum(r['score'] * r.get('weight', 1) for r in valid) / total_w
    return min(100, round(0.6 * max_score + 0.4 * avg_score))


def get_risk_level(score: int) -> str:
    if score >= 75: return 'critical'
    if score >= 50: return 'high'
    if score >= 25: return 'medium'
    return 'low'


def build_summary(level: str, score: int, signal_count: int) -> str:
    summaries = {
        'low':      f"Risk score: {score}/100. No major red flags detected ({signal_count} minor signals). Relatively safe, but always verify through official channels.",
        'medium':   f"Risk score: {score}/100. Suspicious patterns detected ({signal_count} signals). Verify independently before making any payment.",
        'high':     f"Risk score: {score}/100. Multiple high-severity signals ({signal_count} signals). Strong characteristics of a payment scam. Do NOT proceed.",
        'critical': f"CRITICAL — Risk score: {score}/100. Overwhelming evidence of fraud ({signal_count} signals). Almost certainly a scam. Do NOT pay or share information.",
    }
    return summaries.get(level, '')


# ================================================================
# ENDPOINTS
# ================================================================

@app.get("/api/health")
def health():
    return {"status": "ok", "service": "ScamShield API", "version": "1.0.0"}


@app.post("/api/analyze", response_model=AnalysisResponse)
def analyze(request: AnalysisRequest):
    results    = []
    all_signals = []

    if request.text:
        r = analyze_text(request.text)
        results.append({"score": r["score"], "weight": 3})
        all_signals.extend(r["signals"])

    if request.url:
        r = analyze_url(request.url)
        results.append({"score": r["score"], "weight": 3})
        all_signals.extend(r["signals"])

    if request.qr_content:
        qr = request.qr_content
        if qr.startswith("http"):
            r = analyze_url(qr)
        else:
            r = analyze_text(qr)
        results.append({"score": r["score"], "weight": 2})
        all_signals.extend(r["signals"])

    # Deduplicate
    seen    = set()
    deduped = []
    for sig in all_signals:
        if sig["id"] not in seen:
            seen.add(sig["id"])
            deduped.append(sig)

    final_score = compute_final_score(results) if results else 0
    risk_level  = get_risk_level(final_score)
    summary     = build_summary(risk_level, final_score, len(deduped))

    return {
        "score":        final_score,
        "risk_level":   risk_level,
        "signals":      deduped,
        "signal_count": len(deduped),
        "summary":      summary,
    }


@app.post("/api/analyze/text")
def analyze_text_ep(body: dict):
    text = body.get("text", "")
    if not text:
        raise HTTPException(status_code=400, detail="'text' field required")
    return analyze_text(text)


@app.post("/api/analyze/url")
def analyze_url_ep(body: dict):
    url = body.get("url", "")
    if not url:
        raise HTTPException(status_code=400, detail="'url' field required")
    return analyze_url(url)


# Mount static files (frontend + test runner)
ROOT_DIR = pathlib.Path(__file__).resolve().parent.parent
app.mount("/", StaticFiles(directory=str(ROOT_DIR), html=True), name="static")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)

