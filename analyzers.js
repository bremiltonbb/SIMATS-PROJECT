/* ================================================================
   analyzers.js — ScamShield Core Analysis Engine
   Text Analyzer · URL Analyzer · QR Analyzer · Behavioural
   ================================================================ */

'use strict';

// ================================================================
// MODULE 1 — TEXT / NLP ANALYZER
// ================================================================
const TextAnalyzer = {

  patterns: {

    urgency: {
      name: 'Urgency / Fear Language',
      icon: '⏰',
      severity: 'high',
      weight: 25,
      description: 'Uses urgency and fear tactics to pressure you into acting without thinking.',
      tests: [
        /\b(urgent|immediately|right\s*now|act\s*now|hurry|instantly|asap|emergency|critical)\b/i,
        /\b(last\s*chance|final\s*notice|limited\s*time|expires?\s*(soon|today|now|in\s*\d+)|deadline)\b/i,
        /\b(your\s*account\s*(will\s*be\s*|has\s*been\s*)?(blocked|suspended|closed|disabled|terminated|frozen|locked))\b/i,
        /\b(action\s*required|response\s*required|verify\s*(now|immediately|your\s*account))\b/i,
        /\b(within\s*\d+\s*(hour|minute|day|hr|min)s?)\b/i,
        /\b(expires?\s*in\s*\d+\s*(hour|minute|min|hr)s?)\b/i,
        /\b(freeze[d]?|block[ed]?|suspend[ed]?|deactivat[ed]?)\s*(your|the)\s*account\b/i,
        /\b(failure\s*to\s*(comply|respond|act)\s*will)\b/i,
      ],
    },

    impersonation: {
      name: 'Brand / Authority Impersonation',
      icon: '🎭',
      severity: 'critical',
      weight: 35,
      description: 'Claims to be from a trusted organisation to gain your confidence.',
      tests: [
        /\b(amazon|flipkart|myntra|meesho|snapdeal|paytm|phonepe|google\s*pay|gpay|bhim)\s*(customer\s*care|support|helpline|refund|team|official|executive|representative)\b/i,
        /\b(hdfc|sbi|icici|axis|kotak|yes\s*bank|pnb|bob|canara|union\s*bank)\s*(bank)?\s*(helpline|support|care|team|executive|official|officer)\b/i,
        /\b(rbi|reserve\s*bank|income\s*tax(ation)?|it\s*department|irdai|sebi|nabard)\s*(of\s*india)?\s*(official|team|notice|mandate|alert|officer)\b/i,
        /\b(irctc|lic|uidai|aadhaar|epfo|pf\s*(department|office)|esi)\b/i,
        /\b(microsoft|apple|google|meta|facebook|instagram|whatsapp)\s*(support|care|helpline|team|official|representative)\b/i,
        /\b(team\s*(amazon|flipkart|paytm|hdfc|sbi|rbi|google|microsoft|apple))\b/i,
        /\b(official|verified)\s*(representative|agent|executive)\s*(of|from)\b/i,
        // Bare brand name in account/suspension context
        /\byour\s*(amazon|flipkart|paytm|phonepe|hdfc|sbi|icici|axis|kotak|google)\s*(account|wallet|order|subscription)\s*(has|have|is|will)\s*(been|be)\s*(compromised|hacked|blocked|suspended|flagged|frozen|locked|deactivated)/i,
        /\b(amazon|flipkart|paytm|phonepe|hdfc|sbi|icici)\s*(account|order|wallet)\s*(compromised|hacked|blocked|suspended|frozen)/i,
      ],
    },

    otpRequest: {
      name: 'OTP / Credential Request',
      icon: '🔐',
      severity: 'critical',
      weight: 42,
      description: 'No legitimate service ever asks for your OTP, PIN, or password. This is a classic fraud tactic.',
      tests: [
        /\b(share|send|provide|tell|give|enter|submit|forward|type)\s*(your|the)?\s*(otp|one[\s-]time\s*password|pin|password|cvv|cvc|security\s*code|passcode)\b/i,
        /\b(otp|one[\s-]time\s*(password|pin|code))\s*(to\s*(verify|confirm|validate|authenticate|process|complete|receive))\b/i,
        /\b(verify\s*(your)?\s*(account|identity|payment|transaction)\s*(by\s*)?(sharing|entering|sending|providing|giving)\s*(the\s*)?(otp|pin|code|password))\b/i,
        /\b(don'?t\s*share\s*(your|the)?\s*otp)\b/i,
        /\b(bank\s*(will\s*)?never\s*(ask|asks?)\s*(for|you)\s*(otp|pin|password))\b/i,
        /\b(enter\s*(the|your)?\s*(otp|pin|code)\s*(sent|received|given)\s*(to|on)\s*your\s*(mobile|phone|number))\b/i,
        /\b(otp|one\s*time\s*password)\s*(is|was)?\s*(required|needed|must\s*be\s*shared|must\s*share)\b/i,
        /\bshare\s*(the|your)\s*(otp|pin|code|password)\b/i,
      ],
    },

    refundBait: {
      name: 'Fake Refund / Cashback / Prize Bait',
      icon: '💰',
      severity: 'high',
      weight: 30,
      description: 'Classic bait-and-switch: promise of money to extract a small fee or your credentials.',
      tests: [
        /\b(refund|cashback|reward|bonus|prize|rebate)\s*(of\s*)?₹?\s*\d[\d,]*\s*(is\s*)?(ready|processed|approved|pending|credited|waiting|initiated)\b/i,
        /\b(refund|cashback|reward|prize)\s*of\s*(rs\.?|inr|rupees?)?\s*\d[\d,.]+\b/i,
        /\b(you\s*('ve|have|are)\s*(won|qualified|selected|eligible|been\s*chosen|are\s*a\s*winner))\b/i,
        /\b(lottery|lucky\s*(draw|winner)|contest\s*winner|cash\s*prize|bumper\s*prize)\b/i,
        /\b(claim\s*your\s*(prize|reward|refund|money|cashback|winnings))\b/i,
        /\b(₹?\s*\d[\d,]+\s*(has\s*been|is)\s*(added|credited|transferred|sent)\s*(to\s*your\s*(account|wallet)))\b/i,
        /\b(you\s*are\s*(the\s*)?(winner|lucky\s*winner|selected|chosen))\b/i,
        /\b(congratulations?[!]?\s*(you|dear))\b/i,
        /\byour\s*(refund|prize|reward|cashback)\s*(of\s*)?(rs\.?|₹)?\s*\d+/i,
      ],
    },

    advanceFee: {
      name: 'Advance Fee / Processing Fee Scam',
      icon: '💳',
      severity: 'critical',
      weight: 45,
      description: 'Paying a fee to "receive" money is the classic advance-fee (419) fraud. Legitimate services never require this.',
      tests: [
        /\b(pay|transfer|send|deposit)\s*(₹?\s*\d[\d,]*)\s*(to\s*)?(receive|get|claim|unlock|process|release|credit)\b/i,
        /\b(small\s*fee|processing\s*(fee|charge)|handling\s*fee|activation\s*fee|registration\s*(fee|amount|charge)|service\s*charge)\b/i,
        /\b(advance\s*(payment|fee|amount|deposit)|security\s*deposit\s*(to\s*receive|before\s*receiving))\b/i,
        /\b(to\s*(receive|get|claim)\s*your\s*(refund|prize|reward|money)\s*(please\s*)?(pay|transfer|send|deposit|make\s*a\s*payment))\b/i,
        /\b(token\s*(amount|money|fee)|nominal\s*(fee|charge|amount))\b/i,
      ],
    },

    personalInfoRequest: {
      name: 'Personal / Financial Data Request',
      icon: '📋',
      severity: 'high',
      weight: 30,
      description: 'Legitimate organisations never ask for bank account details, card numbers, or identity documents via message.',
      tests: [
        /\b(account\s*number|bank\s*details|card\s*number|debit\s*card|credit\s*card)\s*(details|number|information)\b/i,
        /\b(aadhar|aadhaar|pan\s*card?|passport\s*number|voter\s*id)\s*(number|details|copy|photo|scan|image)\b/i,
        /\b(date\s*of\s*birth|mother'?s?\s*maiden\s*name)\b/i,
        /\b(update\s*(your\s*)?(kyc|bank\s*details|account\s*details|payment\s*info|nominee|records))\b/i,
        /\b(complete\s*(your\s*)?kyc|kyc\s*(expired|incomplete|pending|verification|required))\b/i,
      ],
    },

    remoteAccess: {
      name: 'Remote Access / Suspicious Call Request',
      icon: '📞',
      severity: 'high',
      weight: 28,
      description: 'Asking you to call a number or install remote access software is used to steal credentials in real time.',
      tests: [
        /\b(call\s*(us|our|this|the)\s*(helpline|number|toll[\s-]free|executive|agent|team|customer\s*care))\b/i,
        /\b(our\s*(executive|agent|team|representative)\s*will\s*(call|contact|reach)\s*(you|back))\b/i,
        /\b(download|install)\s*(anydesk|teamviewer|quicksupport|rustdesk|airdroid|remote\s*(desktop|access))\b/i,
        /\b(remote\s*(access|desktop|support|session)\s*(software|app|tool|application))\b/i,
        /\b(allow|grant|give)\s*(remote|screen)\s*(access|control|sharing|permission)\b/i,
        /\b(screen\s*share|screenshare)\b/i,
      ],
    },

    suspiciousLink: {
      name: 'Suspicious / Phishing Link in Message',
      icon: '🔗',
      severity: 'high',
      weight: 25,
      description: 'Message contains links with patterns commonly used in phishing attacks.',
      tests: [
        /https?:\/\/[^\s]+\.(xyz|tk|ml|ga|cf|gq|top|click|link|online|site|club|buzz|bid|win|loan|date)[^\s]*/i,
        /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[^\s]*/i,
        /(bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd|tiny\.cc|rebrand\.ly|rb\.gy|clck\.ru)\/[^\s]+/i,
        /https?:\/\/[^\s]*(refund|reward|prize|claim|verify|login-update|secure-bank|otp-verify)[^\s]*/i,
      ],
    },

    qrTrick: {
      name: 'QR Code "Receive Money" Trick',
      icon: '📷',
      severity: 'critical',
      weight: 38,
      description: '"Scan to receive" QR codes always SEND money, not receive it. This is one of the most common UPI frauds.',
      tests: [
        /\b(scan\s*(this|the)\s*qr\s*(code)?\s*to\s*(receive|get|claim|accept|collect)\s*(money|payment|refund|prize|cash))\b/i,
        /\b(qr\s*code\s*(to\s*)?(receive|accept|collect|claim)\s*(your\s*)?(refund|payment|money|prize|cashback))\b/i,
        /\b(scan\s*(and|&)\s*(receive|get|collect)\s*(₹?\s*\d+|money|your\s*refund))\b/i,
        /\b(i'll?\s*send\s*(you\s*)?money\s*(via|through|using)\s*(qr|scan))\b/i,
      ],
    },

    grammarAnomaly: {
      name: 'Template / Generic Language',
      icon: '📝',
      severity: 'low',
      weight: 8,
      description: 'Generic greetings and unusual phrasing are common in mass-distributed scam messages.',
      tests: [
        /^dear\s+(customer|user|sir|ma'?am|member|valued|account\s*holder)\b/i,
        /\b(kindly\s+(do\s+the\s+needful|revert|update|co[\s-]?operate))\b/i,
        /\b(revert\s*back\s*(at|to)\s*(earliest|soonest|your\s*earliest\s*convenience))\b/i,
        /\b(this\s*(message|sms|mail|call)\s*is\s*(from|by)\s*(team|department|division))\b/i,
      ],
    },
  },

  /**
   * Analyze text for scam patterns.
   * @param {string} text - Input text to analyze
   * @returns {{ score: number, signals: Array }}
   */
  analyze(text) {
    if (!text || text.trim().length < 3) {
      return { score: 0, signals: [] };
    }

    const signals = [];
    let totalScore = 0;

    for (const [key, config] of Object.entries(this.patterns)) {
      const matches = [];

      for (const regex of config.tests) {
        // Use exec in a loop for global patterns, or match for non-global
        const testStr = text;
        const found = testStr.match(new RegExp(regex.source, 'gi'));
        if (found) {
          matches.push(...found.slice(0, 2));
        }
      }

      if (matches.length > 0) {
        // Confidence grows with number of distinct matches, capped at 1
        const confidence = Math.min(1, 0.5 + matches.length * 0.25);
        const contribution = Math.round(config.weight * confidence);
        totalScore += contribution;

        // Deduplicate and trim quotes
        const uniqueQuotes = [...new Set(matches.map(m => m.trim()))].slice(0, 2);

        signals.push({
          id: key,
          name: config.name,
          icon: config.icon,
          severity: config.severity,
          description: config.description,
          quotes: uniqueQuotes,
          score_contribution: contribution,
          category: 'text',
        });
      }
    }

    return { score: Math.min(100, totalScore), signals };
  },
};

// ================================================================
// MODULE 2 — URL / DOMAIN ANALYZER
// ================================================================
const URLAnalyzer = {

  knownBrands: [
    'amazon', 'flipkart', 'paytm', 'phonepe', 'googlepay', 'bhim',
    'hdfc', 'sbi', 'icici', 'axis', 'kotak', 'yesbank', 'rbi',
    'irctc', 'uidai', 'epfo', 'incometax', 'gov',
    'microsoft', 'google', 'apple', 'facebook', 'whatsapp', 'instagram',
    'netflix', 'hotstar', 'jiocinema', 'zomato', 'swiggy', 'ola', 'uber',
    'myntra', 'nykaa', 'meesho', 'razorpay', 'instamojo', 'payumoney',
    'billdesk', 'airtel', 'jio', 'vodafone', 'bsnl', 'indiapost',
  ],

  suspiciousTLDs: [
    '.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.click',
    '.link', '.online', '.site', '.club', '.buzz', '.bid', '.win',
    '.loan', '.date', '.download', '.stream', '.party', '.trade',
    '.racing', '.accountant', '.cricket', '.science', '.work', '.fit',
  ],

  urlShorteners: [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
    'is.gd', 'tiny.cc', 'rebrand.ly', 'buff.ly', 'shorturl.at',
    'cutt.ly', 'rb.gy', 'clck.ru', 'trib.al', 'dlvr.it',
  ],

  // Characters that look similar to others
  homoglyphMap: {
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's',
    '6': 'b', '8': 'b', 'vv': 'w', 'rn': 'm', 'I': 'l',
  },

  /** Parse a URL string into its parts. */
  parseURL(rawUrl) {
    try {
      let url = rawUrl.trim();
      if (!/^https?:\/\//i.test(url)) {
        url = 'https://' + url;
      }
      const u = new URL(url);
      const hostParts = u.hostname.toLowerCase().split('.');
      const tld = hostParts.length >= 2 ? '.' + hostParts.slice(-1)[0] : '';
      const domain = hostParts.length >= 2 ? hostParts.slice(-2).join('.') : u.hostname;
      const subdomain = hostParts.length > 2 ? hostParts.slice(0, -2).join('.') : '';

      return {
        ok: true,
        protocol: u.protocol,
        hostname: u.hostname.toLowerCase(),
        pathname: u.pathname,
        search: u.search,
        tld,
        domain,
        domainNoTLD: hostParts.slice(-2, -1)[0] || '',
        subdomain,
        full: url,
      };
    } catch (e) {
      return { ok: false, full: rawUrl };
    }
  },

  /** Levenshtein edit distance between two strings. */
  levenshtein(a, b) {
    a = a.toLowerCase();
    b = b.toLowerCase();
    const dp = [];
    for (let i = 0; i <= a.length; i++) {
      dp[i] = [i];
      for (let j = 1; j <= b.length; j++) {
        dp[i][j] = i === 0 ? j
          : Math.min(
            dp[i - 1][j] + 1,
            dp[i][j - 1] + 1,
            dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)
          );
      }
    }
    return dp[a.length][b.length];
  },

  /** Normalize homoglyphs in a string for comparison. */
  normalizeHomoglyphs(str) {
    let s = str.toLowerCase();
    for (const [fake, real] of Object.entries(this.homoglyphMap)) {
      s = s.split(fake).join(real);
    }
    return s;
  },

  /**
   * Analyze a URL string.
   * @param {string} rawUrl
   * @returns {{ score: number, signals: Array, parsed: object|null }}
   */
  analyze(rawUrl) {
    if (!rawUrl || rawUrl.trim().length < 3) {
      return { score: 0, signals: [], parsed: null };
    }

    const parsed = this.parseURL(rawUrl);
    const signals = [];
    let totalScore = 0;

    if (!parsed.ok) {
      signals.push({
        id: 'invalid_url',
        name: 'Malformed / Unparseable URL',
        icon: '⚠️',
        severity: 'medium',
        description: 'This URL cannot be properly parsed. Malformed URLs are suspicious in payment contexts.',
        quotes: [rawUrl.substring(0, 70)],
        score_contribution: 20,
        category: 'url',
      });
      return { score: 20, signals, parsed: null };
    }

    const { hostname, domain, domainNoTLD, subdomain, pathname, search, protocol, tld } = parsed;

    // ── Check 1: IP address URL ──────────────────────────────
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
      const s = 45;
      totalScore += s;
      signals.push({
        id: 'ip_url',
        name: 'Raw IP Address Used as URL',
        icon: '🌐',
        severity: 'critical',
        description: 'Legitimate payment portals always use domain names, never raw IP addresses. This is a major red flag.',
        quotes: [hostname],
        score_contribution: s,
        category: 'url',
      });
    }

    // ── Check 2: No HTTPS ────────────────────────────────────
    if (protocol !== 'https:') {
      const s = 32;
      totalScore += s;
      signals.push({
        id: 'no_https',
        name: 'Insecure Connection (HTTP not HTTPS)',
        icon: '🔓',
        severity: 'high',
        description: 'All legitimate payment pages enforce HTTPS. An HTTP connection means data is transmitted unencrypted.',
        quotes: [`${protocol}//${hostname}`],
        score_contribution: s,
        category: 'url',
      });
    }

    // ── Check 3: Suspicious TLD ──────────────────────────────
    const suspTLD = this.suspiciousTLDs.find(t => hostname.endsWith(t));
    if (suspTLD) {
      const s = 35;
      totalScore += s;
      signals.push({
        id: 'suspicious_tld',
        name: 'High-Risk Top-Level Domain',
        icon: '🏴',
        severity: 'high',
        description: `The TLD "${suspTLD}" is predominantly used in phishing and scam sites, rarely by legitimate payment services.`,
        quotes: [hostname],
        score_contribution: s,
        category: 'url',
      });
    }

    // ── Check 4: URL Shortener ───────────────────────────────
    const shortener = this.urlShorteners.find(s => hostname === s || hostname.endsWith('.' + s));
    if (shortener) {
      const s = 25;
      totalScore += s;
      signals.push({
        id: 'url_shortener',
        name: 'URL Shortener / Redirect Used',
        icon: '🔀',
        severity: 'medium',
        description: 'Shortened URLs hide the real destination. Scammers routinely use them to disguise phishing links in payment messages.',
        quotes: [rawUrl.substring(0, 55)],
        score_contribution: s,
        category: 'url',
      });
    }

    // ── Check 5: Lookalike domain (Levenshtein) ──────────────
    const normDomainNoTLD = this.normalizeHomoglyphs(domainNoTLD);
    let lookalikefound = false;

    for (const brand of this.knownBrands) {
      if (brand === domainNoTLD.toLowerCase()) continue; // Exact = potentially real
      const dist = this.levenshtein(normDomainNoTLD, brand);
      const maxLen = Math.max(normDomainNoTLD.length, brand.length);
      if (maxLen === 0) continue;
      const similarity = 1 - dist / maxLen;

      if (similarity >= 0.6 && similarity < 1 && dist <= 3) {
        const s = 52;
        totalScore += s;
        lookalikefound = true;
        signals.push({
          id: 'lookalike_domain',
          name: 'Lookalike / Impersonation Domain',
          icon: '🎭',
          severity: 'critical',
          description: `Domain "${domain}" closely mimics the legitimate "${brand}" brand (${Math.round(similarity * 100)}% similarity, edit distance: ${dist}). This is a classic phishing technique.`,
          quotes: [domain, `Mimics: ${brand}`],
          score_contribution: s,
          category: 'url',
        });
        break;
      }
    }

    // ── Check 6: Brand name in subdomain (deceptive) ─────────
    if (!lookalikefound && subdomain) {
      const brandInSub = this.knownBrands.find(brand =>
        subdomain.includes(brand) && !domainNoTLD.toLowerCase().includes(brand)
      );
      if (brandInSub) {
        const s = 50;
        totalScore += s;
        signals.push({
          id: 'brand_in_subdomain',
          name: 'Brand Name Used Deceptively in Subdomain',
          icon: '🎭',
          severity: 'critical',
          description: `"${brandInSub}" appears in the subdomain to look legitimate, but the actual domain is "${domain}". This is the classic "hdfc.bank-secure-xyz.com" deception.`,
          quotes: [hostname],
          score_contribution: s,
          category: 'url',
        });
      }
    }

    // ── Check 7: Homoglyphs in domain ────────────────────────
    const normHostname = this.normalizeHomoglyphs(hostname);
    if (normHostname !== hostname) {
      const s = 42;
      totalScore += s;
      signals.push({
        id: 'homoglyphs',
        name: 'Look-alike Characters (Homoglyphs)',
        icon: '👁️',
        severity: 'critical',
        description: 'The domain contains characters that visually mimic others (e.g., "0" for "o", "1" for "l", "rn" for "m") to impersonate a legitimate domain.',
        quotes: [hostname, `Normalized: ${normHostname}`],
        score_contribution: s,
        category: 'url',
      });
    }

    // ── Check 8: Suspicious path keywords ────────────────────
    const suspPathKW = ['refund', 'claim', 'prize', 'reward', 'winner', 'verify', 'otp', 'kyc', 'secure-pay', 'payment-verify', 'update-details'];
    const pathQuery = (pathname + search).toLowerCase();
    const foundKW = suspPathKW.filter(kw => pathQuery.includes(kw));
    if (foundKW.length > 0) {
      const s = 20;
      totalScore += s;
      signals.push({
        id: 'suspicious_path',
        name: 'Suspicious Keywords in URL Path',
        icon: '📍',
        severity: 'medium',
        description: `URL path contains high-risk keywords: "${foundKW.join('", "')}" — commonly found in phishing and fake claim pages.`,
        quotes: [pathname.substring(0, 70)],
        score_contribution: s,
        category: 'url',
      });
    }

    // ── Check 9: Excessive subdomains ────────────────────────
    const subParts = subdomain ? subdomain.split('.').filter(Boolean) : [];
    if (subParts.length >= 2) {
      const s = 18;
      totalScore += s;
      signals.push({
        id: 'excessive_subdomains',
        name: 'Excessive Subdomain Depth',
        icon: '🔎',
        severity: 'medium',
        description: `This URL has ${subParts.length} subdomain levels. Scammers use deep subdomains (e.g., "hdfc.bank.secure.malicious.com") to hide the real malicious domain at the end.`,
        quotes: [hostname],
        score_contribution: s,
        category: 'url',
      });
    }

    // ── Check 10: Sensitive parameters in query string ────────
    const sensitiveParams = ['otp', 'token', 'password', 'pass', 'secret', 'key', 'auth', 'cvv', 'pin'];
    const queryLower = search.toLowerCase();
    const foundParams = sensitiveParams.filter(p =>
      queryLower.includes(p + '=') || queryLower.includes(p + '%3D')
    );
    if (foundParams.length > 0) {
      const s = 35;
      totalScore += s;
      signals.push({
        id: 'sensitive_params',
        name: 'Sensitive Credentials in URL Parameters',
        icon: '🔑',
        severity: 'high',
        description: `URL query string contains sensitive parameter names: "${foundParams.join('", "')}". Legitimate sites never pass OTPs or credentials in URLs.`,
        quotes: [search.substring(0, 70)],
        score_contribution: s,
        category: 'url',
      });
    }

    return { score: Math.min(100, totalScore), signals, parsed };
  },
};

// ================================================================
// MODULE 3 — QR CODE ANALYZER
// ================================================================
const QRAnalyzer = {

  /**
   * Decode QR from an HTMLImageElement using jsQR.
   * @param {HTMLImageElement} imgEl - Fully loaded image element
   * @returns {string|null} Decoded QR content or null
   */
  async decodeFromImage(imgEl) {
    if (typeof jsQR !== 'function') {
      console.warn('jsQR library not loaded.');
      return null;
    }

    try {
      const canvas = document.createElement('canvas');
      canvas.width = imgEl.naturalWidth || imgEl.width;
      canvas.height = imgEl.naturalHeight || imgEl.height;
      const ctx = canvas.getContext('2d');
      ctx.drawImage(imgEl, 0, 0, canvas.width, canvas.height);
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);

      // Try normal orientation
      let result = jsQR(imageData.data, imageData.width, imageData.height, {
        inversionAttempts: 'dontInvert',
      });
      if (result) return result.data;

      // Try inverted (dark background QR codes)
      result = jsQR(imageData.data, imageData.width, imageData.height, {
        inversionAttempts: 'onlyInvert',
      });
      if (result) return result.data;

      return null;
    } catch (err) {
      console.error('QR decode error:', err);
      return null;
    }
  },

  /**
   * Parse UPI URI parameters.
   * @param {string} content - Full upi:// URI string
   * @returns {object|null}
   */
  parseUPI(content) {
    try {
      const match = content.match(/^upi:\/\/pay\?(.+)$/i);
      if (!match) return null;
      const p = new URLSearchParams(match[1]);
      return {
        pa:  p.get('pa')  || '',  // Payee address (VPA)
        pn:  p.get('pn')  || '',  // Payee name
        am:  p.get('am')  || '',  // Amount
        mc:  p.get('mc')  || '',  // Merchant code
        tn:  p.get('tn')  || '',  // Transaction note
        cu:  p.get('cu')  || 'INR',
        tr:  p.get('tr')  || '',
      };
    } catch (e) {
      return null;
    }
  },

  /**
   * Analyze decoded QR content.
   * @param {string} content
   * @returns {{ score: number, signals: Array, meta: object }}
   */
  analyze(content) {
    if (!content || content.trim().length < 2) {
      return { score: 0, signals: [], meta: {} };
    }

    const signals = [];
    let totalScore = 0;
    const meta = { type: 'unknown', content };

    const contentLower = content.toLowerCase();

    // ── UPI Payment QR ───────────────────────────────────────
    if (/^upi:\/\/pay\?/i.test(content)) {
      meta.type = 'upi_payment';
      const upi = this.parseUPI(content);
      meta.upi = upi;

      // Signal: Scanning this sends money FROM you
      signals.push({
        id: 'qr_is_payment',
        name: 'QR Code Initiates a Payment (Money Leaves Your Account)',
        icon: '📤',
        severity: 'high',
        description: 'UPI QR codes always initiate a PAYMENT from you to the payee. Scammers claim you will RECEIVE money — but that is impossible. Scanning this will send your money to the payee.',
        quotes: ['QR Type: UPI Payment Request', 'Direction: Your account → Payee'],
        score_contribution: 22,
        category: 'qr',
      });
      totalScore += 22;

      if (upi) {
        const amount = parseFloat(upi.am);

        // Signal: Pre-set amount
        if (!isNaN(amount) && amount > 50) {
          const s = 35;
          totalScore += s;
          signals.push({
            id: 'qr_fixed_amount',
            name: 'Pre-Set Payment Amount Embedded in QR',
            icon: '💰',
            severity: 'high',
            description: `This QR code has a fixed amount of ₹${amount.toLocaleString('en-IN')} embedded. Legitimate "receive refund" QR codes do not pre-set the amount — this ensures a specific sum is deducted from your account.`,
            quotes: [`Amount: ₹${amount.toLocaleString('en-IN')}`, `Payee VPA: ${upi.pa}`],
            score_contribution: s,
            category: 'qr',
          });
        }

        // Signal: Suspicious payee name
        const brandNames = ['amazon', 'flipkart', 'hdfc', 'sbi', 'icici', 'rbi', 'government', 'gov', 'paytm', 'refund', 'support', 'helpline', 'care', 'prize', 'lottery'];
        const payeeLower = (upi.pn + ' ' + upi.pa).toLowerCase();
        const foundBrand = brandNames.find(b => payeeLower.includes(b));
        if (foundBrand) {
          const s = 35;
          totalScore += s;
          signals.push({
            id: 'qr_suspicious_payee',
            name: 'Suspicious Payee Name / Brand Impersonation in QR',
            icon: '⚠️',
            severity: 'critical',
            description: `Payee name "${upi.pn || upi.pa}" contains "${foundBrand}" suggesting brand impersonation. Always verify the payee through official channels before scanning.`,
            quotes: [`Payee: ${upi.pn || '(none)'}`, `VPA: ${upi.pa}`],
            score_contribution: s,
            category: 'qr',
          });
        }

        // Signal: Transaction note with scam keywords
        const noteScamPat = /\b(refund|prize|reward|claim|verify|otp|security|lottery|government|processing\s*fee)\b/i;
        if (upi.tn && noteScamPat.test(upi.tn)) {
          const s = 22;
          totalScore += s;
          signals.push({
            id: 'qr_suspicious_note',
            name: 'Suspicious Transaction Note',
            icon: '📝',
            severity: 'medium',
            description: `The QR transaction note contains suspicious keywords: "${upi.tn}". Legitimate payments don't use such notes.`,
            quotes: [`Note: "${upi.tn}"`],
            score_contribution: s,
            category: 'qr',
          });
        }

        // Signal: Personal VPA used for large payment
        const isPersonalVPA = /@(oksbi|okaxis|okicici|okhdfcbank|paytm|ybl|ibl|axl|upi|fbl|rbl|apl|jiomoney|airtel|pingpay|rapl)$/i.test(upi.pa);
        if (isPersonalVPA && !isNaN(amount) && amount > 1000) {
          const s = 18;
          totalScore += s;
          signals.push({
            id: 'qr_personal_vpa',
            name: 'Personal UPI ID for Large Payment',
            icon: '👤',
            severity: 'medium',
            description: `This QR uses a personal/consumer UPI ID (${upi.pa}) for a payment of ₹${amount.toLocaleString('en-IN')}. Legitimate businesses use verified merchant IDs, not personal accounts.`,
            quotes: [`VPA: ${upi.pa}`],
            score_contribution: s,
            category: 'qr',
          });
        }
      }

    // ── URL-type QR ──────────────────────────────────────────
    } else if (/^https?:\/\//i.test(content)) {
      meta.type = 'url';

      // Run URL analyzer on the embedded URL
      const urlResult = URLAnalyzer.analyze(content);
      if (urlResult.score > 0) {
        signals.push({
          id: 'qr_embedded_url',
          name: 'QR Code Contains a URL — Analyzed Below',
          icon: '🔗',
          severity: 'low',
          description: 'This QR contains a URL. The URL has been analyzed for phishing and scam indicators.',
          quotes: [content.substring(0, 70)],
          score_contribution: 0,
          category: 'qr',
        });
        urlResult.signals.forEach(s => signals.push({ ...s, category: 'qr' }));
        totalScore += urlResult.score;
      } else {
        meta.type = 'url_clean';
      }

    // ── Plain text / phone / other ────────────────────────────
    } else {
      meta.type = 'text';
      const scamKWs = content.match(/\b(refund|prize|reward|claim|verify\s*otp|scan\s*to\s*receive|processing\s*fee|advance\s*fee)\b/gi);
      if (scamKWs) {
        const s = 38;
        totalScore += s;
        signals.push({
          id: 'qr_scam_text',
          name: 'Scam Keywords in QR Text Content',
          icon: '🚨',
          severity: 'critical',
          description: 'The QR code contains text with keywords commonly used in payment fraud.',
          quotes: [...new Set(scamKWs)].slice(0, 2),
          score_contribution: s,
          category: 'qr',
        });
      }
    }

    return { score: Math.min(100, totalScore), signals, meta };
  },
};

// ================================================================
// MODULE 4 — BEHAVIOURAL / CONTEXT ANALYZER
// ================================================================
const BehaviouralAnalyzer = {

  /**
   * Analyze transactional context for red flags.
   * @param {object} ctx
   * @param {number} [ctx.amount]
   * @param {string} [ctx.payeeName]
   * @param {string} [ctx.purpose]
   * @returns {{ score: number, signals: Array }}
   */
  analyze({ amount, payeeName, purpose } = {}) {
    const signals = [];
    let totalScore = 0;

    const numAmount = parseFloat(amount) || 0;

    // ── Amount checks ────────────────────────────────────────
    if (numAmount > 0) {

      // Very high-value transaction
      if (numAmount > 50000) {
        const s = 15;
        totalScore += s;
        signals.push({
          id: 'ctx_high_value',
          name: 'Very High-Value Transaction',
          icon: '💸',
          severity: 'medium',
          description: `₹${numAmount.toLocaleString('en-IN')} is a high-value transaction. Exercise extra caution — scam amounts tend to be high enough to be significant but low enough to seem plausible.`,
          quotes: [`Amount: ₹${numAmount.toLocaleString('en-IN')}`],
          score_contribution: s,
          category: 'behavioural',
        });
      }

      // Small fee to "claim" large refund/prize
      if (numAmount < 1000 && purpose) {
        const purposeLower = purpose.toLowerCase();
        if (/\b(refund|prize|reward|claim|cashback|processing|registration|security\s*deposit)\b/.test(purposeLower)) {
          const s = 55;
          totalScore += s;
          signals.push({
            id: 'ctx_advance_fee',
            name: 'Small Amount to "Unlock" Large Sum (Advance Fee Fraud)',
            icon: '🚨',
            severity: 'critical',
            description: `Paying ₹${numAmount} described as "${purpose}" to receive a larger amount is the textbook advance-fee (419) scam. No legitimate service requires this. The money sent is always lost.`,
            quotes: [`Amount: ₹${numAmount}`, `Purpose: ${purpose}`],
            score_contribution: s,
            category: 'behavioural',
          });
        }
      }
    }

    // ── Payee name checks ────────────────────────────────────
    if (payeeName && payeeName.trim()) {
      const brands = ['amazon', 'hdfc', 'sbi', 'icici', 'rbi', 'government', 'gov', 'paytm', 'flipkart', 'refund', 'support', 'helpline', 'care', 'service', 'prize', 'lottery', 'microsoft', 'google'];
      const pLower = payeeName.toLowerCase();
      const found = brands.find(b => pLower.includes(b));

      if (found) {
        const s = 38;
        totalScore += s;
        signals.push({
          id: 'ctx_payee_impersonation',
          name: 'Payee Name Impersonates a Known Brand or Authority',
          icon: '🎭',
          severity: 'high',
          description: `Payee name "${payeeName}" contains "${found}" suggesting impersonation of a known organisation. Always verify payee identity through official channels before any payment.`,
          quotes: [`Payee: ${payeeName}`],
          score_contribution: s,
          category: 'behavioural',
        });
      }
    }

    return { score: Math.min(100, totalScore), signals };
  },
};
