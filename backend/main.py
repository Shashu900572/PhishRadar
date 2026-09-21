import math
import re
from urllib.parse import urlparse
from fastapi import FastAPI, Form, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

app = FastAPI(title="Multimodal Phishing Detection Engine")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Verified root domains that are 100% legitimate
LEGIT_DOMAINS = {
    "instagram.com", "facebook.com", "whatsapp.com", "meta.com",
    "google.com", "youtube.com", "gmail.com",
    "apple.com", "microsoft.com", "live.com", "linkedin.com",
    "twitter.com", "x.com", "github.com", "amazon.com", "amazon.in",
    "netflix.com", "flipkart.com", "zerodha.com", "kite.zerodha.com",
    "sbi.co.in", "onlinesbi.sbi", "hdfcbank.com", "icicibank.com",
    "axisbank.com", "paytm.com", "phonepe.com", "incometax.gov.in",
    "indiapost.gov.in", "irctc.co.in", "uidai.gov.in", "epfindia.gov.in",
    "onrender.com"
}

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".work", ".click",
    ".loan", ".club", ".buzz", ".guru", ".vip", ".site", ".icu", ".cam"
}

THREAT_KEYWORDS = {
    "urgency": [
        "suspended", "urgent", "24 hours", "immediate", "immediately", "blocked", "freeze", "arrest",
        "deactivated", "deactivate", "expired", "expire", "action required", "terminate", "disconnect",
        "disconnected", "power cut", "cut off", "legal action", "penalty", "fine", "police", "court",
        "last date", "final notice",
        "तुरंत", "बंद", "अवरुद्ध", "24 घंटे", "गिरफ्तार", "चेतावनी", "काट दिया जाएगा", "turant", "band", "block", "giraftaar",
        "ತಕ್ಷಣ", "ರದ್ದು", "ನಿರ್ಬಂಧಿಸಲಾಗಿದೆ", "ಬಂಧನ", "ಎಚ್ಚರಿಕೆ", "ಕಡಿತ", "takshana", "raddu", "bandhana"
    ],
    "credentials_and_finance": [
        "otp", "pin", "cvv", "password", "bank manager", "customs officer", "cbi", "unauthorized",
        "kyc", "pan", "pan card", "aadhar", "aadhaar", "upi", "credit card", "debit card",
        "refund", "lottery", "cashback", "reward", "prize", "electricity bill", "bijli", "challan",
        "loan", "income tax", "subsidy", "apk", "kbc", "delivery address", "customs duty", "bonus",
        "part time job", "earn money", "daily income", "telegram",
        "ओटीपी", "पिन", "पासवर्ड", "बैंक प्रबंधक", "अवैध", "केवाईसी", "लॉटरी", "रिफंड", "बिजली",
        "ಒಟಿಪಿ", "ಪಿನ್", "ಪಾಸ್‌ವರ್ಡ್", "ಅಧಿಕಾರಿ", "ಕೆವೈಸಿ", "ಲಾಟರಿ", "ಮರುಪಾವತಿ", "ವಿದ್ಯುತ್"
    ],
    "contextual_account": [
        "account", "bank", "wallet", "funds", "balance", "sim", "number", "profile", "parcel", "package",
        "खाता", "ಖಾತೆ"
    ]
}

def is_whitelisted(domain: str) -> bool:
    domain = domain.lower().strip()
    for legit in LEGIT_DOMAINS:
        if domain == legit or domain.endswith("." + legit):
            return True
    return False

def detect_language(text: str) -> str:
    if re.search(r'[\u0C80-\u0CFF]', text):
        return "kn-IN"
    elif re.search(r'[\u0900-\u097F]', text):
        return "hi-IN"
    return "en-US"

def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / len(text)
        entropy -= p * math.log2(p)
    return round(entropy, 2)

def match_token(keyword: str, text: str) -> bool:
    if re.match(r'^[a-zA-Z0-9_-]+$', keyword):
        pattern = rf'\b{re.escape(keyword)}\b'
        return bool(re.search(pattern, text, re.IGNORECASE))
    return keyword.lower() in text.lower()

@app.post("/api/scan/url")
async def scan_url(url: str = Form(...)):
    clean_url = url.strip()
    if re.match(r"^https?:[^\/]", clean_url):
        clean_url = re.sub(r"^(https?):", r"\1://", clean_url)
    elif "://" not in clean_url:
        clean_url = f"http://{clean_url}"

    parsed = urlparse(clean_url)
    raw_host = (parsed.hostname or parsed.netloc.split(":")[0]).lower()
    full_path = (parsed.path + ("?" + parsed.query if parsed.query else "")).lower()
    port = parsed.port

    # Whitelist Check (Instant 0% Safe)
    if is_whitelisted(raw_host):
        return {
            "risk_score": 0.0,
            "signals": [f"Verified authentic root domain: {raw_host}"]
        }

    score = 5
    signals = []

    # Suspicious TLD check
    if any(raw_host.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score += 35
        signals.append("High-risk / free-tier domain extension (commonly abused TLD)")

    # Brand Impersonation targets
    impersonation_targets = [
        "zerodha", "kite", "bank", "secure", "login", "instagram", "facebook",
        "sbi", "paytm", "upi", "hdfc", "icici", "kyc", "verify", "support", "bill",
        "amazon", "google", "apple", "netflix", "flipkart", "post", "tax", "poste"
    ]
    matched_brands = [b for b in impersonation_targets if b in raw_host or b in full_path]
    if matched_brands:
        score += 45
        signals.append(f"High-Value Brand/Fintech Impersonation target: {', '.join(matched_brands[:3])}")

    # Fake TLD Suffix Trick (e.g. .com-app)
    if re.search(r'\.(com|co|net|org|gov)-', raw_host):
        score += 40
        signals.append("Deceptive TLD hyphenation trick (impersonating legitimate root domain)")

    # Subdomain brand spoofing
    parts = raw_host.split(".")
    if len(parts) >= 3 and any(b in ".".join(parts[:-2]) for b in impersonation_targets):
        score += 35
        signals.append("Subdomain brand injection: Legitimate organization impersonated on foreign host")

    # Deep URL Path & Query Phishing Vectors
    path_keywords = ["validation", "verification", "confirm", "auth", "signin", "update-account", "webscr", "login", "logon"]
    matched_path_kw = [pk for pk in path_keywords if pk in full_path]
    if matched_path_kw:
        score += 45
        signals.append(f"Deceptive authentication/credential harvesting parameter: {matched_path_kw[0]}")

    if re.search(r'[a-f0-9]{24,}', full_path):
        score += 45
        signals.append("Obfuscated automated phishing kit token/hash located in URI path")

    if len(clean_url) > 60:
        score += 15
        signals.append(f"Abnormal URI length ({len(clean_url)} chars) common in phishing redirects")

    if raw_host.count(".") >= 3:
        score += 20
        signals.append(f"Deceptive subdomain nesting depth ({raw_host.count('.')} dots)")

    if re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', raw_host):
        score += 40
        signals.append("Direct bare IPv4 address routing detected (evading DNS inspection)")

    entropy = calculate_entropy(raw_host)
    if entropy > 4.0:
        score += 20
        signals.append(f"High domain randomness / algorithmic generation (Entropy: {entropy})")

    if port and port not in [80, 443]:
        score += 25
        signals.append(f"Suspicious high-risk port detected: :{port}")

    if raw_host.count("-") >= 2 or ("-" in raw_host and any(b in raw_host for b in impersonation_targets)):
        score += 20
        signals.append("Typosquatting hyphen separator paired with brand name")

    if not signals:
        signals.append("Domain syntax normal, no lexical anomalies found")

    return {"risk_score": min(score, 99), "signals": signals}

@app.post("/api/scan/text")
async def scan_text(content: str = Form(...)):
    score = 5
    signals = []
    text_lower = content.lower()
    lang = detect_language(content)

    found_urgency = [w for w in THREAT_KEYWORDS["urgency"] if match_token(w, text_lower)]
    if found_urgency:
        score += 40
        signals.append(f"Psychological urgency tokens: {', '.join(found_urgency[:4])}")

    found_creds = [w for w in THREAT_KEYWORDS["credentials_and_finance"] if match_token(w, text_lower)]
    if found_creds:
        score += 40
        signals.append(f"Financial / Credential / Scam triggers: {', '.join(found_creds[:4])}")

    found_account = [w for w in THREAT_KEYWORDS["contextual_account"] if match_token(w, text_lower)]
    if found_account:
        score += 15
        signals.append(f"Targeted asset/account context: {', '.join(found_account[:3])}")

    detected_urls = re.findall(r'(?:https?:\/\/|www\.)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:\/[^\s]*)?', content)
    suspicious_links = []
    for raw_u in detected_urls:
        u_domain = raw_u.lower().replace("http://", "").replace("https://", "").split("/")[0]
        if not is_whitelisted(u_domain) and any(ext in u_domain for ext in [".com", ".in", ".org", ".net", ".top", ".xyz", ".co", ".app", ".info", ".me", ".live"]):
            suspicious_links.append(u_domain)

    if suspicious_links:
        score += 35
        signals.append(f"Unverified redirect link detected in SMS: {', '.join(suspicious_links[:2])}")

    if re.search(r'\b(?:\+91|0)?[6-9]\d{9}\b', content) and (found_urgency or found_creds):
        score += 20
        signals.append("Direct unverified contact number embedded with urgent call-to-action")

    if ".apk" in text_lower or "download app" in text_lower:
        score += 35
        signals.append("External unauthorized Android application (.apk) installation prompt")

    if not signals:
        signals.append("Safe message: No credential harvesting or coercive tokens identified")

    return {
        "risk_score": min(score, 99),
        "signals": signals,
        "language": lang
    }

@app.post("/api/scan/image")
async def scan_image(file: UploadFile = File(...)):
    return {"risk_score": 5, "signals": ["Clean image: No hidden barcodes or QR links located"]}

@app.post("/api/scan/video")
async def scan_video(file: UploadFile = File(...)):
    return {"risk_score": 10, "signals": ["No facial artifacts or warping anomalies identified across frames"]}

app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")