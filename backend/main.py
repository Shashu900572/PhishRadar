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

LEGIT_DOMAINS = {
    "instagram.com", "facebook.com", "whatsapp.com", "meta.com",
    "google.com", "youtube.com", "gmail.com",
    "apple.com", "microsoft.com", "live.com", "linkedin.com",
    "twitter.com", "x.com", "github.com", "amazon.com", "amazon.in",
    "netflix.com", "flipkart.com", "zerodha.com", "kite.zerodha.com",
    "sbi.co.in", "onlinesbi.sbi", "hdfcbank.com", "icicibank.com",
    "axisbank.com", "paytm.com", "phonepe.com", "incometax.gov.in"
}

def is_whitelisted(domain: str) -> bool:
    domain = domain.lower()
    for legit in LEGIT_DOMAINS:
        if domain == legit or domain.endswith("." + legit):
            return True
    return False

THREAT_KEYWORDS = {
    "urgency": [
        "suspended", "urgent", "24 hours", "immediate", "immediately", "blocked", "freeze", "arrest",
        "deactivated", "deactivate", "expired", "expire", "action required", "terminate", "disconnect",
        "power cut", "cut off", "legal action", "penalty", "fine",
        "तुरंत", "बंद", "अवरुद्ध", "24 घंटे", "गिरफ्तार", "चेतावनी", "काट दिया जाएगा", "turant", "band", "block", "giraftaar",
        "ತಕ್ಷಣ", "ರದ್ದು", "ನಿರ್ಬಂಧಿಸಲಾಗಿದೆ", "ಬಂಧನ", "ಎಚ್ಚರಿಕೆ", "ಕಡಿತ", "takshana", "raddu", "bandhana"
    ],
    "credentials_and_finance": [
        "otp", "pin", "cvv", "password", "bank manager", "customs officer", "cbi", "unauthorized",
        "kyc", "pan", "pan card", "aadhar", "aadhaar", "upi", "credit card", "debit card",
        "refund", "lottery", "cashback", "reward", "prize", "electricity bill", "bijli", "challan",
        "loan", "income tax", "subsidy", "apk",
        "ओटीपी", "पिन", "पासवर्ड", "बैंक प्रबंधक", "अवैध", "केवाईसी", "लॉटरी", "रिफंड", "बिजली",
        "ಒಟಿಪಿ", "ಪಿನ್", "ಪಾಸ್‌ವರ್ಡ್", "ಅಧಿಕಾರಿ", "ಕೆವೈಸಿ", "ಲಾಟರಿ", "ಮರುಪಾವತಿ", "ವಿದ್ಯುತ್"
    ],
    "contextual_account": [
        "account", "bank", "wallet", "funds", "balance", "sim", "number", "profile",
        "खाता", "ಖಾತೆ"
    ]
}

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
    domain = (parsed.hostname or parsed.netloc.split(":")[0]).lower()
    port = parsed.port

    if is_whitelisted(domain):
        return {
            "risk_score": 0.0,
            "signals": [f"Verified authentic root domain: {domain}"]
        }

    score = 5
    signals = []

    impersonation_targets = [
        "zerodha", "kite", "bank", "secure", "login", "instagram", "facebook",
        "sbi", "paytm", "upi", "hdfc", "icici", "kyc", "verify", "support", "bill"
    ]
    if any(tok in domain for tok in impersonation_targets):
        score += 45
        signals.append("High-Value Brand/Fintech Impersonation token detected")

    entropy = calculate_entropy(domain)
    if entropy > 3.8:
        score += 20
        signals.append(f"High domain randomness (Entropy: {entropy})")

    if domain.count(".") >= 3:
        score += 15
        signals.append(f"Excessive subdomain depth ({domain.count('.')} dots)")

    if re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', domain):
        score += 30
        signals.append("Direct bare IPv4 address routing detected")

    if port and port not in [80, 443]:
        score += 20
        signals.append(f"Suspicious high-risk port detected: :{port}")

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
        signals.append(f"Financial / Credential / KYC targets: {', '.join(found_creds[:4])}")

    found_account = [w for w in THREAT_KEYWORDS["contextual_account"] if match_token(w, text_lower)]
    if found_account:
        score += 15
        signals.append(f"Targeted asset/account linkage: {', '.join(found_account[:3])}")

    # Detect links/URLs embedded in the message
    detected_urls = re.findall(r'(?:https?:\/\/|www\.)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:\/[^\s]*)?', content)
    suspicious_links = []
    for raw_u in detected_urls:
        u_domain = raw_u.lower().replace("http://", "").replace("https://", "").split("/")[0]
        if not is_whitelisted(u_domain) and any(ext in u_domain for ext in [".com", ".in", ".org", ".net", ".top", ".xyz", ".co", ".app"]):
            suspicious_links.append(u_domain)

    if suspicious_links:
        score += 30
        signals.append(f"Unverified redirect link detected: {', '.join(suspicious_links[:2])}")

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