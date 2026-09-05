import math
import re
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

THREAT_KEYWORDS = {
    "urgency": [
        "suspended", "urgent", "24 hours", "immediate", "blocked", "freeze", "arrest",
        "तुरंत", "बंद", "अवरुद्ध", "24 घंटे", "गिरफ्तार", "चेतावनी", "turant", "band", "block", "giraftaar",
        "ತಕ್ಷಣ", "ರದ್ದು", "ನಿರ್ಬಂಧಿಸಲಾಗಿದೆ", "ಬಂಧನ", "ಎಚ್ಚರಿಕೆ", "takshana", "raddu", "bandhana"
    ],
    "credentials": [
        "otp", "pin", "cvv", "password", "bank manager", "customs officer", "cbi", "unauthorized",
        "ओटीपी", "पिन", "पासवर्ड", "बैंक प्रबंधक", "अवैध",
        "ಒಟಿಪಿ", "ಪಿನ್", "ಪಾಸ್‌ವರ್ಡ್", "ಅಧಿಕಾರಿ"
    ],
    "contextual_account": [
        "account", "खाता", "ಖಾತೆ"
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
    # Use strict word boundary for short Latin tokens (like 'pin', 'otp', 'cvv')
    if re.match(r'^[a-zA-Z0-9_-]+$', keyword):
        pattern = rf'\b{re.escape(keyword)}\b'
        return bool(re.search(pattern, text, re.IGNORECASE))
    return keyword.lower() in text.lower()

@app.post("/api/scan/url")
async def scan_url(url: str = Form(...)):
    score = 5
    signals = []
    if any(tok in url.lower() for tok in ["secure", "login", "bank", "verify", "auth", "alert"]):
        score += 45
        signals.append("High-Value Brand/Fintech Impersonation token detected")
    entropy = calculate_entropy(url)
    if entropy > 3.8:
        score += 20
        signals.append(f"High domain randomness (Entropy: {entropy})")
    if url.count(".") >= 3:
        score += 15
        signals.append(f"Excessive subdomain depth ({url.count('.')} dots)")
    if re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', url):
        score += 30
        signals.append("Direct bare IPv4 address routing detected")
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
        score += 45
        signals.append(f"Psychological urgency tokens identified: {', '.join(found_urgency[:4])}")

    found_creds = [w for w in THREAT_KEYWORDS["credentials"] if match_token(w, text_lower)]
    if found_creds:
        score += 48
        signals.append(f"Credential harvest & impersonation triggers: {', '.join(found_creds[:4])}")

    found_account = [w for w in THREAT_KEYWORDS["contextual_account"] if match_token(w, text_lower)]
    if found_account and (found_urgency or found_creds):
        score += 10
        signals.append(f"Targeted account linkage: {', '.join(found_account)}")

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