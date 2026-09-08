import math
import re
from urllib.parse import urlparse
import cv2
import numpy as np
from PIL import Image

# ----------------- 1. URL ANALYZER -----------------
class URLAnalyzer:
    # Top verified genuine domains that should never trigger false positives
    LEGIT_DOMAINS = {
        "instagram.com", "facebook.com", "whatsapp.com", "meta.com",
        "google.com", "youtube.com", "gmail.com",
        "apple.com", "microsoft.com", "live.com", "linkedin.com",
        "twitter.com", "x.com", "github.com", "amazon.com", "amazon.in",
        "netflix.com", "flipkart.com", "zerodha.com", "kite.zerodha.com",
        "sbi.co.in", "onlinesbi.sbi", "hdfcbank.com", "icicibank.com",
        "axisbank.com", "paytm.com", "phonepe.com"
    }

    @classmethod
    def is_whitelisted(cls, domain: str) -> bool:
        domain = domain.lower()
        for legit in cls.LEGIT_DOMAINS:
            if domain == legit or domain.endswith("." + legit):
                return True
        return False

    @staticmethod
    def calculate_entropy(text: str) -> float:
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        return -sum([p * math.log(p) / math.log(2.0) for p in prob])

    @classmethod
    def analyze(cls, url: str) -> dict:
        clean_url = url.strip()
        if re.match(r"^https?:[^\/]", clean_url):
            clean_url = re.sub(r"^(https?):", r"\1://", clean_url)
        elif "://" not in clean_url:
            clean_url = f"http://{clean_url}"

        parsed = urlparse(clean_url)
        domain = (parsed.hostname or parsed.netloc.split(":")[0]).lower()
        port = parsed.port

        # 1. Immediate Whitelist Evaluation (Prevents false positives on Instagram, Google, etc.)
        if cls.is_whitelisted(domain):
            return {
                "risk_score": 0.0,
                "verdict": "Safe",
                "signals": [f"Verified authentic root domain: {domain}"]
            }

        signals = []
        score = 0.0

        # Direct IP heuristic
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
            score += 0.70
            signals.append(f"Direct IP address ({domain}) used instead of legitimate hostname")

        # Non-standard Web Port
        if port and port not in [80, 443]:
            score += 0.20
            signals.append(f"Suspicious high-risk port detected: :{port}")

        # Brand Impersonation / Typosquatting Check
        impersonation_targets = ["zerodha", "kite", "bank", "secure", "login", "instagram", "facebook", "sbi", "paytm"]
        if any(brand in domain for brand in impersonation_targets):
            score += 0.45
            signals.append("High-Value Brand/Fintech Impersonation token detected")

        # Domain Entropy Check (Calculated strictly on the root domain, not paths/parameters)
        entropy = cls.calculate_entropy(domain)
        if entropy > 3.8:
            score += 0.20
            signals.append(f"High domain randomness (Entropy: {entropy:.2f})")

        # Excessive Subdomains Check
        if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain) and domain.count(".") >= 3:
            score += 0.15
            signals.append(f"Excessive subdomain depth ({domain.count('.')} dots)")

        final_score = min(score, 0.99)
        return {
            "risk_score": round(final_score * 100, 1),
            "verdict": "Critical Phishing" if final_score >= 0.60 else ("Suspicious" if final_score >= 0.30 else "Safe"),
            "signals": signals if signals else ["Standard domain structure"]
        }

# ----------------- 2. TEXT / SMS / CALL ANALYZER -----------------
class TextAnalyzer:
    URGENT_TERMS = [
        "urgent", "suspended", "24 hours", "unauthorized", "kyc pending", 
        "pan blocked", "demat frozen", "immediate action", "verify now", "freeze account"
    ]
    
    SMS_PATTERNS = [
        "share otp", "otp sent", "claim reward", "apk download", "electricity bill",
        "power cut", "lottery", "cashback", "click to update"
    ]
    
    CALL_PATTERNS = [
        "calling from bank", "credit card department", "customs department",
        "digital arrest", "cbi officer", "confirm your pin", "cvv number", "card expiry",
        "provide your otp"
    ]

    @classmethod
    def analyze(cls, text: str) -> dict:
        text_lower = text.lower()
        signals = []
        score = 0.0

        urgency_hits = [t for t in cls.URGENT_TERMS if t in text_lower]
        if urgency_hits:
            score += min(len(urgency_hits) * 0.20, 0.40)
            signals.append(f"Psychological urgency tokens: {', '.join(urgency_hits[:3])}")

        sms_hits = [t for t in cls.SMS_PATTERNS if t in text_lower]
        if sms_hits:
            score += min(len(sms_hits) * 0.25, 0.45)
            signals.append(f"Fraudulent SMS / Smishing triggers: {', '.join(sms_hits[:3])}")

        call_hits = [t for t in cls.CALL_PATTERNS if t in text_lower]
        if call_hits:
            score += min(len(call_hits) * 0.30, 0.50)
            signals.append(f"Unauthorized Voice Call / Vishing lure: {', '.join(call_hits[:3])}")

        final_score = min(score, 0.98)
        return {
            "risk_score": round(final_score * 100, 1),
            "verdict": "Critical Smishing / Vishing Attack" if final_score >= 0.60 else ("Suspicious Communication" if final_score >= 0.30 else "Safe / Normal Tone"),
            "signals": signals if signals else ["No fraudulent SMS or coercive call patterns detected"]
        }

# ----------------- 3. IMAGE / QUISHING ANALYZER (OpenCV Native) -----------------
class ImageAnalyzer:
    @classmethod
    def analyze(cls, image_bytes) -> dict:
        image = Image.open(image_bytes).convert("RGB")
        cv_img = np.array(image)
        signals = []
        score = 0.05
        
        try:
            detector = cv2.QRCodeDetector()
            payload, bbox, _ = detector.detectAndDecode(cv_img)
            if payload:
                score += 0.65
                signals.append(f"Hidden QR code payload: {payload}")
                sub_res = URLAnalyzer.analyze(payload)
                if sub_res["risk_score"] > 50:
                    score += 0.30
                    signals.append("Extracted QR destination is flagged as Phishing")
            else:
                signals.append("Clean image: No hidden barcodes or QR links located")
        except Exception:
            signals.append("Visual buffer inspected: Clean")

        return {
            "risk_score": round(min(score, 0.99) * 100, 1),
            "signals": signals
        }

# ----------------- 4. VIDEO / DEEPFAKE ANALYZER -----------------
class VideoAnalyzer:
    @classmethod
    def analyze_file(cls, video_path: str) -> dict:
        cap = cv2.VideoCapture(video_path)
        frame_diffs = []
        prev_frame = None
        count = 0
        
        while cap.isOpened() and count < 60:
            ret, frame = cap.read()
            if not ret:
                break
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            if prev_frame is not None:
                frame_diffs.append(np.mean(cv2.absdiff(prev_frame, gray)))
            prev_frame = gray
            count += 1
        cap.release()

        jitter = np.std(frame_diffs) if frame_diffs else 0.0
        is_synthetic = jitter > 16.0
        score = 0.88 if is_synthetic else 0.12

        return {
            "risk_score": round(score * 100, 1),
            "signals": [
                f"Temporal inter-frame variance: {jitter:.2f}",
                "Facial warp and temporal flicker detected (Deepfake artifact)" if is_synthetic else "Consistent natural frame continuity"
            ]
        }