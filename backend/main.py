
from fastapi import FastAPI, HTTPException, Request, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import urllib.parse
import httpx
from bs4 import BeautifulSoup
import re
import math

app = FastAPI(title="PhishRadar Security Engine")

# CORS Middleware for frontend-backend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Threat Dictionaries & Whitelists ---
LEGIT_DOMAINS = {
    "google.com", "microsoft.com", "github.com", "zerodha.com", 
    "apple.com", "amazon.com", "netflix.com", "paypal.com"
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly", "adf.ly"
}

THREAT_KEYWORDS = {
    "urgency": ["suspended", "verify now", "24 hours", "expired", "urgent", "action required", "immediate login"],
    "financial": ["otp", "kyc", "cvv", "tax refund", "lottery", "bank update", "credit card", "wallet blocked"]
}

# --- Pydantic Models ---
class URLPayload(BaseModel):
    url: str

class TextPayload(BaseModel):
    text: str

class LoginPayload(BaseModel):
    username: str
    password: str

class SignupPayload(BaseModel):
    username: str
    password: str

# --- User Database for Authentication ---
USERS_DB = {
    "shashank": "password123"
}

# --- Signup Endpoint ---
@app.post("/api/signup")
async def signup(payload: SignupPayload):
    if payload.username in USERS_DB:
        raise HTTPException(status_code=400, detail="Username already exists!")
    if not payload.username or not payload.password:
        raise HTTPException(status_code=400, detail="Fields cannot be empty!")
    
    USERS_DB[payload.username] = payload.password
    return {"success": True, "message": "User registered successfully"}

# --- Login Endpoint ---
@app.post("/api/login")
async def login(payload: LoginPayload):
    if payload.username in USERS_DB and USERS_DB[payload.username] == payload.password:
        return {
            "success": True, 
            "message": "Login successful", 
            "token": "phishradar-session-token-xyz"
        }
    raise HTTPException(status_code=401, detail="Invalid username or password")

# --- Shannon Entropy Calculation for URL Randomness ---
def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    entropy = 0
    length = len(text)
    for x in set(text):
        p_x = text.count(x) / length
        entropy += - p_x * math.log2(p_x)
    return entropy

# --- Phase 2 Live DOM Crawler Helper ---
async def perform_phase2_dom_scan(url: str, hostname: str):
    score_addition = 0
    signals = []
    try:
        async with httpx.AsyncClient(timeout=5.0, follow_redirects=True) as client:
            response = await client.get(url)
            html_content = response.text
            
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Check form action attributes for external credential theft
        for form in soup.find_all('form'):
            action = form.get('action', '')
            if action and not action.startswith('#') and hostname not in action:
                score_addition += 35
                signals.append("Insecure form action pointing to external domain")
                
        # Check for hidden iframes (clickjacking)
        if len(soup.find_all('iframe')) > 2:
            score_addition += 20
            signals.append("Multiple hidden iframe elements detected")
            
    except Exception:
        signals.append("DOM crawler failed to reach live target page")
        
    return score_addition, signals

# --- URL Scan Endpoint (Phase 1 & Phase 2) ---
@app.post("/api/scan/url")
async def scan_url(payload: URLPayload):
    url = payload.url
    score = 0
    signals = []
    
    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname or ""
    
    # 1. Whitelist Check
    if any(hostname.endswith(domain) for domain in LEGIT_DOMAINS):
        return {"risk_score": 0.0, "signals": ["Trusted whitelisted domain"]}
        
    # 2. Shortener Check
    if hostname in SHORTENERS:
        score += 55
        signals.append("Detected known URL shortener service")
        
    # 3. High-risk TLD Check
    if hostname.endswith((".xyz", ".top", ".info", ".ru", ".cn", ".buzz")):
        score += 35
        signals.append("High-risk top-level domain detected")
        
    # 4. Lexical Entropy Check
    entropy = calculate_entropy(hostname)
    if entropy > 4.2:
        score += 25
        signals.append(f"High string entropy detected ({entropy:.2f}), possible randomized phishing domain")

    # 5. Phase 2: Live DOM Crawler Trigger if ambiguous score zone
    if 10 <= score <= 75:
        dom_score, dom_signals = await perform_phase2_dom_scan(url, hostname)
        score += dom_score
        signals.extend(dom_signals)
        
    return {"risk_score": min(score, 99.0), "signals": signals}

# --- Text & SMS Scan Endpoint ---
@app.post("/api/scan/text")
async def scan_text(payload: TextPayload):
    text = payload.text.lower()
    score = 0
    signals = []
    
    # Scan for urgency triggers using regex word boundaries
    for word in THREAT_KEYWORDS["urgency"]:
        if re.search(r'\b' + re.escape(word) + r'\b', text):
            score += 25
            signals.append(f"Urgency trigger detected: '{word}'")
            
    # Scan for financial and credential scam triggers
    for word in THREAT_KEYWORDS["financial"]:
        if re.search(r'\b' + re.escape(word) + r'\b', text):
            score += 30
            signals.append(f"Financial/credential trigger detected: '{word}'")
            
    # Check for malicious APK links in text
    if ".apk" in text:
        score += 50
        signals.append("Android application package (.apk) installation payload detected")
        
    return {"risk_score": min(score, 99.0), "signals": signals}

# --- WhatsApp Webhook Verification & Receiver ---
@app.get("/api/webhook/whatsapp")
async def verify_whatsapp_webhook(
    hub_mode: str = Query(None, alias="hub.mode"),
    hub_verify_token: str = Query(None, alias="hub.verify_token"),
    hub_challenge: str = Query(None, alias="hub.challenge")
):
    VERIFY_TOKEN = "phishradar_secure_token_123"
    if hub_mode == "subscribe" and hub_verify_token == VERIFY_TOKEN:
        return Response(content=hub_challenge, media_type="text/plain", status_code=200)
    raise HTTPException(status_code=403, detail="Verification token mismatch")

@app.post("/api/webhook/whatsapp")
async def receive_whatsapp_message(request: Request):
    body = await request.json()
    print(f"📥 WhatsApp Webhook Payload Received: {body}")
    return {"status": "whatsapp_received"}

# --- Email Webhook Receiver ---
@app.post("/api/webhook/email")
async def receive_incoming_email(request: Request):
    form_data = await request.form()
    sender = form_data.get("from", "Unknown Sender")
    subject = form_data.get("subject", "No Subject")
    print(f"📧 Live Email Received from {sender} | Subject: {subject}")
    return {"status": "email_analyzed", "sender": sender, "subject": subject}

# --- Call / Audio Webhook Receiver ---
@app.post("/api/webhook/call")
async def receive_call_recording(request: Request):
    body = await request.json()
    call_sid = body.get("CallSid", "unknown_call")
    recording_url = body.get("RecordingUrl", "")
    print(f"🎙️ Live Call Recording Webhook | Call ID: {call_sid} | Audio URL: {recording_url}")
    return {"status": "call_audio_received", "call_id": call_sid}

# --- Mount Frontend Static Files ---
app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")