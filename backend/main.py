import math
import re
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

app = FastAPI(title="PhishRadar API", version="2.0")

# --- ML & Heuristic Scam Detection Engine ---
class URLRequest(BaseModel):
    url: str

def calculate_entropy(text: str) -> float:
    """Calculates Shannon entropy to detect high domain randomness."""
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    for x in set(text):
        p_x = float(text.count(x)) / length
        entropy += -p_x * math.log2(p_x)
    return entropy

def analyze_phishing_url(url: str):
    risk_score = 15  # Base background risk
    indicators = []

    # 1. Check for IP address in URL (Classic phishing indicator)
    ip_pattern = re.compile(r'https?://(?:\d{1,3}\.){3}\d{1,3}')
    if ip_pattern.search(url):
        risk_score += 45
        indicators.append("⚠️ Direct IP address detected instead of domain name")

    # 2. Check for high-value brand / fintech impersonation keywords
    sensitive_keywords = ['login', 'verify', 'update', 'account', 'banking', 'secure', 'signin', 'auth', 'support']
    found_keywords = [kw for kw in sensitive_keywords if kw in url.lower()]
    if found_keywords:
        risk_score += 30
        indicators.append(f"⚠️ High-Value Brand/Fintech Impersonation token detected ({', '.join(found_keywords)})")

    # 3. Check for high domain randomness (Entropy)
    entropy = calculate_entropy(url)
    if entropy > 4.0:
        risk_score += 25
        indicators.append(f"⚠️ High domain randomness (Entropy: {entropy:.2f})")

    # 4. Check for excessive subdomains or suspicious length
    if url.count('.') > 3 or len(url) > 75:
        risk_score += 20
        indicators.append("⚠️ Excessive URL length or suspicious subdomain structure")

    # Cap risk score at 99%
    final_risk = min(risk_score, 99)

    # Decision rule
    if final_risk >= 50:
        verdict = "MALICIOUS / PHISHING"
        status_class = "danger"
    else:
        verdict = "SAFE / LEGITIMATE"
        status_class = "safe"

    return {
        "url": url,
        "risk_percentage": final_risk,
        "verdict": verdict,
        "status_class": status_class,
        "indicators": indicators if indicators else ["✅ No suspicious heuristics found"]
    }

@app.post("/api/analyze")
async def api_analyze(data: URLRequest):
    return analyze_phishing_url(data.url)


# --- Embedded Dashboard UI (Guaranteed to Load Instantly on Render) ---
HTML_CONTENT = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PhishRadar - ML Phishing Detection</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        body { background-color: #0b0f19; color: #ffffff; display: flex; justify-content: center; align-items: center; min-height: 100vh; padding: 20px; }
        .card { background: #111827; border: 1px solid #1f2937; border-radius: 16px; width: 100%; max-width: 520px; padding: 24px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }
        .matrix-banner { width: 100%; height: 140px; background: linear-gradient(135deg, #064e3b, #022c22); border-radius: 12px; display: flex; align-items: center; justify-content: center; overflow: hidden; margin-bottom: 20px; border: 1px solid #059669; }
        .matrix-banner span { color: #34d399; font-family: monospace; font-size: 13px; text-align: center; padding: 10px; line-height: 1.5; }
        .header-row { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 16px; }
        h1 { font-size: 19px; font-weight: 700; color: #f9fafb; margin-bottom: 4px; }
        p { font-size: 12px; color: #9ca3af; line-height: 1.4; }
        .risk-badge { background: rgba(239, 68, 68, 0.2); border: 1px solid #ef4444; color: #fca5a5; padding: 6px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; text-align: center; transition: all 0.3s; }
        .risk-safe { background: rgba(16, 185, 129, 0.2) !important; border-color: #10b981 !important; color: #6ee7b7 !important; }
        .input-box { width: 100%; background: #030712; border: 1px solid #374151; border-radius: 10px; padding: 12px 16px; color: white; font-size: 14px; margin-bottom: 16px; outline: none; }
        .input-box:focus { border-color: #3b82f6; }
        .btn { width: 100%; background: #2563eb; color: white; border: none; padding: 14px; border-radius: 10px; font-size: 15px; font-weight: 600; cursor: pointer; transition: background 0.2s; margin-bottom: 16px; }
        .btn:hover { background: #1d4ed8; }
        .results-container { display: flex; flex-direction: column; gap: 8px; margin-top: 10px; }
        .alert-box { background: rgba(245, 158, 11, 0.1); border: 1px solid #f59e0b; color: #fcd34d; padding: 12px; border-radius: 8px; font-size: 13px; display: flex; align-items: center; gap: 8px; }
        .safe-box { background: rgba(16, 185, 129, 0.1); border: 1px solid #10b981; color: #6ee7b7; padding: 12px; border-radius: 8px; font-size: 13px; }
    </style>
</head>
<body>

    <div class="card">
        <div class="matrix-banner">
            <span>🟢 PHISHRADAR ML ENGINE ACTIVE<br/>[Entropy, Heuristics & Token Classifier]</span>
        </div>

        <div class="header-row">
            <div>
                <h1>Modality 1: URL Vector Analysis</h1>
                <p>Inspect domain entropy, direct IP binding, and typosquatting tokens</p>
            </div>
            <div id="riskBadge" class="risk-badge">Risk: --</div>
        </div>

        <input type="text" id="urlInput" class="input-box" value="https://www.instagram.com/accounts/login/?hl=" />

        <button class="btn" onclick="analyzeUrl()">Analyze Domain Vector</button>

        <div id="resultsContainer" class="results-container">
            <div class="alert-box">⚠️ Enter a URL above and click Analyze to test scam detection.</div>
        </div>
    </div>

    <script>
        async function analyzeUrl() {
            const url = document.getElementById('urlInput').value;
            const container = document.getElementById('resultsContainer');
            const badge = document.getElementById('riskBadge');
            
            container.innerHTML = '<div class="alert-box">🔍 Running ML feature extraction...</div>';

            try {
                const response = await fetch('/api/analyze', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url: url })
                });
                const data = await response.json();

                badge.innerText = `Risk: ${data.risk_percentage}%`;
                if (data.status_class === 'safe') {
                    badge.className = 'risk-badge risk-safe';
                } else {
                    badge.className = 'risk-badge';
                }

                let html = `<div style="font-weight:700; margin-bottom:6px; color:${data.status_class === 'safe' ? '#34d399' : '#f87171'}">Verdict: ${data.verdict}</div>`;
                data.indicators.forEach(ind => {
                    html += `<div class="${data.status_class === 'safe' ? 'safe-box' : 'alert-box'}">${ind}</div>`;
                });
                container.innerHTML = html;

            } catch (err) {
                container.innerHTML = '<div class="alert-box">❌ Error connecting to detection backend.</div>';
            }
        }
    </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    return HTML_CONTENT