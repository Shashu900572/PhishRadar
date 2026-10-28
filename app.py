import math
import re
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

app = FastAPI(title="PhishRadar", version="3.5")

class URLRequest(BaseModel):
    url: str

def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    for x in set(text):
        p_x = float(text.count(x)) / length
        entropy += -p_x * math.log2(p_x)
    return entropy

@app.post("/api/analyze")
async def analyze_url(data: URLRequest):
    url = data.url
    risk_score = 15
    indicators = []

    # 1. Check for IP address binding
    if re.search(r'https?://(?:\d{1,3}\.){3}\d{1,3}', url):
        risk_score += 45
        indicators.append("⚠️ Direct IP address detected instead of domain name")

    # 2. Check for brand / fintech impersonation keywords
    keywords = ['login', 'verify', 'update', 'account', 'banking', 'secure', 'signin', 'auth', 'support']
    found = [kw for kw in keywords if kw in url.lower()]
    if found:
        risk_score += 30
        indicators.append(f"⚠️ High-Value Brand/Fintech Impersonation token detected ({', '.join(found)})")

    # 3. Check domain randomness (Entropy)
    entropy = calculate_entropy(url)
    if entropy > 4.0:
        risk_score += 25
        indicators.append(f"⚠️ High domain randomness (Entropy: {entropy:.2f})")

    final_risk = min(risk_score, 99)
    verdict = "MALICIOUS / PHISHING" if final_risk >= 50 else "SAFE / LEGITIMATE"
    status_class = "danger" if final_risk >= 50 else "safe"

    return {
        "url": url,
        "risk_percentage": final_risk,
        "verdict": verdict,
        "status_class": status_class,
        "indicators": indicators if indicators else ["✅ No suspicious heuristics found"]
    }

# Exact UI Interface matching your screenshot design
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PhishRadar - Modality 1: URL Vector Analysis</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        body { background-color: #070913; color: #ffffff; display: flex; justify-content: center; align-items: center; min-height: 100vh; padding: 16px; }
        .card { background: #0f172a; border: 1px solid #1e293b; border-radius: 20px; width: 100%; max-width: 440px; padding: 24px; box-shadow: 0 20px 40px rgba(0,0,0,0.6); }
        .matrix-banner { width: 100%; height: 150px; background: linear-gradient(135deg, #022c22, #064e3b); border-radius: 12px; display: flex; align-items: center; justify-content: center; overflow: hidden; margin-bottom: 20px; border: 1px solid #059669; position: relative; }
        .matrix-grid { width: 100%; height: 100%; background: repeating-linear-gradient(0deg, rgba(52, 211, 153, 0.15) 0px, rgba(52, 211, 153, 0.15) 1px, transparent 1px, transparent 15px); display: flex; align-items: center; justify-content: center; }
        .matrix-text { color: #34d399; font-family: monospace; font-size: 13px; text-align: center; font-weight: bold; text-shadow: 0 0 8px rgba(52,211,153,0.6); }
        .header-row { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 16px; }
        h1 { font-size: 18px; font-weight: 700; color: #f8fafc; margin-bottom: 6px; }
        p { font-size: 12px; color: #94a3b8; line-height: 1.4; }
        .risk-badge { background: rgba(239, 68, 68, 0.2); border: 1px solid #ef4444; color: #fca5a5; padding: 6px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; text-align: center; white-space: nowrap; }
        .risk-safe { background: rgba(16, 185, 129, 0.2) !important; border-color: #10b981 !important; color: #6ee7b7 !important; }
        .input-box { width: 100%; background: #020617; border: 1px solid #334155; border-radius: 12px; padding: 12px 16px; color: white; font-size: 13px; margin-bottom: 16px; outline: none; }
        .input-box:focus { border-color: #3b82f6; }
        .btn { width: 100%; background: #2563eb; color: white; border: none; padding: 14px; border-radius: 12px; font-size: 14px; font-weight: 600; cursor: pointer; transition: background 0.2s; margin-bottom: 16px; box-shadow: 0 4px 12px rgba(37,99,235,0.3); }
        .btn:hover { background: #1d4ed8; }
        .alert-box { background: rgba(245, 158, 11, 0.1); border: 1px solid #f59e0b; color: #fcd34d; padding: 12px; border-radius: 10px; font-size: 12px; margin-bottom: 10px; display: flex; align-items: center; gap: 8px; }
        .safe-box { background: rgba(16, 185, 129, 0.1); border: 1px solid #10b981; color: #6ee7b7; padding: 12px; border-radius: 10px; font-size: 12px; margin-bottom: 10px; }
        .nav-row { display: flex; justify-content: space-between; margin-top: 20px; border-top: 1px solid #1e293b; padding-top: 16px; }
        .nav-btn { background: #1e293b; color: #cbd5e1; border: 1px solid #334155; padding: 8px 16px; border-radius: 8px; font-size: 12px; cursor: pointer; text-decoration: none; }
        .nav-btn:hover { background: #334155; color: white; }
    </style>
</head>
<body>

    <div class="card">
        <div class="matrix-banner">
            <div class="matrix-grid">
                <div class="matrix-text">🟢 MATRIX STREAM ACTIVE<br/>[Entropy & Threat Vector Scanner]</div>
            </div>
        </div>

        <div class="header-row">
            <div>
                <h1>Modality 1: URL Vector Analysis</h1>
                <p>Inspect domain entropy, direct IP binding, and typosquatting tokens</p>
            </div>
            <div id="riskBadge" class="risk-badge">Risk: 70%</div>
        </div>

        <input type="text" id="urlInput" class="input-box" value="https://www.instagram.com/accounts/login/?hl=" />

        <button class="btn" onclick="analyzeUrl()">Analyze Domain Vector</button>

        <div id="resultsContainer">
            <div class="alert-box">⚠️ High-Value Brand/Fintech Impersonation token detected</div>
            <div class="alert-box">⚠️ High domain randomness (Entropy: 4.21)</div>
        </div>

        <div class="nav-row">
            <a href="#" class="nav-btn">← Home</a>
            <a href="#" class="nav-btn">Next: Text/SMS →</a>
        </div>
    </div>

    <script>
        async function analyzeUrl() {
            const url = document.getElementById('urlInput').value;
            const container = document.getElementById('resultsContainer');
            const badge = document.getElementById('riskBadge');
            
            container.innerHTML = '<div class="alert-box">🔍 Analyzing vector components...</div>';

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

                let html = `<div style="font-weight:700; margin-bottom:8px; color:${data.status_class === 'safe' ? '#34d399' : '#f87171'}">Verdict: ${data.verdict}</div>`;
                data.indicators.forEach(ind => {
                    html += `<div class="${data.status_class === 'safe' ? 'safe-box' : 'alert-box'}">${ind}</div>`;
                });
                container.innerHTML = html;
            } catch (err) {
                container.innerHTML = '<div class="alert-box">❌ Error connecting to server.</div>';
            }
        }
    </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
async def serve_index():
    return HTML_TEMPLATE