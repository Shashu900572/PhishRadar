from fastapi import FastAPI
from fastapi.responses import HTMLResponse

app = FastAPI()

@app.get("/", response_class=HTMLResponse)
def read_root():
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>PhishRadar Dashboard</title>
        <style>
            body { background-color: #0b0f19; color: #ffffff; display: flex; justify-content: center; align-items: center; min-height: 100vh; font-family: sans-serif; }
            .card { background: #111827; border: 1px solid #1f2937; border-radius: 16px; padding: 30px; text-align: center; max-width: 400px; width: 100%; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }
            h1 { font-size: 22px; color: #34d399; margin-bottom: 10px; }
            p { color: #9ca3af; font-size: 14px; }
        </style>
    </head>
    <body>
        <div class="card">
            <h1>PhishRadar Online</h1>
            <p>Modality 1: URL Vector Analysis Active</p>
        </div>
    </body>
    </html>
    """