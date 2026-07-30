import os
import re
import base64
import urllib.parse
from urllib.parse import urlparse
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Literal

app = FastAPI()

# ==========================================
# QUESTION 1: PRORATION CALCULATOR (v1 & v2)
# ==========================================

class ProrateRequest(BaseModel):
    old_price: float
    new_price: float
    days_remaining: int
    days_in_actual_month: int
    spec: Literal["v1", "v2"]

def compute_proration(payload: dict) -> float:
    old_price = float(payload.get("old_price", 0))
    new_price = float(payload.get("new_price", 0))
    days_remaining = float(payload.get("days_remaining", 0))
    
    days_in_actual_month = float(
        payload.get("days_in_actual_month") or payload.get("days_in_month", 30)
    )
    spec = str(payload.get("spec", "v2")).strip().lower()
    price_delta = new_price - old_price

    if spec == "v1":
        raw_charge = price_delta * (days_remaining / 30.0)
    elif spec == "v2":
        if days_in_actual_month == 0:
            raw_charge = 0.0
        else:
            raw_charge = price_delta * (days_remaining / days_in_actual_month)
    else:
        raw_charge = price_delta * (days_remaining / days_in_actual_month)

    return round(raw_charge + 1e-9, 2)

@app.api_route("/prorate", methods=["GET", "POST"])
async def prorate_handler(request: Request):
    if request.method == "GET":
        return {"status": "ok"}
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)
    return {"charge": compute_proration(data)}


# ==========================================
# QUESTION 2: GUARDRAIL HOOK (SECURITY POLICY)
# ==========================================

ALLOWED_WRITE_DIR = os.path.normpath("/home/agent/workspace/build")
FORBIDDEN_FILE = os.path.normpath("/home/agent/credentials.env")
ALLOWED_HOSTS = {"pypi.org", "huggingface.co"}
WORKING_DIR = os.path.normpath("/home/agent/workspace")

def sanitize_path(raw_path: str) -> str:
    """Repeatedly URL-decode and strip null bytes/variables to uncover hidden traversals."""
    path = raw_path
    # Decode double/triple URL encoding (e.g. %252e -> %2e -> .)
    for _ in range(3):
        decoded = urllib.parse.unquote(path)
        if decoded == path:
            break
        path = decoded

    # Remove null bytes
    path = path.replace("\x00", "")

    # Expand shell environment variables and tildes
    path = os.path.expandvars(os.path.expanduser(path))
    path = path.replace("$HOME", "/home/agent").replace("~", "/home/agent")
    
    return path

def decode_base64_strings(text: str) -> str:
    """Find and decode base64 chunks in bash commands to inspect hidden payloads."""
    b64_pattern = re.compile(r'(?:[A-Za-z0-9+/]{4}){3,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')
    decoded_text = text
    for match in b64_pattern.findall(text):
        try:
            decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
            if len(decoded) > 3:
                decoded_text += f" {decoded}"
        except Exception:
            pass
    return decoded_text

def inspect_bash_command(cmd: str) -> tuple[str, str]:
    if "/etc/shadow" in cmd:
        return "block", "Reading /etc/shadow is never permitted."

    normalized_cmd = sanitize_path(cmd)
    full_inspection_str = decode_base64_strings(normalized_cmd)

    secret_regex = re.compile(r'(^|[\s/\'"]+)credentials\.env($|[\s/\'"]+)')
    if secret_regex.search(full_inspection_str):
        return "block", "Access to /home/agent/credentials.env is strictly forbidden."

    tokens = re.split(r'[\s\'";|&><]+', full_inspection_str)
    for token in tokens:
        if not token or token.startswith("-"):
            continue
        try:
            if token.startswith("/"):
                resolved = os.path.normpath(token)
            else:
                resolved = os.path.normpath(os.path.join(WORKING_DIR, token))
            
            if resolved == FORBIDDEN_FILE:
                return "block", "Command attempts to access forbidden credentials file."
        except Exception:
            pass

    return "allow", "Command passed policy check."

def inspect_write_file(path: str) -> tuple[str, str]:
    if not path or not path.strip():
        return "block", "File path cannot be empty."

    # Fully sanitize and decode path traversals
    clean_path = sanitize_path(path)

    # Resolve relative paths against working directory
    if not os.path.isabs(clean_path):
        resolved_path = os.path.normpath(os.path.join(WORKING_DIR, clean_path))
    else:
        resolved_path = os.path.normpath(clean_path)

    # Strict containment check using commonpath
    try:
        common = os.path.commonpath([resolved_path, ALLOWED_WRITE_DIR])
        if common == ALLOWED_WRITE_DIR:
            return "allow", "Write destination is within permitted build directory."
    except ValueError:
        pass

    return "block", f"Writes outside of {ALLOWED_WRITE_DIR} are blocked."

def inspect_http_request(url: str) -> tuple[str, str]:
    if not url:
        return "block", "URL cannot be empty."

    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        hostname = (parsed.hostname or "").lower().strip()
        
        if hostname in ALLOWED_HOSTS:
            return "allow", f"Outbound request to allowed host '{hostname}'."
        else:
            return "block", f"Host '{hostname}' is not in the allowed outbound whitelist."
    except Exception:
        return "block", "Invalid or unparseable URL."

def process_guardrail(payload: dict) -> dict:
    tool = payload.get("tool")

    if tool == "bash":
        cmd = payload.get("command", "")
        decision, reason = inspect_bash_command(cmd)
    elif tool == "write_file":
        path = payload.get("path", "")
        decision, reason = inspect_write_file(path)
    elif tool == "http_request":
        url = payload.get("url", "")
        decision, reason = inspect_http_request(url)
    else:
        decision, reason = "block", f"Unknown or missing tool '{tool}'."

    return {"decision": decision, "reason": reason}


# ==========================================
# ROUTING & CATCH-ALL HANDLERS
# ==========================================

@app.api_route("/", methods=["GET", "POST"])
async def root_handler(request: Request):
    if request.method == "GET":
        return {"status": "ok"}
    
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)
    
    if "tool" in data:
        return process_guardrail(data)
    else:
        return {"charge": compute_proration(data)}

@app.api_route("/guardrail", methods=["GET", "POST"])
@app.api_route("/check", methods=["GET", "POST"])
async def guardrail_handler(request: Request):
    if request.method == "GET":
        return {"status": "ok"}
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)
    return process_guardrail(data)
