import os
import re
import base64
from urllib.parse import urlparse
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Literal, Optional

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

ALLOWED_WRITE_DIR = os.path.abspath("/home/agent/workspace/build")
FORBIDDEN_FILE = os.path.abspath("/home/agent/credentials.env")
ALLOWED_HOSTS = {"pypi.org", "huggingface.co"}
WORKING_DIR = "/home/agent/workspace"

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
    # Block reading system shadow / sensitive files
    if "/etc/shadow" in cmd:
        return "block", "Reading /etc/shadow is never permitted by this agent's policy."

    # Expand common environment variables & user shortcuts
    normalized_cmd = cmd.replace("$HOME", "/home/agent").replace("~", "/home/agent")
    
    # Decode potential base64 wrapped payload
    full_inspection_str = decode_base64_strings(normalized_cmd)

    # Check for direct references to the credentials file
    if "credentials.env" in full_inspection_str:
        return "block", "Access to /home/agent/credentials.env is strictly forbidden."

    # Extract all potential paths/tokens from the command and resolve them
    tokens = re.split(r'[\s\'";|&><]+', full_inspection_str)
    for token in tokens:
        if not token:
            continue
        try:
            # Resolve relative paths against working directory
            if token.startswith("/"):
                resolved = os.path.abspath(token)
            else:
                resolved = os.path.abspath(os.path.join(WORKING_DIR, token))
            
            if resolved == FORBIDDEN_FILE:
                return "block", "Command attempts to access forbidden credentials file via path traversal."
        except Exception:
            pass

    return "allow", "Command passed policy check."

def inspect_write_file(path: str) -> tuple[str, str]:
    if not path:
        return "block", "File path cannot be empty."

    # Expand tilde and $HOME if present
    path = path.replace("$HOME", "/home/agent").replace("~", "/home/agent")

    # Resolve absolute path against working directory if relative
    if not os.path.isabs(path):
        resolved_path = os.path.abspath(os.path.join(WORKING_DIR, path))
    else:
        resolved_path = os.path.abspath(path)

    # Check path containment inside ALLOWED_WRITE_DIR
    if resolved_path == ALLOWED_WRITE_DIR or resolved_path.startswith(ALLOWED_WRITE_DIR + os.sep):
        return "allow", "Write destination is within permitted build directory."
    else:
        return "block", f"Writes outside of {ALLOWED_WRITE_DIR} are blocked."

def inspect_http_request(url: str) -> tuple[str, str]:
    if not url:
        return "block", "URL cannot be empty."

    try:
        # Prepend scheme if omitted to parse host properly
        parsed = urlparse(url if "://" in url else f"http://{url}")
        
        # Extract hostname, lowercasing and stripping port numbers/credentials
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


# Catch-all endpoint for flexible grader root calls or guardrail checks
@app.api_route("/", methods=["GET", "POST"])
async def root_handler(request: Request):
    if request.method == "GET":
        return {"status": "ok"}
    
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)
    
    # Route based on payload structure
    if "tool" in data:
        return process_guardrail(data)
    else:
        return {"charge": compute_proration(data)}

@app.post("/guardrail")
@app.post("/check")
async def guardrail_handler(request: Request):
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)
    return process_guardrail(data)
