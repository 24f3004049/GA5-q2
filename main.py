import os
import re
import json
import base64
import hashlib
import urllib.parse
from urllib.parse import urlparse
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Literal

app = FastAPI()

# Config for Question 4 MCP Server
EXAM_EMAIL = "24f3004049@ds.study.iitm.ac.in".strip().lower()

# ======================================================
# QUESTION 1: PRORATION CALCULATOR (v1 & v2)
# ======================================================

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


# ======================================================
# QUESTION 2: GUARDRAIL HOOK (SECURITY POLICY)
# ======================================================

ALLOWED_WRITE_DIR = os.path.normpath("/home/agent/workspace/build")
FORBIDDEN_FILE = os.path.normpath("/home/agent/credentials.env")
ALLOWED_HOSTS = {"pypi.org", "huggingface.co"}
WORKING_DIR = os.path.normpath("/home/agent/workspace")

def sanitize_path(raw_path: str) -> str:
    path = str(raw_path)
    for _ in range(3):
        decoded = urllib.parse.unquote(path)
        if decoded == path:
            break
        path = decoded

    path = path.replace("\x00", "")
    path = path.replace("$HOME", "/home/agent")
    if path == "~" or path.startswith("~/"):
        path = "/home/agent" + path[1:]
    elif "~" in path:
        path = path.replace("~", "/home/agent")
    
    return path

def decode_base64_strings(text: str) -> str:
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
    if not path or not str(path).strip():
        return "block", "File path cannot be empty."

    clean_path = sanitize_path(path)

    if not os.path.isabs(clean_path):
        resolved_path = os.path.normpath(os.path.join(WORKING_DIR, clean_path))
    else:
        resolved_path = os.path.normpath(clean_path)

    try:
        common = os.path.commonpath([resolved_path, ALLOWED_WRITE_DIR])
        if common == ALLOWED_WRITE_DIR:
            return "allow", "Write destination is within permitted build directory."
    except Exception:
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


# ======================================================
# QUESTION 3: RUN-BUDGET & LOOP GUARD (/check)
# ======================================================

IGNORE_KEYS = {"request_id", "requestid", "_request_id", "trace_id", "traceid"}

def canonicalize_arg_value(val):
    if isinstance(val, str):
        return " ".join(val.split())
    elif isinstance(val, dict):
        return {
            k: canonicalize_arg_value(v)
            for k, v in sorted(val.items())
            if k.lower() not in IGNORE_KEYS
        }
    elif isinstance(val, list):
        return [canonicalize_arg_value(x) for x in val]
    else:
        return val

def get_step_signature(step: dict) -> str:
    tool = step.get("tool", "")
    raw_args = step.get("args", {})
    clean_args = canonicalize_arg_value(raw_args)
    return f"{tool}::{json.dumps(clean_args, sort_keys=True)}"

def check_run_control(payload: dict) -> dict:
    budget_tokens = payload.get("budget_tokens", 42000)
    steps = payload.get("steps", [])

    total_tokens = sum(s.get("tokens_used", 0) for s in steps)
    if total_tokens >= budget_tokens:
        return {
            "decision": "halt",
            "reason": f"Cumulative tokens_used ({total_tokens}) has reached or exceeded the budget ({budget_tokens})."
        }

    if len(steps) >= 3:
        signatures = [get_step_signature(s) for s in steps]

        if len(signatures) >= 3:
            last_3 = signatures[-3:]
            if len(set(last_3)) == 1:
                return {
                    "decision": "halt",
                    "reason": f"Detected infinite loop: same tool called 3 consecutive times with functionally identical args."
                }

        if len(signatures) >= 6:
            last_6 = signatures[-6:]
            if (last_6[0] == last_6[2] == last_6[4] and 
                last_6[1] == last_6[3] == last_6[5] and 
                last_6[0] != last_6[1]):
                return {
                    "decision": "halt",
                    "reason": "Detected infinite loop: 2-step alternating cycle repeated 6 times."
                }

    return {
        "decision": "continue",
        "reason": f"Well under budget ({total_tokens}/{budget_tokens}); run is making progress."
    }


# ======================================================
# QUESTION 4: MCP SERVER (MODEL CONTEXT PROTOCOL)
# ======================================================

def compute_challenge_response(challenge: str) -> str:
    s = f"{challenge}:{EXAM_EMAIL}"
    return hashlib.sha256(s.encode('utf-8')).hexdigest()[:16]

async def handle_mcp_request(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}, "id": None}, status_code=400)

    method = body.get("method")
    req_id = body.get("id")

    # 1. MCP initialize handshake
    if method == "initialize":
        return JSONResponse({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "exam-mcp-server",
                    "version": "1.0.0"
                }
            }
        })

    # 2. MCP initialized notification (no id response needed for notifications)
    if method == "notifications/initialized":
        return JSONResponse({"jsonrpc": "2.0", "result": {}}, status_code=200)

    # 3. List Tools
    if method == "tools/list":
        return JSONResponse({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "tools": [
                    {
                        "name": "solve_challenge",
                        "description": "Solves exam challenge using HTTP header challenge token.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {},
                            "required": []
                        }
                    }
                ]
            }
        })

    # 4. Call Tool
    if method == "tools/call":
        params = body.get("params", {})
        tool_name = params.get("name")

        if tool_name == "solve_challenge":
            # Extract challenge from HTTP request header
            challenge = request.headers.get("X-Exam-Challenge") or request.headers.get("x-exam-challenge", "")
            
            # Fallback if header is missing
            if not challenge:
                challenge = params.get("arguments", {}).get("challenge", "")

            response_text = compute_challenge_response(challenge)

            return JSONResponse({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": response_text
                        }
                    ]
                }
            })

        return JSONResponse({
            "jsonrpc": "2.0",
            "error": {"code": -32601, "message": f"Tool '{tool_name}' not found"},
            "id": req_id
        }, status_code=404)

    return JSONResponse({
        "jsonrpc": "2.0",
        "error": {"code": -32601, "message": f"Method '{method}' not found"},
        "id": req_id
    }, status_code=400)

@app.api_route("/mcp", methods=["GET", "POST"])
@app.api_route("/sse", methods=["GET", "POST"])
async def mcp_endpoint(request: Request):
    if request.method == "GET":
        return {"status": "MCP server online"}
    return await handle_mcp_request(request)


# ======================================================
# ROUTING & CATCH-ALL HANDLERS
# ======================================================

@app.api_route("/check", methods=["GET", "POST"])
async def check_handler(request: Request):
    if request.method == "GET":
        return {"status": "ok"}
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)
    return check_run_control(data)

@app.api_route("/guardrail", methods=["GET", "POST"])
async def guardrail_handler(request: Request):
    if request.method == "GET":
        return {"status": "ok"}
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)
    return process_guardrail(data)

@app.api_route("/", methods=["GET", "POST"])
async def root_handler(request: Request):
    if request.method == "GET":
        return {"status": "ok"}
    
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)
    
    # Auto-detect routing based on payload properties
    if "jsonrpc" in data or "method" in data:
        return await handle_mcp_request(request)
    elif "steps" in data or "budget_tokens" in data:
        return check_run_control(data)
    elif "tool" in data:
        return process_guardrail(data)
    else:
        return {"charge": compute_proration(data)}
