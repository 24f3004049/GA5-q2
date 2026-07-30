from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

def compute_proration(payload: dict) -> float:
    # 1. Flexible Field Extraction & Robust Type Parsing
    old_price = float(payload.get("old_price", 0))
    new_price = float(payload.get("new_price", 0))
    days_remaining = float(payload.get("days_remaining", 0))
    
    # Check both possible key names for month length just in case
    days_in_actual_month = float(
        payload.get("days_in_actual_month") or payload.get("days_in_month", 30)
    )
    
    # 2. Case and space normalization for spec
    spec = str(payload.get("spec", "v2")).strip().lower()

    # 3. Explicit branching
    price_delta = new_price - old_price

    if spec == "v1":
        raw_charge = price_delta * (days_remaining / 30.0)
    elif spec == "v2":
        if days_in_actual_month == 0:
            raw_charge = 0.0
        else:
            raw_charge = price_delta * (days_remaining / days_in_actual_month)
    else:
        # Fallback to v2 if spec is unrecognized
        raw_charge = price_delta * (days_remaining / days_in_actual_month)

    # 4. Standard float rounding (+ 1e-9 prevents round-to-even discrepancies)
    return round(raw_charge + 1e-9, 2)


@app.api_route("/", methods=["GET", "POST"])
async def root_handler(request: Request):
    if request.method == "GET":
        return {"status": "ok"}
    
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)
        
    charge = compute_proration(data)
    return {"charge": charge}


@app.api_route("/prorate", methods=["GET", "POST"])
async def prorate_handler(request: Request):
    if request.method == "GET":
        return {"status": "ok"}

    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    charge = compute_proration(data)
    return {"charge": charge}
