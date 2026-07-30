# main.py
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Literal

app = FastAPI()

class ProrateRequest(BaseModel):
    old_price: float
    new_price: float
    days_remaining: int
    days_in_actual_month: int
    spec: Literal["v1", "v2"]

@app.get("/")
def health_check():
    return {"status": "ok"}

@app.post("/prorate")
def calculate_proration(payload: ProrateRequest):
    price_delta = payload.new_price - payload.old_price
    
    if payload.spec == "v1":
        # Legacy rule: Always divide by 30
        charge = price_delta * (payload.days_remaining / 30.0)
    elif payload.spec == "v2":
        # Corrected rule: Divide by actual days in the month
        if payload.days_in_actual_month == 0:
            raise HTTPException(status_code=400, detail="days_in_actual_month cannot be zero")
        charge = price_delta * (payload.days_remaining / payload.days_in_actual_month)
    else:
        raise HTTPException(status_code=400, detail="Invalid spec version")

    # Round to 2 decimal places to satisfy tolerance requirement
    return {"charge": round(charge, 2)}
