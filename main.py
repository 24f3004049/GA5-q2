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

def calculate_charge(payload: ProrateRequest):
    price_delta = payload.new_price - payload.old_price
    
    if payload.spec == "v1":
        charge = price_delta * (payload.days_remaining / 30.0)
    elif payload.spec == "v2":
        if payload.days_in_actual_month == 0:
            raise HTTPException(status_code=400, detail="days_in_actual_month cannot be zero")
        charge = price_delta * (payload.days_remaining / payload.days_in_actual_month)
    else:
        raise HTTPException(status_code=400, detail="Invalid spec version")

    return {"charge": round(charge, 2)}

# Support POST to both root '/' and '/prorate'
@app.post("/")
def prorate_root(payload: ProrateRequest):
    return calculate_charge(payload)

@app.post("/prorate")
def prorate_path(payload: ProrateRequest):
    return calculate_charge(payload)
