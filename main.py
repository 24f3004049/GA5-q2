import calendar
from fastapi import FastAPI, Request
app = FastAPI()

@app.post("/prorate")
async def prorate(req: Request):
    b = await req.json()
    old, new = b["old_price"], b["new_price"]          # match the real field names
    year, month, day = b["year"], b["month"], b["upgrade_day"]
    dim = calendar.monthrange(year, month)[1]
    remaining = dim - day + 1
    charge = round((new - old) * (remaining / dim), 2)
    return {"charge": charge}                          # match the real response key
