from fastapi import FastAPI

from api.routers.attack import router as attack_router
from api.routers.dashboard import router as dashboard_router
from api.routers.feed import router as feed_router
from api.routers.indicators import router as indicators_router
from api.routers.investigate import router as investigate_router
from api.routers.observables import router as observables_router
from api.routers.vulnerabilities import router as vulnerabilities_router


app = FastAPI(
    title="CTI Platform API",
    description="Vendor-neutral Cyber Threat Intelligence Platform",
    version="0.1.0",
)

app.include_router(dashboard_router)
app.include_router(feed_router)
app.include_router(vulnerabilities_router)
app.include_router(indicators_router)
app.include_router(observables_router)
app.include_router(attack_router)
app.include_router(investigate_router)


@app.get("/")
def home():
    return {
        "message": "CTI Platform is running",
        "version": "0.1.0",
    }