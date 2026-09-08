from fastapi import FastAPI

from apps.hardened_api import models
from apps.hardened_api.database import SessionLocal, engine
from apps.hardened_api.routes import admin, auth, invoices, orders, support, users
from apps.hardened_api.seed import seed_database


app = FastAPI(
    title="Hardened AuthZ API",
    description="Hardened API used as the secure comparison target for authorization scanner tests.",
    version="0.1.0",
)


def initialize_database() -> None:
    models.Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        seed_database(db)


initialize_database()

app.include_router(auth.router)
app.include_router(orders.router)
app.include_router(invoices.router)
app.include_router(support.router)
app.include_router(users.router)
app.include_router(admin.router)


@app.get("/health")
def health_check() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "hardened_api",
    }
