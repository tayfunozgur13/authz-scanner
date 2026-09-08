from fastapi import FastAPI

from apps.vulnerable_api import models
from apps.vulnerable_api.database import SessionLocal, engine
from apps.vulnerable_api.routes import admin, auth, invoices, orders, support, users
from apps.vulnerable_api.seed import seed_database


app = FastAPI(
    title="Vulnerable AuthZ API",
    description="Intentionally vulnerable API used as a target for authorization scanner tests.",
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
        "service": "vulnerable_api",
    }
