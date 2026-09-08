from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from apps.vulnerable_api.auth import get_current_user
from apps.vulnerable_api.database import get_db
from apps.vulnerable_api.models import Invoice, User
from apps.vulnerable_api.schemas import InvoicePublic


router = APIRouter(tags=["invoices"])


def get_invoice_or_404(db: Session, invoice_id: str) -> Invoice:
    invoice = db.get(Invoice, invoice_id)
    if invoice is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invoice not found")
    return invoice


@router.get("/invoices", response_model=list[InvoicePublic])
def list_invoices(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[Invoice]:
    return list(db.scalars(select(Invoice)).all())


@router.get("/invoices/{invoice_id}", response_model=InvoicePublic)
def get_invoice(
    invoice_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Invoice:
    return get_invoice_or_404(db, invoice_id)


@router.get(
    "/organizations/{organization_id}/invoices/{invoice_id}",
    response_model=InvoicePublic,
)
def get_organization_invoice(
    organization_id: str,
    invoice_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Invoice:
    invoice = get_invoice_or_404(db, invoice_id)
    if invoice.organization_id != organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invoice not found")
    return invoice
