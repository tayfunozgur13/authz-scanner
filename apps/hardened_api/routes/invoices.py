from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from apps.hardened_api.auth import get_current_user
from apps.hardened_api.database import get_db
from apps.hardened_api.models import Invoice, User, UserRole
from apps.hardened_api.schemas import InvoicePublic


router = APIRouter(tags=["invoices"])


def get_invoice_or_404(db: Session, invoice_id: str) -> Invoice:
    invoice = db.get(Invoice, invoice_id)
    if invoice is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invoice not found")
    return invoice


def require_invoice_access(invoice: Invoice, current_user: User) -> None:
    if current_user.role == UserRole.ADMIN:
        return
    if invoice.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")


@router.get("/invoices", response_model=list[InvoicePublic])
def list_invoices(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[Invoice]:
    query = select(Invoice)
    if current_user.role != UserRole.ADMIN:
        query = query.where(Invoice.owner_id == current_user.id)
    return list(db.scalars(query).all())


@router.get("/invoices/{invoice_id}", response_model=InvoicePublic)
def get_invoice(
    invoice_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Invoice:
    invoice = get_invoice_or_404(db, invoice_id)
    require_invoice_access(invoice, current_user)
    return invoice


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
    require_invoice_access(invoice, current_user)
    return invoice
