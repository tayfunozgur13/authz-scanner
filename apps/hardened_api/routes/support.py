from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from apps.hardened_api.auth import get_current_user
from apps.hardened_api.database import get_db
from apps.hardened_api.models import SupportTicket, User, UserRole
from apps.hardened_api.schemas import SupportTicketActionResponse, SupportTicketPublic


router = APIRouter(prefix="/support", tags=["support"])

STAFF_ROLES = {UserRole.SUPPORT, UserRole.MANAGER, UserRole.ADMIN}
MANAGER_ROLES = {UserRole.MANAGER, UserRole.ADMIN}


def get_ticket_or_404(db: Session, ticket_id: str) -> SupportTicket:
    ticket = db.get(SupportTicket, ticket_id)
    if ticket is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Support ticket not found",
        )
    return ticket


def require_staff(current_user: User) -> None:
    if current_user.role not in STAFF_ROLES:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")


def require_manager(current_user: User) -> None:
    if current_user.role not in MANAGER_ROLES:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")


def require_ticket_access(ticket: SupportTicket, current_user: User) -> None:
    if current_user.role in STAFF_ROLES:
        return
    if ticket.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")


@router.get("/tickets", response_model=list[SupportTicketPublic])
def list_support_tickets(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[SupportTicket]:
    query = select(SupportTicket)
    if current_user.role not in STAFF_ROLES:
        query = query.where(SupportTicket.owner_id == current_user.id)
    return list(db.scalars(query).all())


@router.get("/tickets/{ticket_id}", response_model=SupportTicketPublic)
def get_support_ticket(
    ticket_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SupportTicket:
    ticket = get_ticket_or_404(db, ticket_id)
    require_ticket_access(ticket, current_user)
    return ticket


@router.post("/tickets/{ticket_id}/assign", response_model=SupportTicketActionResponse)
def assign_support_ticket(
    ticket_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SupportTicket:
    require_staff(current_user)
    ticket = get_ticket_or_404(db, ticket_id)
    ticket.assigned_support_id = current_user.id
    db.commit()
    db.refresh(ticket)
    return ticket


@router.post("/tickets/{ticket_id}/close", response_model=SupportTicketActionResponse)
def close_support_ticket(
    ticket_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SupportTicket:
    require_manager(current_user)
    ticket = get_ticket_or_404(db, ticket_id)
    ticket.status = "closed"
    db.commit()
    db.refresh(ticket)
    return ticket
