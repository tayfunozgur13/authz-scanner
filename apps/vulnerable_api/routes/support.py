from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from apps.vulnerable_api.auth import get_current_user
from apps.vulnerable_api.database import get_db
from apps.vulnerable_api.models import SupportTicket, User
from apps.vulnerable_api.schemas import SupportTicketActionResponse, SupportTicketPublic


router = APIRouter(prefix="/support", tags=["support"])


def get_ticket_or_404(db: Session, ticket_id: str) -> SupportTicket:
    ticket = db.get(SupportTicket, ticket_id)
    if ticket is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Support ticket not found",
        )
    return ticket


@router.get("/tickets", response_model=list[SupportTicketPublic])
def list_support_tickets(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[SupportTicket]:
    return list(db.scalars(select(SupportTicket)).all())


@router.get("/tickets/{ticket_id}", response_model=SupportTicketPublic)
def get_support_ticket(
    ticket_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SupportTicket:
    return get_ticket_or_404(db, ticket_id)


@router.post("/tickets/{ticket_id}/assign", response_model=SupportTicketActionResponse)
def assign_support_ticket(
    ticket_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SupportTicket:
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
    ticket = get_ticket_or_404(db, ticket_id)
    ticket.status = "closed"
    db.commit()
    db.refresh(ticket)
    return ticket
