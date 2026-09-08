from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

from apps.vulnerable_api.auth import authenticate_user, create_access_token
from apps.vulnerable_api.database import get_db
from apps.vulnerable_api.schemas import LoginRequest, TokenResponse


router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)) -> TokenResponse:
    user = authenticate_user(db, payload.email, payload.password)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    return TokenResponse(access_token=create_access_token(user))


@router.post("/session")
def session_login(
    payload: LoginRequest,
    response: Response,
    db: Session = Depends(get_db),
) -> dict[str, str]:
    user = authenticate_user(db, payload.email, payload.password)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    response.set_cookie(
        key="session_id",
        value=create_access_token(user),
        httponly=True,
        samesite="lax",
    )
    return {"detail": "Session created"}
