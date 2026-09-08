from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

from apps.vulnerable_api.auth import (
    authenticate_user,
    create_access_token,
    create_expired_access_token,
    create_refresh_token,
    get_user_from_refresh_token,
)
from apps.vulnerable_api.database import get_db
from apps.vulnerable_api.schemas import (
    LoginRequest,
    RefreshTokenRequest,
    TokenPairResponse,
    TokenResponse,
)


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


@router.post("/login-with-refresh", response_model=TokenPairResponse)
def login_with_refresh(
    payload: LoginRequest,
    db: Session = Depends(get_db),
) -> TokenPairResponse:
    user = authenticate_user(db, payload.email, payload.password)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    return TokenPairResponse(
        access_token=create_access_token(user),
        refresh_token=create_refresh_token(user),
    )


@router.post("/login-expired-with-refresh", response_model=TokenPairResponse)
def login_expired_with_refresh(
    payload: LoginRequest,
    db: Session = Depends(get_db),
) -> TokenPairResponse:
    user = authenticate_user(db, payload.email, payload.password)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    return TokenPairResponse(
        access_token=create_expired_access_token(user),
        refresh_token=create_refresh_token(user),
    )


@router.post("/refresh", response_model=TokenPairResponse)
def refresh(payload: RefreshTokenRequest, db: Session = Depends(get_db)) -> TokenPairResponse:
    user = get_user_from_refresh_token(payload.refresh_token, db)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    return TokenPairResponse(
        access_token=create_access_token(user),
        refresh_token=create_refresh_token(user),
    )


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
