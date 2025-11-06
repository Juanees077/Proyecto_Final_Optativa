from apis.auth.schemas import TokenData
from apis.auth.utils.utils import get_user_by_username
from config import Settings
from db.session import get_db
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from pathlib import Path
from sqlalchemy.orm import Session
from typing_extensions import Annotated

ALGORITHM = "RS256"
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Load keys from the same directory as this module
_KEY_DIR = Path(__file__).resolve().parent
PRIVATE_KEY = (_KEY_DIR / "private.pem").read_bytes()
PUBLIC_KEY = (_KEY_DIR / "public.pem").read_bytes()


async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    db: Session = Depends(get_db),
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(
            token,
            PUBLIC_KEY,  
            algorithms=[ALGORITHM],
        )
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception

        token_data = TokenData(username=username)

    except JWTError:
        raise credentials_exception

    user = get_user_by_username(db, username=token_data.username)
    if user is None:
        raise credentials_exception

    return user
