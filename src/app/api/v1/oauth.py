import random
import secrets
from abc import ABC
from typing import Any

from fastapi import APIRouter, Depends, Request, Response
from fastapi_sso.sso.base import OpenID, SSOBase
from fastapi_sso.sso.github import GithubSSO
from fastapi_sso.sso.google import GoogleSSO
from fastapi_sso.sso.microsoft import MicrosoftSSO
from sqlalchemy.ext.asyncio import AsyncSession

from ...api.dependencies import get_current_user
from ...core.config import settings
from ...core.db.database import async_get_db
from ...core.exceptions.http_exceptions import UnauthorizedException
from ...core.security import (
    create_access_token,
    create_refresh_token,
)
from ...crud.crud_users import crud_users
from ...schemas.user import UserCreate, UserRead, UserUpdate
from .users import patch_user, write_user

router = APIRouter(tags=["login", "oauth"])


class BaseOAuthProvider(ABC):
    provider_config: dict[str, Any]
    sso_provider: type[SSOBase]

    def __init__(self, router: Any):
        self.router = router
        self.provider_name: str = self.sso_provider.provider
        if self.is_enabled:
            self.sso = self.sso_provider(redirect_uri=self.redirect_uri, **self.provider_config)
            tag = f"{self.sso_provider.provider.title()} OAuth"
            self.router.add_api_route(
                f"/login/{self.provider_name}",
                self._login_handler,
                methods=["GET"],
                tags=[tag],
                summary=f"Login with {self.provider_name.title()} OAuth",
            )
            self.router.add_api_route(
                f"/callback/{self.provider_name}",
                self._callback_handler,
                methods=["GET"],
                tags=[tag],
                summary=f"Callback for {self.provider_name.title()} OAuth",
            )

    @property
    def redirect_uri(self) -> str:
        return f"{settings.APP_BACKEND_HOST}/api/v1/callback/{self.provider_name}"

    @property
    def is_enabled(self) -> bool:
        return all(self.provider_config.values())

    async def _create_and_set_token(self, response: Response, user: dict[str, Any]) -> str:
        access_token = await create_access_token(data={"sub": user["username"]})
        refresh_token = await create_refresh_token(data={"sub": user["username"]})
        max_age = settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60
        response.set_cookie(
            key="refresh_token", value=refresh_token, httponly=True, secure=True, samesite="lax", max_age=max_age
        )
        return access_token

    async def _login_handler(self):
        async with self.sso:
            return await self.sso.get_login_redirect()

    async def _callback_handler(self, request: Request, response: Response, db: AsyncSession = Depends(async_get_db)):
        async with self.sso:
            oauth_user: OpenID | None = await self.sso.verify_and_process(request)
        if not oauth_user or not oauth_user.email:
            raise UnauthorizedException(f"Invalid response from {self.provider_name.title()} OAuth.")

        db_user = await crud_users.get(db=db, email=oauth_user.email, is_deleted=False, schema_to_select=UserRead)
        user_create = await self._get_user_details(oauth_user)
        if not db_user:
            db_user = await write_user(request=request, user=user_create, db=db)
        access_token = await self._create_and_set_token(response, db_user)
        current_user = await get_current_user(token=access_token, db=db)
        user_update = UserUpdate(
            name=user_create.name,
            username=user_create.username,
            email=user_create.email,
            profile_image_url=user_create.profile_image_url,
        )
        await patch_user(
            request=request, username=db_user["username"], values=user_update, current_user=current_user, db=db
        )
        return {"access_token": access_token, "token_type": "bearer"}

    async def _get_user_details(self, oauth_user: OpenID) -> UserCreate:
        """Get user details from the OAuth provider response.

        The exact details exposed by the OpenID class can be found here:
        https://github.com/tomasvotava/fastapi-sso/blob/master/fastapi_sso/sso/base.py#L64
        """
        if not oauth_user.email:
            raise UnauthorizedException(f"Invalid response from {self.provider_name.title()} OAuth.")
        username = oauth_user.email.split("@")[0]
        name = oauth_user.display_name or username
        random_password = secrets.token_urlsafe(32)
        # Create a random password for OAuth users.
        # It can still be changed if the user requests login with password.
        picture = oauth_user.picture
        if not picture:
            initials = [word[0] for word in name.split()]
            initials = "+".join(initials[:2])
            color = random.choice(settings.AVATAR_DEFAULT_COLORS).lstrip("#")
            picture = f"https://ui-avatars.com/api/?name={initials}&background={color}"
        return UserCreate(
            email=oauth_user.email,
            name=name,
            password=random_password,
            username=username,
            profile_image_url=picture,
        )


class GoogleOAuthProvider(BaseOAuthProvider):
    sso_provider = GoogleSSO
    provider_config = {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "client_secret": settings.GOOGLE_CLIENT_SECRET,
    }


class MicrosoftOAuthProvider(BaseOAuthProvider):
    sso_provider = MicrosoftSSO
    provider_config = {
        "client_id": settings.MICROSOFT_CLIENT_ID,
        "client_secret": settings.MICROSOFT_CLIENT_SECRET,
        "tenant": settings.MICROSOFT_TENANT,
    }


class GithubSSOProvider(BaseOAuthProvider):
    sso_provider = GithubSSO
    provider_config = {
        "client_id": settings.GITHUB_CLIENT_ID,
        "client_secret": settings.GITHUB_CLIENT_SECRET,
    }


GoogleOAuthProvider(router)
MicrosoftOAuthProvider(router)
GithubSSOProvider(router)
