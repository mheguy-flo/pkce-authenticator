from typing import TYPE_CHECKING, TypedDict

if TYPE_CHECKING:
    from InquirerPy.base.control import Choice


class AuthClient(TypedDict):
    id: str
    name: str


class AuthCodeFlow(TypedDict):
    auth_uri: str
    code_verifier: str
    redirect_uri: str
    scope: list[str]
    state: str


class AuthEnvironment(TypedDict):
    id: str
    clients: "list[Choice]"


class AuthResponse(TypedDict):
    code: str
    error: str | None
    state: str


class PKCE(TypedDict):
    code_challenge: bytes
    code_verifier: str
    transformation: str


class Tokens(TypedDict):
    access_token: str
    expires_in: int
    refresh_token: str
    scope: str
    token_type: str


class UserInput(TypedDict):
    environment_id: str
    client_id: str
    scope: list[str]
    port: int
