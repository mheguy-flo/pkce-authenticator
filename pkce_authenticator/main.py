"""Authenticates with Authorization Code Flow with PKCE and provides tokens to the user."""
import base64
import hashlib
import json
import logging
import random
import string
from pprint import pprint
from typing import TYPE_CHECKING, Any
from urllib.parse import urlencode

import pyperclip
import requests

from pkce_authenticator.callback_handler import AuthCodeReceiver
from pkce_authenticator.user_interaction import get_user_input
from pkce_authenticator.utils import get_oidc_configuration

if TYPE_CHECKING:
    from pkce_authenticator.data_models import PKCE, AuthCodeFlow, AuthResponse, Tokens

AUTH_TIMEOUT = 180

logging.basicConfig(level=logging.INFO)


def generate_pkce_data(length: int = 64, code_challenge_method: str = "S256") -> "PKCE":
    verifier = "".join(random.sample(string.ascii_letters + string.digits + "-._~", length))
    code_challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=")
    return {
        "code_verifier": verifier,
        "transformation": code_challenge_method,
        "code_challenge": code_challenge,
    }


class Client:
    def __init__(self, server_config: dict[str, Any], redirect_uri: str, client_id: str, scope: list[str]) -> None:
        self.configuration = server_config
        self.redirect_uri = redirect_uri
        self.client_id = client_id
        self.scope = scope
        self.logger = logging.getLogger(__name__)

    def create_authorization_code_flow(self) -> "AuthCodeFlow":
        pkce = generate_pkce_data()
        state = "".join(random.sample(string.ascii_letters, 16))

        params = {
            "client_id": self.client_id,
            "response_type": "code",
            "redirect_uri": self.redirect_uri,
            "scope": " ".join(sorted(self.scope)),
            "state": state,
            "code_challenge": pkce["code_challenge"],
            "code_challenge_method": pkce["transformation"],
        }
        auth_uri = f'{self.configuration["authorization_endpoint"]}?{urlencode(params)}'

        return {
            "state": state,
            "redirect_uri": self.redirect_uri,
            "scope": self.scope,
            "auth_uri": auth_uri,
            "code_verifier": pkce["code_verifier"],
        }

    def obtain_token_by_browser(
        self,
        auth_code_receiver: "AuthCodeReceiver",
        timeout: float,
    ) -> "Tokens":
        auth_code_flow = self.create_authorization_code_flow()

        auth_response = auth_code_receiver.get_auth_response(
            auth_uri=auth_code_flow["auth_uri"],
            state=auth_code_flow["state"],
            timeout=timeout,
        )

        self.validate_authorization_code(auth_code_flow, auth_response)

        return self.exchange_authorization_code_for_token(
            auth_response["code"],
            auth_code_flow["code_verifier"],
        )

    def validate_authorization_code(self, auth_code_flow: "AuthCodeFlow", auth_response: "AuthResponse") -> bool:
        if auth_code_flow["state"] != auth_response["state"]:
            raise ValueError(f'state mismatch: {auth_code_flow["state"]} vs {auth_response["state"]}')

        if auth_response.get("error"):
            error = {
                "error": auth_response["error"],
                "error_description": auth_response.get("error_description"),
                "error_uri": auth_response.get("error_uri"),
            }
            raise ValueError(f"Error in auth_response: {error}")

        if not auth_response.get("code"):
            raise ValueError('auth_response must contain either "code" or "error"')

        return True

    def exchange_authorization_code_for_token(self, code: str, code_verifier: str) -> "Tokens":
        resp = requests.post(
            self.configuration["token_endpoint"],
            headers={"Accept": "application/json"},
            data={
                "client_id": self.client_id,
                "code": code,
                "redirect_uri": self.redirect_uri,
                "scope": " ".join(sorted(self.scope)),
                "code_verifier": code_verifier,
                "grant_type": "authorization_code",
            },
            timeout=5,
        )

        if resp.status_code >= 500:  # noqa: PLR2004
            resp.raise_for_status()

        try:
            resp = json.loads(resp.text)
        except ValueError:
            self.logger.exception("Token response is not in json format: %s", resp.text)
            raise

        return resp


def main(
    environment_id: str,
    client_id: str,
    scope: list[str],
    port: int,
) -> None:
    oidc_discovery_endpoint = f"https://auth.pingone.ca/{environment_id}/as/.well-known/openid-configuration"
    redirect_uri = f"http://localhost:{port}/auth"

    server_config = get_oidc_configuration(oidc_discovery_endpoint)
    client = Client(server_config=server_config, client_id=client_id, redirect_uri=redirect_uri, scope=scope)

    with AuthCodeReceiver(port=port) as receiver:
        result = client.obtain_token_by_browser(
            auth_code_receiver=receiver,
            timeout=AUTH_TIMEOUT,
        )

    pprint(result)

    try:
        pyperclip.copy(result["access_token"])
        print("The access token has been copied to your clipboard.")
    except pyperclip.PyperclipException:
        print("The access token has not been copied to your clipboard.")

    input("Press Enter to exit...")


if __name__ == "__main__":
    main(**get_user_input())
