from typing import TYPE_CHECKING

from InquirerPy import inquirer
from InquirerPy.validator import NumberValidator

from pkce_authenticator.config import ENVIRONMENT_CHOICES, REDIRECT_PORT, SCOPES

if TYPE_CHECKING:
    from pkce_authenticator.data_models import UserInput


def get_user_input() -> "UserInput":
    """Have user select redirect port, environment, client, and scope for the tokens."""
    if inquirer.confirm(message=f"Use default port for redirect ({REDIRECT_PORT})?", default=True).execute():
        port = REDIRECT_PORT
    else:
        port = inquirer.number(
            message="Redirect port:",
            min_allowed=1,
            max_allowed=65535,
            validate=NumberValidator(),
            replace_mode=True,
        ).execute()

    scope = inquirer.checkbox(
        message="Select scopes:",
        instruction="Press <space> to (de)select. <enter> to submit.",
        choices=SCOPES,
    ).execute()

    environment = inquirer.select(
        message="Select environment:",
        choices=ENVIRONMENT_CHOICES,
    ).execute()

    client_id = inquirer.select(
        message="Select client:",
        choices=environment["clients"],
    ).execute()

    return {"client_id": client_id, "environment_id": environment["id"], "port": port, "scope": scope}
