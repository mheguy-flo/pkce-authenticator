from InquirerPy.base.control import Choice

from pkce_authenticator.data_models import AuthEnvironment

REDIRECT_PORT = 38080

ENVIRONMENT_CHOICES = [
    Choice(
        name="admin-qa",
        value=AuthEnvironment(
            id="baeae5cc-a0b2-417b-9add-80a3791a5ca3",
            clients=[
                Choice(value="8da883f2-4820-46c8-9969-14e123901e77", name="CPO - RFC7636"),
                Choice(value="ae70d4a1-693c-434a-b3e4-f747ebc9754c", name="CPO SiteHost manager"),
                Choice(value="83cc9cc7-2fae-46b5-b1e1-b3987ccd7bbe", name="EMSP Admin Portal"),
            ],
        ),
    ),
    Choice(
        name="admin-floca-prod",
        value=AuthEnvironment(
            id="747ae15b-e7c3-443f-bed9-a1115fd8fd9e",
            clients=[
                Choice(value="1515c5b2-0510-4fbb-ab02-ef042888e58d", name="EMSP Admin Portal"),
            ],
        ),
    ),
]

SCOPES = [
    Choice("api:all", enabled=True),
    "openid",
    "address",
    "email",
    "phone",
    "profile",
]
