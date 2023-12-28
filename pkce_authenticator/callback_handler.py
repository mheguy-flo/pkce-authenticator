import logging
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, NoReturn, Self, cast
from urllib.parse import parse_qs, urlparse

from pkce_authenticator.data_models import AuthResponse
from pkce_authenticator.utils import is_wsl, open_browser

logger = logging.getLogger(__name__)


class _AuthCodeHttpServer(HTTPServer):
    def __init__(self, server_address: tuple[str, int], *args: Any) -> None:
        self.auth_response = {}
        self.auth_state = ""

        if sys.platform == "win32" or is_wsl():
            self.allow_reuse_address = False

        super().__init__(server_address, *args)

    def handle_timeout(self) -> NoReturn:
        raise RuntimeError("Timeout. No auth response arrived.")


class _AuthCodeHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        self.server = cast(_AuthCodeHttpServer, self.server)

        qs = parse_qs(urlparse(self.path).query)

        if not qs.get("code") and not qs.get("error"):
            self._send_full_response("Invalid request", False)
            return

        auth_response = {k: v[0] if len(v) == 1 else v for k, v in qs.items()}
        logger.debug("Got auth response: %s", auth_response)

        if self.server.auth_state != auth_response["state"]:
            self._send_full_response("State mismatch", False)
            logger.error("Possible attack! State mismatch: %s != %s", self.server.auth_state, auth_response["state"])
            return

        if "code" in qs:
            response = "Authentication completed. You can close this window now."
        else:
            response = "Authentication failed. See error in terminal."
            logger.error("Authentication failed: %s", auth_response)

        self._send_full_response(response)
        self.server.auth_response = auth_response

    def _send_full_response(self, body: str, is_ok: bool = True) -> None:
        self.send_response(200 if is_ok else 400)
        content_type = "text/plain"
        self.send_header("Content-type", content_type)
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def log_message(self, format: Any, *args: Any) -> None:  # noqa: A002
        logger.debug(format, *args)


class AuthCodeReceiver:
    def __init__(self, port: int) -> None:
        self._server = _AuthCodeHttpServer(("127.0.0.1", port), _AuthCodeHandler)
        self._closing = False

    def get_auth_response(self, timeout: float | None = None, **kwargs: Any) -> AuthResponse:
        result = {}
        kwargs["timeout"] = timeout
        t = threading.Thread(target=self._get_auth_response, args=(result,), kwargs=kwargs)
        t.daemon = True
        t.start()
        begin = time.time()
        while (time.time() - begin < timeout) if timeout else True:
            time.sleep(1)
            if not t.is_alive():
                break
        else:
            raise TimeoutError("Timeout. No auth response arrived.")

        return cast(AuthResponse, result)

    def _get_auth_response(
        self,
        result: dict[str, Any],
        auth_uri: str,
        timeout: float,
        state: str,
    ) -> None:
        logger.info("Open a browser on this device to visit: %s", auth_uri)
        browser_opened = False

        try:
            browser_opened = open_browser(auth_uri)
        except Exception:
            logger.exception("open_browser failed with exception")

        if not browser_opened:
            print("Failed to open a browser. Please visit: %s" % auth_uri)

        self._server.timeout = timeout
        self._server.auth_state = state

        while not self._closing:
            self._server.handle_request()
            if self._server.auth_response:
                break

        result.update(self._server.auth_response)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_) -> None:
        self._closing = True
        self._server.server_close()
