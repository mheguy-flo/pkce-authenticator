import platform
import subprocess
import webbrowser

import requests


def open_browser(uri: str = "about:blank") -> bool:
    browser_opened = webbrowser.open(uri)

    if not browser_opened and is_wsl():
        try:
            exit_code = subprocess.call(
                ["powershell.exe", "-NoProfile", "-Command", f'Start-Process "{uri}"']  # noqa: S603, S607
            )
            browser_opened = exit_code == 0
        except FileNotFoundError:
            pass
    return browser_opened


def is_wsl():
    uname = platform.uname()
    platform_name = getattr(uname, "system", uname[0]).lower()
    release = getattr(uname, "release", uname[2]).lower()
    return platform_name == "linux" and "microsoft" in release


def get_oidc_configuration(discover_endpoint: str) -> dict[str, str]:
    resp = requests.get(discover_endpoint, timeout=5)
    resp.raise_for_status()
    return resp.json()
