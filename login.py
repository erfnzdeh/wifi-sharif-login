#!/usr/bin/env python3
"""Sign in to the Sharif network portal and connect this device.

Usage:
  ./login.py              connect (default)
  ./login.py status       show whether this device is online
  ./login.py disconnect   end the network session

Credentials live in credentials.env (mode 600). On first run, if that file
is missing, they are copied out of net.sharif.ir.har when it is present.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from http.cookiejar import LWPCookieJar
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CRED_PATH = ROOT / "credentials.env"
COOKIE_PATH = ROOT / "cookies.txt"
HAR_PATH = ROOT / "net.sharif.ir.har"
BASE = "https://net.sharif.ir"
HOME = f"{BASE}/en-us/user/home/"
CONNECT = f"{BASE}/en-us/user/aaa_ras_connect/"
DISCONNECT = f"{BASE}/en-us/user/aaa_ras_disconnect/"
SESSIONS = f"{BASE}/en-us/user/get_user_online_session/"
METADATA = f"{BASE}/en-us/user/get_user_metadata/"
USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36"
)
TIMEOUT = 20
USERNAME_FIELDS = ("username", "user", "normal_username", "email")


class PortalError(Exception):
    pass


class FormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[dict] = []
        self._form: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self._form = {
                "action": attr.get("action", ""),
                "method": (attr.get("method") or "get").lower(),
                "inputs": [],
            }
            return
        if self._form is None:
            return
        if tag == "input":
            self._form["inputs"].append(
                {
                    "name": attr.get("name", ""),
                    "type": (attr.get("type") or "text").lower(),
                    "value": attr.get("value", ""),
                }
            )
        elif tag in ("button", "textarea") and attr.get("name"):
            self._form["inputs"].append(
                {
                    "name": attr["name"],
                    "type": (attr.get("type") or "text").lower(),
                    "value": attr.get("value", ""),
                }
            )

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


def parse_forms(html: str) -> list[dict]:
    parser = FormParser()
    parser.feed(html)
    parser.close()
    return parser.forms


def login_form(html: str) -> dict | None:
    for form in parse_forms(html):
        if any(field["type"] == "password" for field in form["inputs"]):
            return form
    return None


def load_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def extract_from_har(path: Path) -> tuple[str, str] | None:
    with path.open() as handle:
        har = json.load(handle)
    pattern = re.compile(r'user\s*:\s*"([^"]+)"\s*,\s*pass\s*:\s*"([^"]+)"')
    for entry in har.get("log", {}).get("entries", []):
        text = entry.get("response", {}).get("content", {}).get("text") or ""
        match = pattern.search(text)
        if match:
            return match.group(1), match.group(2)
    return None


def write_credentials(username: str, password: str) -> None:
    fd = os.open(CRED_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(f"NET_SHARIF_USER={username}\n")
        handle.write(f"NET_SHARIF_PASSWORD={password}\n")


def credentials() -> tuple[str, str]:
    if not CRED_PATH.exists() and HAR_PATH.exists():
        found = extract_from_har(HAR_PATH)
        if found:
            write_credentials(*found)
    if not CRED_PATH.exists():
        raise PortalError(
            "Missing credentials.env. Add NET_SHARIF_USER and NET_SHARIF_PASSWORD."
        )
    os.chmod(CRED_PATH, 0o600)
    values = load_env(CRED_PATH)
    username = values.get("NET_SHARIF_USER", "")
    password = values.get("NET_SHARIF_PASSWORD", "")
    if not username or not password:
        raise PortalError(
            "credentials.env needs NET_SHARIF_USER and NET_SHARIF_PASSWORD."
        )
    return username, password


def opener() -> tuple[urllib.request.OpenerDirector, LWPCookieJar]:
    jar = LWPCookieJar(str(COOKIE_PATH))
    if COOKIE_PATH.exists():
        jar.load(ignore_discard=True, ignore_expires=True)
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar)), jar


def save_cookies(jar: LWPCookieJar) -> None:
    jar.save(ignore_discard=True, ignore_expires=True)
    os.chmod(COOKIE_PATH, 0o600)


def csrf_token(jar: LWPCookieJar) -> str:
    for cookie in jar:
        if cookie.name == "csrftoken":
            return cookie.value
    return ""


def redact(text: str) -> str:
    text = re.sub(r'(pass(?:word)?["\s:=]+)[^"&\s<]+', r"\1***", text, flags=re.I)
    return text


def request(
    client: urllib.request.OpenerDirector,
    jar: LWPCookieJar,
    url: str,
    data: dict[str, str] | None = None,
    referer: str | None = None,
    ajax: bool = False,
) -> tuple[int, str, str]:
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "*/*" if ajax else "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }
    if referer:
        headers["Referer"] = referer
    if ajax:
        headers["X-Requested-With"] = "XMLHttpRequest"
    body = None
    if data is not None:
        token = csrf_token(jar)
        if token:
            headers["X-CSRFToken"] = token
        headers["Origin"] = BASE
        headers["Content-Type"] = "application/x-www-form-urlencoded; charset=UTF-8"
        body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=body, headers=headers)
    try:
        with client.open(req, timeout=TIMEOUT) as response:
            payload = response.read().decode("utf-8", errors="replace")
            return response.status, response.geturl(), payload
    except urllib.error.HTTPError as error:
        payload = error.read().decode("utf-8", errors="replace")
        return error.code, error.geturl() or url, payload
    except urllib.error.URLError as error:
        reason = getattr(error, "reason", error)
        raise PortalError(
            "Can't reach net.sharif.ir. Join Sharif-Wifi or the campus network, then run this again.\n"
            f"({reason})"
        ) from error


def looks_signed_in(html: str, final_url: str) -> bool:
    if login_form(html):
        return False
    if "aaa_ras_connect" in html:
        return True
    return "/user/home" in final_url and "logout" in html


def fill_login(form: dict, username: str, password: str) -> dict[str, str]:
    payload: dict[str, str] = {}
    username_set = False
    for field in form["inputs"]:
        name = field["name"]
        if not name or field["type"] in ("submit", "button", "image"):
            continue
        if field["type"] == "password":
            payload[name] = password
            continue
        if name in USERNAME_FIELDS or (field["type"] in ("text", "email") and not username_set):
            payload[name] = username
            username_set = True
            continue
        payload[name] = field["value"]
    if not any(field["type"] == "password" for field in form["inputs"]):
        raise PortalError("Login page has no password field.")
    if not username_set:
        raise PortalError("Login page has no username field.")
    return payload


def sign_in(
    client: urllib.request.OpenerDirector,
    jar: LWPCookieJar,
    username: str,
    password: str,
) -> None:
    status, final_url, html = request(client, jar, HOME)
    if status >= 400 and not login_form(html):
        raise PortalError(f"Portal returned HTTP {status} for the home page.")
    if looks_signed_in(html, final_url):
        return
    form = login_form(html)
    if form is None:
        for candidate in (
            f"{BASE}/en-us/login/",
            f"{BASE}/login/",
            f"{BASE}/en-us/user/login/",
        ):
            status, final_url, html = request(client, jar, candidate, referer=HOME)
            form = login_form(html)
            if form is not None:
                break
    if form is None:
        raise PortalError(
            "Couldn't find the login form. Open net.sharif.ir once in a browser "
            "while this fails and share that page if it still doesn't work."
        )
    action = urllib.parse.urljoin(final_url, form["action"] or final_url)
    payload = fill_login(form, username, password)
    status, final_url, html = request(client, jar, action, payload, referer=final_url)
    if login_form(html) or not looks_signed_in(html, final_url):
        snippet = redact(re.sub(r"\s+", " ", html))[:240]
        raise PortalError(f"Login was rejected (HTTP {status}). {snippet}")
    save_cookies(jar)


def ensure_csrf(
    client: urllib.request.OpenerDirector, jar: LWPCookieJar
) -> None:
    if not csrf_token(jar):
        request(client, jar, HOME, referer=HOME)


def connect_session(
    client: urllib.request.OpenerDirector,
    jar: LWPCookieJar,
    username: str,
    password: str,
) -> None:
    ensure_csrf(client, jar)
    status, _, body = request(
        client,
        jar,
        CONNECT,
        {"user": username, "pass": password},
        referer=HOME,
        ajax=True,
    )
    if status >= 400:
        raise PortalError(f"Connect was refused (HTTP {status}). {redact(body)[:180]}")


def disconnect_session(
    client: urllib.request.OpenerDirector, jar: LWPCookieJar
) -> None:
    ensure_csrf(client, jar)
    status, _, body = request(
        client, jar, DISCONNECT, {}, referer=HOME, ajax=True
    )
    if status >= 400:
        raise PortalError(f"Disconnect was refused (HTTP {status}). {redact(body)[:180]}")


def online_sessions(
    client: urllib.request.OpenerDirector, jar: LWPCookieJar
) -> dict:
    status, final_url, body = request(client, jar, SESSIONS, referer=HOME, ajax=True)
    if status >= 400 or not body.strip() or body.lstrip().startswith("<") or "login" in final_url:
        raise PortalError("Session expired. Run ./login.py again.")
    try:
        return json.loads(body)
    except json.JSONDecodeError as error:
        raise PortalError(f"Unexpected session response: {redact(body)[:180]}") from error


def this_device_online(payload: dict) -> tuple[bool, str, int]:
    result = payload.get("result") or {}
    if not result:
        return False, str(payload.get("ip") or ""), 0
    user_id = next(iter(result))
    sessions = result[user_id] or []
    current_ip = str(payload.get("ip") or "")
    connected = any(entry.get("session_ip") == current_ip for entry in sessions)
    return connected, current_ip, len(sessions)


def account_line(
    client: urllib.request.OpenerDirector, jar: LWPCookieJar
) -> str:
    status, _, body = request(client, jar, METADATA, referer=HOME, ajax=True)
    if status >= 400 or not body.strip():
        return ""
    try:
        result = json.loads(body).get("result") or {}
    except json.JSONDecodeError:
        return ""
    if not result:
        return ""
    info = result[next(iter(result))]
    credit = info.get("credit")
    try:
        credit_gb = f"{int(float(credit)) / 1024:.3f} GB"
    except (TypeError, ValueError):
        credit_gb = ""
    name = str(info.get("normal_username") or "").split("@")[0]
    bits = [part for part in (name, credit_gb) if part]
    return " · ".join(bits)


def describe(payload: dict, account: str) -> str:
    connected, current_ip, count = this_device_online(payload)
    state = "Connected" if connected else "Not connected"
    where = f" ({current_ip})" if current_ip else ""
    extra = f" — {account}" if account else ""
    return f"{state}{where}. Sessions: {count}.{extra}"


def wait_until(predicate, attempts: int = 5) -> dict:
    last = {}
    for attempt in range(attempts):
        last = predicate()
        if this_device_online(last)[0]:
            return last
        if attempt + 1 < attempts:
            time.sleep(0.7)
    return last


def cmd_status(client, jar) -> int:
    payload = online_sessions(client, jar)
    account = account_line(client, jar)
    connected, _, _ = this_device_online(payload)
    print(describe(payload, account))
    return 0 if connected else 1


def cmd_connect(client, jar) -> int:
    username, password = credentials()
    sign_in(client, jar, username, password)
    save_cookies(jar)
    already = online_sessions(client, jar)
    if this_device_online(already)[0]:
        print(describe(already, account_line(client, jar)))
        return 0
    connect_session(client, jar, username, password)
    payload = wait_until(lambda: online_sessions(client, jar))
    account = account_line(client, jar)
    print(describe(payload, account))
    if not this_device_online(payload)[0]:
        print("The portal accepted the request, but this device is not in the session list yet.")
        return 1
    return 0


def cmd_disconnect(client, jar) -> int:
    username, password = credentials()
    sign_in(client, jar, username, password)
    disconnect_session(client, jar)
    time.sleep(0.7)
    payload = online_sessions(client, jar)
    connected, _, _ = this_device_online(payload)
    print(describe(payload, account_line(client, jar)))
    return 1 if connected else 0


def self_test() -> int:
    html = """
    <form method="post" action="/en-us/login/">
      <input type="hidden" name="csrfmiddlewaretoken" value="abc">
      <input type="text" name="username" value="">
      <input type="password" name="password">
      <button type="submit">Login</button>
    </form>
    """
    form = login_form(html)
    assert form is not None
    payload = fill_login(form, "alice", "secret")
    assert payload == {
        "csrfmiddlewaretoken": "abc",
        "username": "alice",
        "password": "secret",
    }
    assert looks_signed_in("<a href='/en-us/user/logout/'>x</a> aaa_ras_connect", HOME)
    assert not looks_signed_in(html, f"{BASE}/en-us/login/")
    found = extract_from_har(HAR_PATH)
    assert found is not None and found[0] and found[1]
    print("self-test ok")
    return 0


def main() -> int:
    command = sys.argv[1] if len(sys.argv) > 1 else "connect"
    if command in ("-h", "--help", "help"):
        print(__doc__.strip())
        return 0
    if command == "--self-test":
        return self_test()
    commands = {
        "connect": cmd_connect,
        "login": cmd_connect,
        "status": cmd_status,
        "disconnect": cmd_disconnect,
        "logout": cmd_disconnect,
    }
    if command not in commands:
        print(__doc__.strip())
        return 2
    try:
        if command in ("status",):
            # Status still needs a live session cookie; sign in when it is missing.
            client, jar = opener()
            try:
                return cmd_status(client, jar)
            except PortalError as error:
                if "Session expired" not in str(error):
                    raise
                username, password = credentials()
                sign_in(client, jar, username, password)
                save_cookies(jar)
                return cmd_status(client, jar)
        client, jar = opener()
        return commands[command](client, jar)
    except PortalError as error:
        print(error, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
