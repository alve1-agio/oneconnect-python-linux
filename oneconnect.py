import asyncio
import base64
import hashlib
import os
import platform
import socket
import webbrowser
import html
from dotenv import load_dotenv
from dataclasses import dataclass, field
from typing import Iterable, Optional, Tuple, List, Dict, Union, Mapping
from urllib.parse import urlencode
from configauthxml import ConfigAuthXml, Authenticator, ConfigAuthXmlParameter, ClientEnvironment

import aiohttp
import xml.etree.ElementTree as ET

from aiohttp import web
import jwt  # PyJWT
import requests


@dataclass
class OIDCResult:
    id_token: str
    refresh_token: str | None
    url: str | None

@dataclass
class TunnelConfiguration:
    dtls_allowed_cipher_suites: List[str] = field(default_factory=list)
    dtls12_allowed_cipher_suites: List[str] = field(default_factory=list)
    dtls_pre_master_secret: bytes = field(default_factory=lambda: os.urandom(48))


def _pick_loopback_host() -> str:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.close()
        return "127.0.0.1"
    except OSError:
        if socket.has_ipv6:
            return "::1"
        raise RuntimeError("IPv4 and IPv6 loopback are not available")


def _find_free_port(start=49215, end=65535, host="127.0.0.1") -> int:
    for p in range(start, end + 1):
        with socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET,
                           socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind((host, p))
                return p
            except OSError:
                continue
    raise RuntimeError("Failed to set up HTTP loopback listener")


def _base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _gen_pkce():
    verifier = _base64url(os.urandom(32))
    challenge = _base64url(hashlib.sha256(verifier.encode()).digest())
    return verifier, challenge

def compute_uid(username: str,
                system_id_bytes: Optional[bytes] = None,
                spoof_uid_hex: Optional[str] = None,
                seed: Optional[str] = None) -> str:

    if spoof_uid_hex:                    # direct spoof (64-char hex)
        return spoof_uid_hex.lower()

    if system_id_bytes is None:
        system_id_bytes = hashlib.sha256((seed or "spoof-default").encode("utf-8")).digest()

    h = hashlib.sha256()
    h.update(system_id_bytes)
    h.update(username.encode("utf-8"))
    return h.hexdigest()


async def start_web_server_wait_on_response(address: str,
                                            client_id: str,
                                            nonce: str | None = None,
                                            cancel_event: asyncio.Event | None = None
                                            ) -> OIDCResult:
    host = _pick_loopback_host()
    port = _find_free_port(host=host)
    redirect_uri = f"http://[{host}]" if ":" in host else f"http://{host}"
    redirect_uri += f":{port}/oneconnect/oauth/"

    # ---- Discover provider endpoints ----
    well_known = requests.get(
        address.rstrip("/"),
        timeout=10
    )
    well_known.raise_for_status()
    meta = well_known.json()
    auth_endpoint = meta["authorization_endpoint"]
    token_endpoint = meta["token_endpoint"]

    # ---- Prepare PKCE + state/nonce ----
    verifier, challenge = _gen_pkce()
    state = _base64url(os.urandom(16))
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "openid offline_access",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": state,
    }
    if nonce and nonce.strip():
        params["nonce"] = nonce.strip()

    start_url = auth_endpoint + "?" + urlencode(params)

    # ---- Browser launch ----
    webbrowser.open(start_url)

    # ---- Server that handles the redirect and finishes the flow ----
    result_holder: dict = {}

    async def handle(request: web.Request):
        # Cancellation check
        if cancel_event and cancel_event.is_set():
            raise asyncio.CancelledError()

        # We expect the provider to redirect back with ?code=&state=
        q = request.rel_url.query
        error = q.get("error")
        code = q.get("code")
        recv_state = q.get("state")

        # Prepare defaults for HTML
        html_msg = "Authentication is done and the browser can be closed."
        meta_refresh = ""

        if error:
            html_msg = f"Error: {q.get('error_description') or error}"
            status = 400
            result_holder["error"] = html_msg
        elif not code or recv_state != state:
            html_msg = "Error: Missing authorization code or invalid state."
            status = 400
            result_holder["error"] = html_msg
        else:
            # Exchange code for tokens
            async with aiohttp.ClientSession() as session:
                data = {
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": redirect_uri,
                    "client_id": client_id,
                    "code_verifier": verifier,
                }
                async with session.post(token_endpoint, data=data) as resp:
                    if resp.status != 200:
                        body = await resp.text()
                        html_msg = f"Error: token exchange failed ({resp.status})."
                        result_holder["error"] = f"{html_msg} {body}"
                        status = 400
                    else:
                        tok = await resp.json()
                        id_token = tok.get("id_token")
                        refresh_token = tok.get("refresh_token")
                        clavister_url = None
                        if id_token:
                            try:
                                claims = jwt.decode(
                                    id_token,
                                    options={"verify_signature": False, "verify_aud": False}
                                )
                                clavister_url = claims.get("clavister_url")
                            except jwt.PyJWTError:  # signature not verified intentionally — token comes from the server we just authenticated with
                                pass

                        result_holder["id_token"] = id_token
                        result_holder["refresh_token"] = refresh_token
                        result_holder["clavister_url"] = clavister_url

                        if clavister_url:
                            meta_refresh = f" http-equiv='refresh' content='1;url={clavister_url}'"
                            html_msg = "Your Single Sign-On portal is being prepared. Please wait to be redirected."
                        status = 200

        html_response = (
            f"<html><head><meta {meta_refresh}></head>\n"
            '<body style="background-color:#000; color: #aaa">\n'
            '<div style="display:block; position:relative; width:100%; height:500px ">\n'
            '<div style="display:block; position:absolute; width:100%; height:50%; margin:auto; top:0; bottom:0; right:0; left:0; ">\n'
            f'<h2 style="text-align:center">{html.escape(html_msg)}</h2>\n'
            "</div></div></body></html>"
        )
        return web.Response(text=html_response, status=status, content_type="text/html")

    app = web.Application()
    app.add_routes([web.get("/oneconnect/oauth/", handle)])

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host=host, port=port)
    try:
        await site.start()

        # Wait until we have a result or cancellation
        # (The handler populates result_holder after processing the token response)
        while not result_holder:
            if cancel_event and cancel_event.is_set():
                raise asyncio.CancelledError()
            await asyncio.sleep(0.05)

        # Build the return value or raise
        if "error" in result_holder:
            raise RuntimeError(result_holder["error"])
        return OIDCResult(
            id_token=result_holder.get("id_token", ""),
            refresh_token=result_holder.get("refresh_token"),
            url=result_holder.get("clavister_url"),
        )
    finally:
        # Stop listener
        await runner.cleanup()


def create_configauth_xml(
    parameters: Optional[Iterable[Tuple[str, str]]] = None,
    authenticator: Optional[Union[str, Mapping[str, str]]] = None,
) -> str:
    root = ET.Element("ConfigAuth")
    if parameters:
        params_el = ET.SubElement(root, "Parameters")
        for name, value in parameters:
            p = ET.SubElement(params_el, "Parameter")
            ET.SubElement(p, "Name").text = name
            ET.SubElement(p, "Value").text = value if value is not None else ""

    if authenticator is not None:
        auth_el = ET.SubElement(root, "Authenticator")
        if isinstance(authenticator, str):
            auth_el.text = authenticator
        elif isinstance(authenticator, Mapping):
            for k, v in authenticator.items():
                ET.SubElement(auth_el, str(k)).text = str(v)

    xml_bytes = ET.tostring(root, encoding="utf-8", method="xml")
    return xml_bytes.decode("utf-8")


def _x_pad_value(body_bytes: bytes) -> str:
    rem = len(body_bytes) % 64
    pad = 64 - rem if rem != 0 else 64
    return "X" * pad

def _format_version(package_version: Tuple[int, int, int, int] | str) -> str:
    if isinstance(package_version, str):
        return package_version
    major, minor, build, rev = package_version
    return f"{major}.{minor}.{build}.{rev}"

def collect_client_environment(
    package_version: Tuple[int, int, int, int] | str,
    uid: str,
    av_enabled: bool,
    av_updated: bool,
    wolfssl_version: Optional[str] = None,
) -> ClientEnvironment:
    os_info = platform.freedesktop_os_release().get("PRETTY_NAME", platform.system()) if hasattr(platform, "freedesktop_os_release") else platform.system()
    arch = "X64" if platform.machine() in ("x86_64", "AMD64") else platform.machine()
    return ClientEnvironment(
        UID=uid,
        ClientVersion=_format_version(package_version),
        WolfSSLVersion=wolfssl_version or "Unknown",
        OperatingSystemInformation=os_info,
        OperatingSystemArchitecture=arch,
        IsAVEnable=av_enabled,
        IsAVUpdated=av_updated,
    )

def build_request_headers(
    client_env: ClientEnvironment,
    tunnel_cfg: TunnelConfiguration,
) -> Dict[str, str]:
    ua = f"OneConnect/{client_env.ClientVersion} (Clavister OneConnect VPN)"
    dtls_cs = ":".join(["PSK-NEGOTIATE"] + list(tunnel_cfg.dtls_allowed_cipher_suites))
    dtls12_cs = ":".join(tunnel_cfg.dtls12_allowed_cipher_suites)
    master_secret_hex = tunnel_cfg.dtls_pre_master_secret.hex().upper()

    return {
        "User-Agent": ua,
        "X-CSTP-Version": "1",
        "X-CSTP-Base-MTU": "1500",
        "X-CSTP-Address-Type": "IPv4",
        "X-DTLS-CipherSuite": dtls_cs,
        "X-DTLS12-CipherSuite": dtls12_cs,
        "X-DTLS-Accept-Encoding": "identity",
        "X-DTLS-Master-Secret": master_secret_hex,
    }

async def send_user_credential_async(
    session: aiohttp.ClientSession,
    auth_uri: str,
    headers: Dict[str, str],
    parameters: Optional[Iterable[Tuple[str, str]]],
    authenticator: Authenticator,
    *,
    timeout: Optional[int] = None,
) -> aiohttp.ClientResponse:
    param_objs = [ConfigAuthXmlParameter(Name=name, Value=value or "") for name, value in (parameters or [])]
    cfg = ConfigAuthXml(Parameters=param_objs, authenticator=authenticator)
    xml_str = cfg.create_xml_document_string()
    body = xml_str.encode("utf-8")

    headers.update({
        "Content-Type": "text/xml; charset=utf-8",
        "X-Pad": _x_pad_value(body),
    })


    return await session.post(auth_uri, data=body, headers=headers)


async def handle_onetouch_auth(
    session: aiohttp.ClientSession,
    auth_uri: str,
    headers: Dict[str, str],
) -> str:
    """Handle OneTouch push notification authentication"""
    import sys

    print("\n" + "="*80, file=sys.stderr, flush=True)
    print("OneTouch Authentication Required", file=sys.stderr, flush=True)
    print("Please approve the push notification on your OneID app", file=sys.stderr, flush=True)
    print("="*80, file=sys.stderr, flush=True)

    # The push notification is already sent by the server
    # We just need to poll for authentication completion (max 120 seconds)
    max_attempts = 120
    for attempt in range(max_attempts):
        await asyncio.sleep(2)

        # Poll the server to check if authentication is complete
        try:
            resp = await send_user_credential_async(
                session, auth_uri, headers, [], Authenticator.OneTouch
            )
            xml_text = await resp.text()
        except Exception as e:
            continue

        try:
            parsed = ConfigAuthXml.read_xml(xml_text)

            # Check if we got a session token (success)
            if hasattr(parsed, 'SessionToken') and parsed.SessionToken:
                print("✓ Authentication approved!\n", file=sys.stderr, flush=True)
                return parsed.SessionToken

            # Check for failure
            if hasattr(parsed, 'AuthId') and parsed.AuthId.value == "failure":
                error_msg = parsed.Message if hasattr(parsed, 'Message') else "Authentication failed"
                raise Exception(f"OneTouch authentication failed: {error_msg}")

        except Exception as e:
            if "failure" in str(e) or "failed" in str(e):
                raise
            # Continue polling on other errors

        if (attempt + 1) % 10 == 0:
            print(f"Waiting... ({attempt + 1 * 2}s)", file=sys.stderr, flush=True)

    raise Exception("OneTouch authentication timed out after 240 seconds")


async def main():
    load_dotenv()

    server_uri = os.getenv("SERVER_URI") or ""
    auth_uri = f"{server_uri}/auth"
    username = os.getenv("UID_USERNAME") or "user"
    device = os.getenv("UID_DEVICE")
    if not device:
        raise SystemExit("ERROR: UID_DEVICE is not set in .env. Generate one with: echo -n \"$(hostname)-$(date +%s)\" | sha256sum | cut -d' ' -f1")

    package_version = (3, 11, 10, 0)   # Current version of OneConnect for Windows
    uid = compute_uid(username=username, seed=device)
    av_enabled, av_updated = True, True

    client_env = collect_client_environment(package_version, uid, av_enabled, av_updated, wolfssl_version="4.8.1")

    tunnel_cfg = TunnelConfiguration(
        dtls_allowed_cipher_suites=[
            "OC-DTLS1_2-AES128-GCM", 
            "OC-DTLS1_2-AES256-GCM"
        ],
        dtls12_allowed_cipher_suites=[
            "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-RSA-AES256-GCM-SHA384",
            "AES128-GCM-SHA256",
            "AES256-GCM-SHA384"
        ],
        dtls_pre_master_secret=os.urandom(48),  # or your negotiated value
    )

    headers = {}

    if client_env and tunnel_cfg:
        headers.update(build_request_headers(client_env, tunnel_cfg))

    cfg = ConfigAuthXml(clientEnvironment=client_env)
    xml_str = cfg.create_xml_document_string()

    address = ""
    client_id = ""
    nonce = ""

    async with aiohttp.ClientSession() as s:
        # Get the Entra Discovery endpoint and ClientId
        resp = await s.post(server_uri, data=xml_str, headers=headers)
        xml_text = await resp.text()
        import sys

        try:
            parsed = ConfigAuthXml.read_xml(xml_text)
            address = parsed.DiscoveryEndPoint
            client_id = parsed.ClientId
            nonce = parsed.Nonce

            # If no discovery endpoint, check if server is asking for username first
            if not address and parsed.Parameters:
                # Submit username
                username_param = [("username", username)]
                resp = await send_user_credential_async(
                    s, auth_uri, headers, username_param, Authenticator.Form
                )
                xml_text = await resp.text()

                # Parse the response again
                parsed = ConfigAuthXml.read_xml(xml_text)
                address = parsed.DiscoveryEndPoint
                client_id = parsed.ClientId
                nonce = parsed.Nonce

            # Check if server wants OneTouch authentication
            if hasattr(parsed, 'authenticator') and parsed.authenticator == Authenticator.OneTouch:
                session_token = await handle_onetouch_auth(s, auth_uri, headers)

                # Skip OIDC flow and jump to outputting the session token
                connect_uri = f"{server_uri}/CSCOSSLC/tunnel"
                resp = await s.request("CONNECT", connect_uri, headers=headers)
                print(f"webvpn={session_token}")
                return

            if not address:
                print("ERROR: Discovery endpoint is empty! Server might not support OIDC.", file=sys.stderr, flush=True)
                sys.exit(1)
        except Exception as e:
            print(f"ERROR parsing XML: {e}", file=sys.stderr, flush=True)
            import traceback
            traceback.print_exc()
            raise

        # Send the browser to the login screen and start a local server.
        oidc_result = await start_web_server_wait_on_response(address, client_id, nonce)

        params = [("id-token", oidc_result.id_token), ("refresh-token", oidc_result.refresh_token or "")]
        session_token = ""

        # Send the tokens to the VPN server to get the session token.
        resp = await send_user_credential_async(
            s, auth_uri, headers, params, Authenticator.OIDC,
        )
        xml_text = await resp.text()

        try:
            parsed = ConfigAuthXml.read_xml(xml_text)
            session_token = parsed.SessionToken
        except Exception as e:
            raise

        # Send a CONNECT command. Doesn't work without this even though OpenConnect should do it too?
        connect_uri = f"{server_uri}/CSCOSSLC/tunnel"
        resp = await s.request("CONNECT", connect_uri, headers=headers)

        print(f"webvpn={session_token}")

if __name__=="__main__":
    asyncio.run(main())
