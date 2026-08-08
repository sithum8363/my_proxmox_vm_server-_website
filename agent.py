"""Home-network Proxmox management agent.

Run this application only on the Ubuntu management VM. Publish it through a
Cloudflare Tunnel and protect requests with Cloudflare Access plus the
AGENT_SHARED_SECRET bearer token.
"""

import asyncio
import logging
import os
import secrets
import ssl
import time
from dataclasses import dataclass
from threading import Lock
from urllib.parse import quote, urlencode

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from proxmoxer import ProxmoxAPI
from proxmoxer.core import AuthenticationError, ResourceException
from requests.exceptions import RequestException
from websockets.asyncio.client import connect


load_dotenv()

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger(__name__)

app = FastAPI()
app.mount(
    "/novnc",
    StaticFiles(directory=os.getenv("NOVNC_DIRECTORY", "novnc")),
    name="novnc",
)


# Proxmox connection settings.
PVE_HOST = os.getenv("PVE_HOST", "")
PVE_PORT = int(os.getenv("PVE_PORT", "8006"))
PVE_NODE = os.getenv("PVE_NODE", "proxmox")
PVE_API_USER = os.getenv("PVE_API_USER", "")
PVE_TOKEN_NAME = os.getenv("PVE_TOKEN_NAME", "")
PVE_TOKEN_VALUE = os.getenv("PVE_TOKEN_VALUE", "")
PVE_VERIFY_SSL = os.getenv("PVE_VERIFY_SSL", "true").lower() == "true"

# Agent and panel settings.
AGENT_SHARED_SECRET = os.getenv("AGENT_SHARED_SECRET", "")
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "").rstrip("/")
TEMPLATE_ID = int(os.getenv("TEMPLATE_ID", "1000"))
MAX_USER_VMS = int(os.getenv("MAX_USER_VMS", "10"))
HOST_MEMORY_RESERVE_MB = int(os.getenv("HOST_MEMORY_RESERVE_MB", "2048"))
HIDDEN_VM_IDS = {
    int(value.strip())
    for value in os.getenv("HIDDEN_VM_IDS", "").split(",")
    if value.strip()
}

MEBIBYTE = 1024 * 1024
USER_SESSION_TTL_SECONDS = 8 * 60 * 60
CONSOLE_CONNECTION_TTL_SECONDS = 20


class LoginRequest(BaseModel):
    username: str
    password: str


@dataclass
class UserSession:
    username: str
    proxmox: ProxmoxAPI
    last_seen: float


@dataclass
class ConsoleConnection:
    vmid: int
    websocket_url: str
    auth_cookie: str
    created_at: float


user_sessions: dict[str, UserSession] = {}
user_sessions_lock = Lock()

console_connections: dict[str, ConsoleConnection] = {}
console_connections_lock = Lock()


@app.middleware("http")
async def authenticate_render(request: Request, call_next):
    """Require the Render-to-agent secret on every private HTTP endpoint."""

    # Health is public for monitoring. noVNC is static; its WebSocket requires
    # a short-lived, single-use connection ID from /api/console/{vmid}.
    is_public = (
        request.url.path == "/health"
        or request.url.path == "/novnc"
        or request.url.path.startswith("/novnc/")
    )

    if not is_public:
        supplied = request.headers.get("Authorization", "")
        expected = f"Bearer {AGENT_SHARED_SECRET}"

        if not AGENT_SHARED_SECRET or not secrets.compare_digest(
            supplied,
            expected,
        ):
            return JSONResponse(
                status_code=401,
                content={"detail": "Unauthorized agent request"},
            )

    return await call_next(request)


def get_service_proxmox() -> ProxmoxAPI:
    """Return the restricted service-token client used for capacity checks."""

    if not all(
        (
            PVE_HOST,
            PVE_API_USER,
            PVE_TOKEN_NAME,
            PVE_TOKEN_VALUE,
        )
    ):
        raise HTTPException(
            status_code=503,
            detail="Proxmox service token is not configured",
        )

    return ProxmoxAPI(
        PVE_HOST,
        port=PVE_PORT,
        user=PVE_API_USER,
        token_name=PVE_TOKEN_NAME,
        token_value=PVE_TOKEN_VALUE,
        verify_ssl=PVE_VERIFY_SSL,
    )


def get_user_session(request: Request) -> UserSession:
    session_token = request.headers.get("X-User-Session", "")
    now = time.monotonic()

    if not session_token:
        raise HTTPException(status_code=401, detail="User session is missing")

    with user_sessions_lock:
        session = user_sessions.get(session_token)

        if session is None:
            raise HTTPException(status_code=401, detail="User session is invalid")

        if session.last_seen < now - USER_SESSION_TTL_SECONDS:
            user_sessions.pop(session_token, None)
            raise HTTPException(status_code=401, detail="User session has expired")

        session.last_seen = now
        return session


def get_user_proxmox(request: Request) -> ProxmoxAPI:
    return get_user_session(request).proxmox


@app.exception_handler(ResourceException)
async def proxmox_error(_: Request, exc: ResourceException):
    """Return useful HTTP statuses without exposing Proxmox internals."""

    upstream_status = int(getattr(exc, "status_code", 502) or 502)
    logger.warning("Proxmox request failed: %s", exc)

    if upstream_status == 401:
        status_code = 401
        detail = "The Proxmox login has expired"
    elif upstream_status == 403:
        status_code = 403
        detail = "This Proxmox account does not have permission for that action"
    elif upstream_status == 404:
        status_code = 404
        detail = "The requested Proxmox resource was not found"
    elif 400 <= upstream_status < 500:
        status_code = upstream_status
        detail = "Proxmox rejected the request"
    else:
        status_code = 502
        detail = "Proxmox could not complete the request"

    return JSONResponse(status_code=status_code, content={"detail": detail})


def reject_template(vmid: int) -> None:
    if vmid == TEMPLATE_ID:
        raise HTTPException(
            status_code=403,
            detail="The template VM cannot be changed",
        )


def host_memory_bytes(proxmox: ProxmoxAPI) -> int:
    return int(proxmox.nodes(PVE_NODE).status.get()["memory"]["total"])


def create_vnc_connection(
    proxmox: ProxmoxAPI,
    vmid: int,
) -> tuple[str, str, str]:
    """Create a VNC proxy using the logged-in user's Proxmox ticket."""

    console = (
        proxmox.nodes(PVE_NODE)
        .qemu(vmid)
        .vncproxy.post(websocket=1, **{"generate-password": 1})
    )

    auth_ticket, _csrf_token = proxmox._backend.get_tokens()
    if not auth_ticket:
        raise HTTPException(
            status_code=401,
            detail="The Proxmox login ticket is unavailable",
        )

    query = urlencode(
        {
            "port": console["port"],
            "vncticket": console["ticket"],
        }
    )
    websocket_url = (
        f"wss://{PVE_HOST}:{PVE_PORT}/api2/json/nodes/"
        f"{PVE_NODE}/qemu/{vmid}/vncwebsocket?{query}"
    )

    return (
        websocket_url,
        f"PVEAuthCookie={auth_ticket}",
        console.get("password", console["ticket"]),
    )


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/auth/login")
def user_login(credentials: LoginRequest):
    """Authenticate a real Proxmox user such as student1@pve."""

    username = credentials.username.strip()

    if not PVE_HOST:
        raise HTTPException(status_code=503, detail="PVE_HOST is not configured")

    if "@" not in username:
        raise HTTPException(
            status_code=400,
            detail=(
                "Use the complete Proxmox username, "
                "for example student1@pve"
            ),
        )

    if not credentials.password:
        raise HTTPException(status_code=400, detail="Password is required")

    try:
        # ProxmoxAPI performs the /access/ticket login during construction.
        user_proxmox = ProxmoxAPI(
            PVE_HOST,
            port=PVE_PORT,
            user=username,
            password=credentials.password,
            verify_ssl=PVE_VERIFY_SSL,
        )
    except AuthenticationError:
        raise HTTPException(
            status_code=401,
            detail="Invalid Proxmox username or password",
        ) from None
    except RequestException:
        logger.exception("Could not contact Proxmox while logging in")
        raise HTTPException(
            status_code=503,
            detail="The Proxmox server is unavailable",
        ) from None

    session_token = secrets.token_urlsafe(48)
    now = time.monotonic()

    with user_sessions_lock:
        expired_tokens = [
            token
            for token, session in user_sessions.items()
            if session.last_seen < now - USER_SESSION_TTL_SECONDS
        ]
        for token in expired_tokens:
            user_sessions.pop(token, None)

        user_sessions[session_token] = UserSession(
            username=username,
            proxmox=user_proxmox,
            last_seen=now,
        )

    return {"username": username, "session_token": session_token}


@app.post("/auth/logout")
def user_logout(request: Request):
    session_token = request.headers.get("X-User-Session", "")

    if session_token:
        with user_sessions_lock:
            user_sessions.pop(session_token, None)

    return {"ok": True}


@app.get("/vms")
def list_vms(request: Request):
    proxmox = get_user_proxmox(request)
    vms = proxmox.nodes(PVE_NODE).qemu.get()

    return [
        {
            "vmid": vm["vmid"],
            "name": vm.get("name", f"VM {vm['vmid']}"),
            "status": vm.get("status", "unknown"),
            "cpu": vm.get("cpu", 0),
            "memory": vm.get("mem", 0),
            "max_memory": vm.get("maxmem", 0),
        }
        for vm in vms
        if vm["vmid"] != TEMPLATE_ID and vm["vmid"] not in HIDDEN_VM_IDS
    ]


@app.get("/capacity")
def capacity(request: Request):
    # Require a website user session, but use the read-only service token for
    # global host capacity because a VM-only user may not have Sys.Audit.
    get_user_session(request)
    proxmox = get_service_proxmox()
    vms = proxmox.nodes(PVE_NODE).qemu.get()
    total = host_memory_bytes(proxmox)
    safe = max(0, total - HOST_MEMORY_RESERVE_MB * MEBIBYTE)
    allocated = sum(
        int(vm.get("maxmem", 0))
        for vm in vms
        if vm.get("status") == "running"
    )

    return {
        "available": True,
        "host_memory_mb": total // MEBIBYTE,
        "reserve_mb": HOST_MEMORY_RESERVE_MB,
        "safe_vm_memory_mb": safe // MEBIBYTE,
        "allocated_vm_memory_mb": allocated // MEBIBYTE,
        "available_vm_memory_mb": max(0, safe - allocated) // MEBIBYTE,
    }


@app.post("/vms")
def create_vm(name: str, vmid: int, request: Request):
    reject_template(vmid)
    proxmox = get_user_proxmox(request)
    vms = proxmox.nodes(PVE_NODE).qemu.get()

    if vmid in {vm["vmid"] for vm in vms}:
        raise HTTPException(status_code=409, detail="This VM ID is already in use")

    visible_user_vms = [vm for vm in vms if vm["vmid"] != TEMPLATE_ID]
    if len(visible_user_vms) >= MAX_USER_VMS:
        raise HTTPException(
            status_code=429,
            detail=f"VM limit reached ({MAX_USER_VMS} VMs)",
        )

    task = (
        proxmox.nodes(PVE_NODE)
        .qemu(TEMPLATE_ID)
        .clone.post(newid=vmid, name=name, full=1)
    )
    return {"task": task}


@app.delete("/vms/{vmid}")
def delete_vm(vmid: int, request: Request):
    reject_template(vmid)
    proxmox = get_user_proxmox(request)
    vm = proxmox.nodes(PVE_NODE).qemu(vmid)

    if vm.status.current.get()["status"] == "running":
        vm.status.stop.post()
        raise HTTPException(
            status_code=409,
            detail="VM is stopping; delete it after it has stopped",
        )

    return {"task": vm.delete(purge=1)}


@app.post("/vms/{vmid}/start")
def start_vm(vmid: int, request: Request):
    reject_template(vmid)
    proxmox = get_user_proxmox(request)
    vm = proxmox.nodes(PVE_NODE).qemu(vmid)

    if vm.status.current.get()["status"] == "running":
        raise HTTPException(status_code=409, detail="The VM is already running")

    return {"task": vm.status.start.post()}


@app.post("/vms/{vmid}/stop")
def stop_vm(vmid: int, request: Request):
    reject_template(vmid)
    proxmox = get_user_proxmox(request)
    vm = proxmox.nodes(PVE_NODE).qemu(vmid)

    if vm.status.current.get()["status"] != "running":
        raise HTTPException(status_code=409, detail="The VM is not running")

    return {"task": vm.status.stop.post()}


@app.get("/api/console/{vmid}")
def console(vmid: int, request: Request):
    reject_template(vmid)
    proxmox = get_user_proxmox(request)

    if proxmox.nodes(PVE_NODE).qemu(vmid).status.current.get()["status"] != "running":
        raise HTTPException(
            status_code=409,
            detail="Start the VM before opening its console",
        )

    if not PUBLIC_BASE_URL:
        raise HTTPException(
            status_code=503,
            detail="PUBLIC_BASE_URL is not configured",
        )

    websocket_url, auth_cookie, vnc_password = create_vnc_connection(
        proxmox,
        vmid,
    )
    connection_id = secrets.token_urlsafe(32)
    now = time.monotonic()

    with console_connections_lock:
        expired_ids = [
            item_id
            for item_id, item in console_connections.items()
            if item.created_at < now - CONSOLE_CONNECTION_TTL_SECONDS
        ]
        for item_id in expired_ids:
            console_connections.pop(item_id, None)

        console_connections[connection_id] = ConsoleConnection(
            vmid=vmid,
            websocket_url=websocket_url,
            auth_cookie=auth_cookie,
            created_at=now,
        )

    # The leading slash is required. Without it, noVNC requests
    # /novnc/ws/console/... and Starlette StaticFiles rejects the WebSocket.
    query = urlencode(
        {
            "autoconnect": 1,
             "reconnect": 0,
            "logging": "debug",
            "path": f"/ws/console/{vmid}?connection_id={connection_id}",
        }
    )
    console_url = (
        f"{PUBLIC_BASE_URL}/novnc/vnc_lite.html?{query}"
        f"#password={quote(vnc_password, safe='')}"
    )
    return {"console_url": console_url}


@app.websocket("/ws/console/{vmid}")
async def console_websocket(websocket: WebSocket, vmid: int):
    connection_id = websocket.query_params.get("connection_id")

    with console_connections_lock:
        entry = (
            console_connections.pop(connection_id, None)
            if connection_id
            else None
        )

    if (
        entry is None
        or entry.vmid != vmid
        or entry.created_at
        < time.monotonic() - CONSOLE_CONNECTION_TTL_SECONDS
    ):
        await websocket.close(code=1008)
        return

    await websocket.accept(subprotocol="binary")

    try:
        ssl_context = ssl.create_default_context()
        if not PVE_VERIFY_SSL:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

        async with connect(
            entry.websocket_url,
            ssl=ssl_context,
            origin=f"https://{PVE_HOST}:{PVE_PORT}",
            additional_headers={"Cookie": entry.auth_cookie},
            subprotocols=["binary"],
            proxy=None,
        ) as pve_socket:

            async def browser_to_pve():
                while True:
                    message = await websocket.receive()

                    if message["type"] == "websocket.disconnect":
                        return

                    if message.get("bytes") is not None:
                        await pve_socket.send(message["bytes"])
                    elif message.get("text") is not None:
                        await pve_socket.send(message["text"])

            async def pve_to_browser():
                async for message in pve_socket:
                    if isinstance(message, bytes):
                        await websocket.send_bytes(message)
                    else:
                        await websocket.send_text(message)

            done, pending = await asyncio.wait(
                {
                    asyncio.create_task(browser_to_pve()),
                    asyncio.create_task(pve_to_browser()),
                },
                return_when=asyncio.FIRST_COMPLETED,
            )

            for task in pending:
                task.cancel()

            await asyncio.gather(*pending, return_exceptions=True)
            await asyncio.gather(*done)

    except WebSocketDisconnect:
        return
    except Exception:
        logger.exception("Console connection failed for VM %s", vmid)
        try:
            await websocket.close(code=1011)
        except RuntimeError:
            pass
