import os
import asyncio
import logging
import secrets
import socket
import ssl
import time
from dataclasses import dataclass
from threading import Lock
from urllib.parse import urlencode

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
from proxmoxer.core import ResourceException
from starlette.responses import JSONResponse
from starlette.middleware.sessions import SessionMiddleware
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from proxmoxer import ProxmoxAPI
from websockets.asyncio.client import connect

load_dotenv()

app = FastAPI()
app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SESSION_SECRET", secrets.token_urlsafe(32)),
    https_only=os.getenv("SESSION_HTTPS_ONLY", "false").lower() == "true",
    same_site="lax",
)

templates = Jinja2Templates(directory="templates")

app.mount("/static", StaticFiles(directory="assets"), name="static")
app.mount("/novnc", StaticFiles(directory="novnc"), name="novnc")

NODE = "proxmox"
TEMPLATE_ID = 1000
# These VMs remain available in Proxmox but are intentionally omitted from the
# cloud panel's VM list.
HIDDEN_VM_IDS = {11111111}
PVE_HOST = "192.168.1.18"
PVE_PORT = int(os.getenv("PVE_PORT", "8006"))
PVE_HEALTHCHECK_TIMEOUT_SECONDS = float(os.getenv("PVE_HEALTHCHECK_TIMEOUT_SECONDS", "2"))
SUPPORT_WHATSAPP_NUMBER = os.getenv("SUPPORT_WHATSAPP_NUMBER", "94779304675")
logger = logging.getLogger(__name__)
CONSOLE_CONNECTION_TTL_SECONDS = 20
MAX_USER_VMS = int(os.getenv("MAX_USER_VMS", "10"))
PENDING_CREATION_TTL_SECONDS = 600
HOST_MEMORY_RESERVE_MB = int(os.getenv("HOST_MEMORY_RESERVE_MB", "2048"))
# A PVEVMUser can control a VM but is not normally allowed to inspect node-wide
# memory.  Set this when that role must still be subject to the panel's memory
# reservation check, without granting it the broader Sys.Audit permission.
HOST_MEMORY_TOTAL_MB = int(os.getenv("HOST_MEMORY_TOTAL_MB", "0"))
REQUIRE_HOST_MEMORY_AUDIT = os.getenv("REQUIRE_HOST_MEMORY_AUDIT", "false").lower() == "true"
PENDING_START_TTL_SECONDS = 120
MEBIBYTE = 1024 * 1024
WEB_SESSION_TTL_SECONDS = 8 * 60 * 60
console_connections: dict[str, tuple[str, str, float]] = {}
console_connections_lock = Lock()
pending_creations: dict[int, float] = {}
pending_creations_lock = Lock()
pending_starts: dict[int, tuple[int, float]] = {}
pending_starts_lock = Lock()
web_sessions: dict[str, "WebSession"] = {}
web_sessions_lock = Lock()


class LoginRequest(BaseModel):
    username: str
    password: str


@dataclass
class WebSession:
    username: str
    client: ProxmoxAPI
    expires_at: float


def proxmox_permission_detail() -> str:
    return (
        "Proxmox denied this action. PVEVMUser must be assigned to /vms or the "
        "specific VM. It can view, use the console, and start or stop permitted "
        "VMs; cloning and deleting require additional Proxmox privileges."
    )


def proxmox_is_available() -> bool:
    """Return whether the Proxmox HTTPS service can be reached from this panel."""
    try:
        with socket.create_connection(
            (PVE_HOST, PVE_PORT), timeout=PVE_HEALTHCHECK_TIMEOUT_SECONDS
        ):
            return True
    except OSError:
        return False


@app.exception_handler(ResourceException)
async def proxmox_resource_exception_handler(_: Request, exc: ResourceException):
    if exc.status_code == 401:
        return JSONResponse(status_code=401, content={"detail": "Your Proxmox session is no longer valid. Please sign in again."})
    if exc.status_code == 403:
        return JSONResponse(status_code=403, content={"detail": proxmox_permission_detail()})

    logger.warning("Proxmox API request failed: %s", exc)
    return JSONResponse(status_code=502, content={"detail": "Proxmox could not complete the request. Please try again."})


def get_session_client(session_id: str | None) -> ProxmoxAPI:
    if not session_id:
        raise HTTPException(status_code=401, detail="Please sign in with your Proxmox account")

    with web_sessions_lock:
        session = web_sessions.get(session_id)
        if session is None or session.expires_at < time.monotonic():
            web_sessions.pop(session_id, None)
            raise HTTPException(status_code=401, detail="Your session has expired. Please sign in again")

        session.expires_at = time.monotonic() + WEB_SESSION_TTL_SECONDS
        return session.client


def get_proxmox(request: Request) -> ProxmoxAPI:
    return get_session_client(request.session.get("session_id"))


def wait_for_task(proxmox: ProxmoxAPI, task_id: str, timeout_seconds: int = 120) -> None:
    deadline = time.monotonic() + timeout_seconds

    while time.monotonic() < deadline:
        status = proxmox.nodes(NODE).tasks(task_id).status.get()
        if status["status"] == "stopped":
            if status.get("exitstatus") == "OK":
                return
            raise HTTPException(
                status_code=500,
                detail=f"Proxmox task failed: {status.get('exitstatus', 'unknown error')}",
            )
        time.sleep(1)

    raise HTTPException(status_code=409, detail="Timed out waiting for VM to stop")


def create_vnc_connection(proxmox: ProxmoxAPI, vmid: int) -> tuple[str, str, str]:
    console = proxmox.nodes(NODE).qemu(vmid).vncproxy.post(
        websocket=1,
        **{"generate-password": 1},
    )
    auth_ticket, _ = proxmox.get_tokens()
    if not auth_ticket:
        raise RuntimeError("Could not get the Proxmox authentication ticket")

    query = urlencode({"port": console["port"], "vncticket": console["ticket"]})
    websocket_url = (
        f"wss://{PVE_HOST}:8006/api2/json/nodes/{NODE}/qemu/{vmid}/vncwebsocket?{query}"
    )
    return websocket_url, auth_ticket, console.get("password", console["ticket"])


def discard_expired_console_connections() -> None:
    with console_connections_lock:
        expiry = time.monotonic() - CONSOLE_CONNECTION_TTL_SECONDS
        expired_ids = [
            connection_id
            for connection_id, (_, _, created_at) in console_connections.items()
            if created_at < expiry
        ]
        for connection_id in expired_ids:
            del console_connections[connection_id]


def clean_pending_creations(existing_vm_ids: set[int]) -> None:
    expiry = time.monotonic() - PENDING_CREATION_TTL_SECONDS
    with pending_creations_lock:
        for vmid, created_at in list(pending_creations.items()):
            if vmid in existing_vm_ids or created_at < expiry:
                del pending_creations[vmid]


def vm_memory_bytes(vm: dict) -> int:
    return int(vm.get("maxmem", 0))


def get_host_memory_bytes(proxmox: ProxmoxAPI) -> int | None:
    """Get host memory without requiring PVEVMUser to have Sys.Audit when configured."""
    if HOST_MEMORY_TOTAL_MB > 0:
        return HOST_MEMORY_TOTAL_MB * MEBIBYTE

    try:
        return int(proxmox.nodes(NODE).status.get()["memory"]["total"])
    except ResourceException as exc:
        if exc.status_code != 403 or REQUIRE_HOST_MEMORY_AUDIT:
            raise
        logger.info("Skipping host-memory check because the signed-in user lacks Sys.Audit")
        return None


def clean_pending_starts(vms: list[dict]) -> None:
    running_vm_ids = {vm["vmid"] for vm in vms if vm.get("status") == "running"}
    expiry = time.monotonic() - PENDING_START_TTL_SECONDS
    with pending_starts_lock:
        for vmid, (_, started_at) in list(pending_starts.items()):
            if vmid in running_vm_ids or started_at < expiry:
                del pending_starts[vmid]


def reserve_memory_for_start(proxmox: ProxmoxAPI, vmid: int, vms: list[dict]) -> None:
    vm = next((item for item in vms if item["vmid"] == vmid), None)
    if vm is None:
        raise HTTPException(status_code=404, detail="VM was not found")

    vm_memory = vm_memory_bytes(vm)
    if vm_memory <= 0:
        raise HTTPException(status_code=409, detail="The VM memory configuration is unavailable")

    host_memory = get_host_memory_bytes(proxmox)
    if host_memory is None:
        # PVEVMUser has VM.PowerMgmt but not normally Sys.Audit. Do not block
        # power control solely because the account cannot read node-wide data.
        return
    allowed_vm_memory = max(0, host_memory - HOST_MEMORY_RESERVE_MB * MEBIBYTE)

    clean_pending_starts(vms)
    with pending_starts_lock:
        allocated_memory = sum(
            vm_memory_bytes(item)
            for item in vms
            if item["vmid"] != vmid and item.get("status") == "running"
        )
        allocated_memory += sum(memory for memory, _ in pending_starts.values())

        if allocated_memory + vm_memory > allowed_vm_memory:
            available_mb = max(0, (allowed_vm_memory - allocated_memory) // MEBIBYTE)
            required_mb = vm_memory // MEBIBYTE
            raise HTTPException(
                status_code=409,
                detail=(
                    f"Not enough safe host memory. This VM needs {required_mb} MB, "
                    f"but only {available_mb} MB is available after reserving "
                    f"{HOST_MEMORY_RESERVE_MB} MB for Proxmox."
                ),
            )

        pending_starts[vmid] = (vm_memory, time.monotonic())

@app.get("/")
def home(request: Request):
    if not proxmox_is_available():
        logger.warning("Proxmox service is unavailable at %s:%s", PVE_HOST, PVE_PORT)
        return templates.TemplateResponse(
            request=request,
            name="maintenance.html",
            context={"support_whatsapp_number": SUPPORT_WHATSAPP_NUMBER},
            status_code=503,
        )

    try:
        get_proxmox(request)
    except HTTPException:
        return templates.TemplateResponse(request=request, name="login.html", context={})

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={}
    )


@app.post("/auth/login")
def login(credentials: LoginRequest, request: Request):
    username = credentials.username.strip()
    if not username or not credentials.password:
        raise HTTPException(status_code=400, detail="Username and password are required")

    try:
        client = ProxmoxAPI(
            PVE_HOST,
            user=username,
            password=credentials.password,
            verify_ssl=False,
        )
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid Proxmox username or password") from None

    session_id = secrets.token_urlsafe(32)
    with web_sessions_lock:
        web_sessions[session_id] = WebSession(
            username=username,
            client=client,
            expires_at=time.monotonic() + WEB_SESSION_TTL_SECONDS,
        )

    request.session.clear()
    request.session["session_id"] = session_id
    return {"username": username}


@app.get("/auth/me")
def current_user(request: Request):
    session_id = request.session.get("session_id")
    get_session_client(session_id)
    with web_sessions_lock:
        return {"username": web_sessions[session_id].username}


@app.post("/auth/logout")
def logout(request: Request):
    session_id = request.session.get("session_id")
    with web_sessions_lock:
        if session_id:
            web_sessions.pop(session_id, None)
    request.session.clear()
    return {"ok": True}


@app.get("/vms")
def list_vms(request: Request):
    proxmox = get_proxmox(request)
    vms=proxmox.nodes(NODE).qemu.get()
    clean_pending_creations({vm["vmid"] for vm in vms})
    clean_pending_starts(vms)
    result = []
    for vm in vms:
        if vm["vmid"] == TEMPLATE_ID or vm["vmid"] in HIDDEN_VM_IDS:
            continue
        result.append({
            "vmid": vm["vmid"],
            "name": vm.get("name", f"VM {vm['vmid']}"),
            "status": vm.get("status", "unknown"),
            "cpu": vm.get("cpu", 0),
            "memory": vm.get("mem", 0),
            "max_memory": vm.get("maxmem", 0),
        })

    return result


@app.get("/capacity")
def get_capacity(request: Request):
    proxmox = get_proxmox(request)
    vms = proxmox.nodes(NODE).qemu.get()
    host_memory = get_host_memory_bytes(proxmox)
    if host_memory is None:
        return {"available": False}
    safe_vm_memory = max(0, host_memory - HOST_MEMORY_RESERVE_MB * MEBIBYTE)
    allocated_memory = sum(
        vm_memory_bytes(vm)
        for vm in vms
        if vm["vmid"] != TEMPLATE_ID and vm.get("status") == "running"
    )

    return {
        "available": True,
        "host_memory_mb": host_memory // MEBIBYTE,
        "reserve_mb": HOST_MEMORY_RESERVE_MB,
        "safe_vm_memory_mb": safe_vm_memory // MEBIBYTE,
        "allocated_vm_memory_mb": allocated_memory // MEBIBYTE,
        "available_vm_memory_mb": max(0, safe_vm_memory - allocated_memory) // MEBIBYTE,
    }

@app.post("/vms")
def create_vm(name: str, vmid: int, request: Request):
    proxmox = get_proxmox(request)
    if vmid == TEMPLATE_ID:
        raise HTTPException(status_code=400, detail="VM ID 1000 is reserved for the template")

    vms = proxmox.nodes(NODE).qemu.get()
    existing_vm_ids = {vm["vmid"] for vm in vms}
    clean_pending_creations(existing_vm_ids)

    with pending_creations_lock:
        if vmid in existing_vm_ids or vmid in pending_creations:
            raise HTTPException(status_code=409, detail="This VM ID is already in use")

        user_vm_count = sum(vm["vmid"] != TEMPLATE_ID for vm in vms)
        if user_vm_count + len(pending_creations) >= MAX_USER_VMS:
            raise HTTPException(
                status_code=429,
                detail=f"VM limit reached ({MAX_USER_VMS} VMs)",
            )

        pending_creations[vmid] = time.monotonic()

    try:
        task = proxmox.nodes(NODE).qemu(TEMPLATE_ID).clone.post(
            newid=vmid,
            name=name,
            full=1,
        )
    except ResourceException as exc:
        with pending_creations_lock:
            pending_creations.pop(vmid, None)
        if exc.status_code == 403:
            raise HTTPException(
                status_code=403,
                detail=(
                    "PVEVMUser cannot clone VMs. Assign VM.Allocate and VM.Clone "
                    "(or use a separate VM-creator role) to create a VM."
                ),
            ) from None
        raise HTTPException(
            status_code=502,
            detail="Proxmox rejected the clone request. Check the template and storage configuration.",
        ) from None
    except Exception:
        with pending_creations_lock:
            pending_creations.pop(vmid, None)
        logger.exception("VM clone request failed for VM %s", vmid)
        raise HTTPException(
            status_code=502,
            detail="The VM clone request could not be completed. Please try again.",
        ) from None

    print("create_vm",name,vmid)
    return {"task": task}


@app.delete("/vms/{vmid}")
def delete_vm(vmid: int, request: Request):
    proxmox = get_proxmox(request)
    if vmid == TEMPLATE_ID:
        raise HTTPException(status_code=403, detail="The template VM cannot be deleted")

    vm = proxmox.nodes(NODE).qemu(vmid)

    if vm.status.current.get()["status"] == "running":
        stop_task = vm.status.stop.post()
        wait_for_task(proxmox, stop_task)

    return {"task": vm.delete(purge=1)}


@app.post("/vms/{vmid}/start")
def start_vm(vmid: int, request: Request):
    proxmox = get_proxmox(request)
    if vmid == TEMPLATE_ID:
        raise HTTPException(status_code=403, detail="The template VM cannot be started")

    vm = proxmox.nodes(NODE).qemu(vmid)
    if vm.status.current.get()["status"] == "running":
        raise HTTPException(status_code=409, detail="The VM is already running")

    vms = proxmox.nodes(NODE).qemu.get()
    reserve_memory_for_start(proxmox, vmid, vms)

    try:
        task = vm.status.start.post()
        wait_for_task(proxmox, task, timeout_seconds=30)
        return {"task": task}
    except Exception:
        with pending_starts_lock:
            pending_starts.pop(vmid, None)
        raise


@app.post("/vms/{vmid}/stop")
def stop_vm(vmid: int, request: Request):
    proxmox = get_proxmox(request)
    if vmid == TEMPLATE_ID:
        raise HTTPException(status_code=403, detail="The template VM cannot be stopped")

    vm = proxmox.nodes(NODE).qemu(vmid)
    if vm.status.current.get()["status"] != "running":
        raise HTTPException(status_code=409, detail="The VM is not running")

    with pending_starts_lock:
        pending_starts.pop(vmid, None)

    return {"task": vm.status.stop.post()}


@app.get("/api/console/{vmid}")
def api_console(vmid: int, request: Request):
    proxmox = get_proxmox(request)
    if vmid == TEMPLATE_ID:
        raise HTTPException(status_code=403, detail="The template VM has no user console")

    vm = proxmox.nodes(NODE).qemu(vmid)
    if vm.status.current.get()["status"] != "running":
        raise HTTPException(status_code=409, detail="Start the VM before opening its console")

    websocket_url, auth_ticket, vnc_password = create_vnc_connection(proxmox, vmid)
    discard_expired_console_connections()
    connection_id = secrets.token_urlsafe(32)
    with console_connections_lock:
        console_connections[connection_id] = (websocket_url, auth_ticket, time.monotonic())
    return {"connection_id": connection_id, "vnc_password": vnc_password}


@app.websocket("/ws/console/{vmid}")
async def console_websocket(websocket: WebSocket, vmid: int):
    if vmid == TEMPLATE_ID:
        await websocket.close(code=1008)
        return

    try:
        get_session_client(websocket.session.get("session_id"))
    except HTTPException:
        await websocket.close(code=1008)
        return

    connection_id = websocket.query_params.get("connection_id")
    with console_connections_lock:
        connection = console_connections.pop(connection_id, None) if connection_id else None
    if connection is None:
        await websocket.close(code=1008)
        return

    await websocket.accept()

    try:
        websocket_url, auth_ticket, _ = connection
        ssl_context = ssl._create_unverified_context()

        async with connect(
            websocket_url,
            ssl=ssl_context,
            origin=f"https://{PVE_HOST}:8006",
            additional_headers={"Cookie": f"PVEAuthCookie={auth_ticket}"},
        ) as proxmox_websocket:
            async def browser_to_proxmox():
                while True:
                    message = await websocket.receive()
                    if message["type"] == "websocket.disconnect":
                        return
                    if message.get("bytes") is not None:
                        await proxmox_websocket.send(message["bytes"])
                    elif message.get("text") is not None:
                        await proxmox_websocket.send(message["text"])

            async def proxmox_to_browser():
                async for message in proxmox_websocket:
                    if isinstance(message, bytes):
                        await websocket.send_bytes(message)
                    else:
                        await websocket.send_text(message)

            browser_task = asyncio.create_task(browser_to_proxmox())
            proxmox_task = asyncio.create_task(proxmox_to_browser())
            done, pending = await asyncio.wait(
                {browser_task, proxmox_task},
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            for task in done:
                task.result()
    except WebSocketDisconnect:
        return
    except Exception:
        logger.exception("VM console connection failed for VM %s", vmid)
        await websocket.close(code=1011)
