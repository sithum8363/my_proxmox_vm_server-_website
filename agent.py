"""Home-network Proxmox agent.

Run this only on the Ubuntu management VM.  Publish it through Cloudflare
Tunnel and require both Cloudflare Access and AGENT_SHARED_SECRET  ;';.
"""
import asyncio
import logging
import os
import secrets
import ssl
import time
from threading import Lock
from urllib.parse import quote, urlencode

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from proxmoxer import ProxmoxAPI
from proxmoxer.core import ResourceException
from websockets.asyncio.client import connect

load_dotenv()
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger(__name__)

app = FastAPI()
app.mount("/novnc", StaticFiles(directory=os.getenv("NOVNC_DIRECTORY", "novnc")), name="novnc")

PVE_HOST = os.getenv("PVE_HOST", "")
PVE_PORT = int(os.getenv("PVE_PORT", "8006"))
PVE_NODE = os.getenv("PVE_NODE", "proxmox")
PVE_API_USER = os.getenv("PVE_API_USER", "")
PVE_TOKEN_NAME = os.getenv("PVE_TOKEN_NAME", "")
PVE_TOKEN_VALUE = os.getenv("PVE_TOKEN_VALUE", "")
PVE_VERIFY_SSL = os.getenv("PVE_VERIFY_SSL", "true").lower() == "true"
AGENT_SHARED_SECRET = os.getenv("AGENT_SHARED_SECRET", "")
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "").rstrip("/")
TEMPLATE_ID = int(os.getenv("TEMPLATE_ID", "1000"))
MAX_USER_VMS = int(os.getenv("MAX_USER_VMS", "10"))
HOST_MEMORY_RESERVE_MB = int(os.getenv("HOST_MEMORY_RESERVE_MB", "2048"))
HIDDEN_VM_IDS = {int(value) for value in os.getenv("HIDDEN_VM_IDS", "").split(",") if value.strip()}
CONSOLE_CONNECTION_TTL_SECONDS = 20
MEBIBYTE = 1024 * 1024
console_connections: dict[str, tuple[str, str, float]] = {}
console_connections_lock = Lock()


@app.middleware("http")
async def authenticate_render(request: Request, call_next):
    # /health is intentionally public so Cloudflare/Render can monitor it.
    # noVNC is a static browser application. Its WebSocket still requires a
    # one-time ticket created by the authenticated /api/console endpoint.
    if request.url.path != "/health" and not request.url.path.startswith("/novnc/"):
        supplied = request.headers.get("Authorization", "")
        expected = f"Bearer {AGENT_SHARED_SECRET}"
        if not AGENT_SHARED_SECRET or not secrets.compare_digest(supplied, expected):
            return JSONResponse(status_code=401, content={"detail": "Unauthorized agent request"})
    return await call_next(request)


def get_proxmox() -> ProxmoxAPI:
    if not all((PVE_HOST, PVE_API_USER, PVE_TOKEN_NAME, PVE_TOKEN_VALUE)):
        raise HTTPException(status_code=503, detail="Proxmox agent is not configured")
    return ProxmoxAPI(
        PVE_HOST,
        port=PVE_PORT,
        user=PVE_API_USER,
        token_name=PVE_TOKEN_NAME,
        token_value=PVE_TOKEN_VALUE,
        verify_ssl=PVE_VERIFY_SSL,
    )


@app.exception_handler(ResourceException)
async def proxmox_error(_: Request, exc: ResourceException):
    logger.warning("Proxmox request failed: %s", exc)
    return JSONResponse(status_code=502, content={"detail": "Proxmox could not complete the request"})


def reject_template(vmid: int) -> None:
    if vmid == TEMPLATE_ID:
        raise HTTPException(status_code=403, detail="The template VM cannot be changed")


def host_memory_bytes(proxmox: ProxmoxAPI) -> int:
    return int(proxmox.nodes(PVE_NODE).status.get()["memory"]["total"])


def create_vnc_connection(proxmox: ProxmoxAPI, vmid: int) -> tuple[str, str, str]:
    console = proxmox.nodes(PVE_NODE).qemu(vmid).vncproxy.post(websocket=1, **{"generate-password": 1})
    query = urlencode({"port": console["port"], "vncticket": console["ticket"]})
    return (
        f"wss://{PVE_HOST}:{PVE_PORT}/api2/json/nodes/{PVE_NODE}/qemu/{vmid}/vncwebsocket?{query}",
        f"PVEAPIToken={PVE_API_USER}!{PVE_TOKEN_NAME}={PVE_TOKEN_VALUE}",
        console.get("password", console["ticket"]),
    )


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/vms")
def list_vms():
    vms = get_proxmox().nodes(PVE_NODE).qemu.get()
    return [
        {"vmid": vm["vmid"], "name": vm.get("name", f"VM {vm['vmid']}"), "status": vm.get("status", "unknown"),
         "cpu": vm.get("cpu", 0), "memory": vm.get("mem", 0), "max_memory": vm.get("maxmem", 0)}
        for vm in vms if vm["vmid"] != TEMPLATE_ID and vm["vmid"] not in HIDDEN_VM_IDS
    ]


@app.get("/capacity")
def capacity():
    proxmox = get_proxmox()
    vms = proxmox.nodes(PVE_NODE).qemu.get()
    total = host_memory_bytes(proxmox)
    safe = max(0, total - HOST_MEMORY_RESERVE_MB * MEBIBYTE)
    allocated = sum(int(vm.get("maxmem", 0)) for vm in vms if vm.get("status") == "running")
    return {"available": True, "host_memory_mb": total // MEBIBYTE, "reserve_mb": HOST_MEMORY_RESERVE_MB,
            "safe_vm_memory_mb": safe // MEBIBYTE, "allocated_vm_memory_mb": allocated // MEBIBYTE,
            "available_vm_memory_mb": max(0, safe - allocated) // MEBIBYTE}


@app.post("/vms")
def create_vm(name: str, vmid: int):
    reject_template(vmid)
    proxmox = get_proxmox()
    vms = proxmox.nodes(PVE_NODE).qemu.get()
    if vmid in {vm["vmid"] for vm in vms}:
        raise HTTPException(status_code=409, detail="This VM ID is already in use")
    if sum(vm["vmid"] != TEMPLATE_ID for vm in vms) >= MAX_USER_VMS:
        raise HTTPException(status_code=429, detail=f"VM limit reached ({MAX_USER_VMS} VMs)")
    return {"task": proxmox.nodes(PVE_NODE).qemu(TEMPLATE_ID).clone.post(newid=vmid, name=name, full=1)}


@app.delete("/vms/{vmid}")
def delete_vm(vmid: int):
    reject_template(vmid)
    vm = get_proxmox().nodes(PVE_NODE).qemu(vmid)
    if vm.status.current.get()["status"] == "running":
        vm.status.stop.post()
        raise HTTPException(status_code=409, detail="VM is stopping; delete it after it has stopped")
    return {"task": vm.delete(purge=1)}


@app.post("/vms/{vmid}/start")
def start_vm(vmid: int):
    reject_template(vmid)
    vm = get_proxmox().nodes(PVE_NODE).qemu(vmid)
    if vm.status.current.get()["status"] == "running":
        raise HTTPException(status_code=409, detail="The VM is already running")
    return {"task": vm.status.start.post()}


@app.post("/vms/{vmid}/stop")
def stop_vm(vmid: int):
    reject_template(vmid)
    vm = get_proxmox().nodes(PVE_NODE).qemu(vmid)
    if vm.status.current.get()["status"] != "running":
        raise HTTPException(status_code=409, detail="The VM is not running")
    return {"task": vm.status.stop.post()}


@app.get("/api/console/{vmid}")
def console(vmid: int):
    reject_template(vmid)
    proxmox = get_proxmox()
    if proxmox.nodes(PVE_NODE).qemu(vmid).status.current.get()["status"] != "running":
        raise HTTPException(status_code=409, detail="Start the VM before opening its console")
    if not PUBLIC_BASE_URL:
        raise HTTPException(status_code=503, detail="PUBLIC_BASE_URL is not configured")
    websocket_url, authorization, vnc_password = create_vnc_connection(proxmox, vmid)
    connection_id = secrets.token_urlsafe(32)
    with console_connections_lock:
        console_connections[connection_id] = (websocket_url, authorization, time.monotonic())
    path = urlencode({"autoconnect": 1, "path": f"/ws/console/{vmid}?connection_id={connection_id}"})
    return {"console_url": f"{PUBLIC_BASE_URL}/novnc/vnc.html?{path}#password={quote(vnc_password, safe='')}"}


@app.websocket("/ws/console/{vmid}")
async def console_websocket(websocket: WebSocket, vmid: int):
    connection_id = websocket.query_params.get("connection_id")
    with console_connections_lock:
        entry = console_connections.pop(connection_id, None) if connection_id else None
    if not entry or entry[2] < time.monotonic() - CONSOLE_CONNECTION_TTL_SECONDS:
        await websocket.close(code=1008)
        return
    await websocket.accept()
    websocket_url, authorization, _ = entry
    try:
        ssl_context = ssl.create_default_context() if PVE_VERIFY_SSL else ssl._create_unverified_context()
        async with connect(websocket_url, ssl=ssl_context, origin=f"https://{PVE_HOST}:{PVE_PORT}", additional_headers={"Authorization": authorization}) as pve_socket:
            async def browser_to_pve():
                while True:
                    message = await websocket.receive()
                    if message["type"] == "websocket.disconnect": return
                    await pve_socket.send(message.get("bytes") if message.get("bytes") is not None else message.get("text"))
            async def pve_to_browser():
                async for message in pve_socket:
                    await (websocket.send_bytes(message) if isinstance(message, bytes) else websocket.send_text(message))
            left, right = await asyncio.wait({asyncio.create_task(browser_to_pve()), asyncio.create_task(pve_to_browser())}, return_when=asyncio.FIRST_COMPLETED)
            for task in right: task.cancel()
            await asyncio.gather(*right, return_exceptions=True)
    except WebSocketDisconnect:
        return
    except Exception:
        logger.exception("Console connection failed for VM %s", vmid)
        await websocket.close(code=1011)
