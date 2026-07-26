"""Render web application.

This service never connects to Proxmox.  It sends authenticated requests to
the home-network agent through Cloudflare Tunnel instead.
"""
import os
import secrets
from typing import Any

import requests
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware

load_dotenv()

app = FastAPI()
app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SESSION_SECRET", secrets.token_urlsafe(32)),
    https_only=os.getenv("SESSION_HTTPS_ONLY", "true").lower() == "true",
    same_site="lax",
)
app.mount("/static", StaticFiles(directory="assets"), name="static")
templates = Jinja2Templates(directory="templates")

AGENT_URL = os.getenv("AGENT_URL", "").rstrip("/")
AGENT_SHARED_SECRET = os.getenv("AGENT_SHARED_SECRET", "")
CF_ACCESS_CLIENT_ID = os.getenv("CF_ACCESS_CLIENT_ID", "")
CF_ACCESS_CLIENT_SECRET = os.getenv("CF_ACCESS_CLIENT_SECRET", "")
PANEL_USERNAME = os.getenv("PANEL_USERNAME", "")
PANEL_PASSWORD = os.getenv("PANEL_PASSWORD", "")
SUPPORT_WHATSAPP_NUMBER = os.getenv("SUPPORT_WHATSAPP_NUMBER", "94779304675")


class LoginRequest(BaseModel):
    username: str
    password: str


def require_login(request: Request) -> str:
    username = request.session.get("username")
    if not username:
        raise HTTPException(status_code=401, detail="Please sign in")
    return username


def agent_request(method: str, path: str, **kwargs: Any) -> requests.Response:
    """Call the Ubuntu agent.  The agent secret never reaches the browser."""
    if not AGENT_URL or not AGENT_SHARED_SECRET:
        raise HTTPException(status_code=503, detail="The management agent is not configured")
    headers = {"Authorization": f"Bearer {AGENT_SHARED_SECRET}"}
    if CF_ACCESS_CLIENT_ID and CF_ACCESS_CLIENT_SECRET:
        headers["CF-Access-Client-Id"] = CF_ACCESS_CLIENT_ID
        headers["CF-Access-Client-Secret"] = CF_ACCESS_CLIENT_SECRET
    try:
        return requests.request(
            method,
            f"{AGENT_URL}{path}",
            headers=headers,
            timeout=45,
            **kwargs,
        )
    except requests.RequestException:
        raise HTTPException(status_code=503, detail="The home management agent is offline") from None


def proxy(method: str, path: str, request: Request) -> JSONResponse:
    require_login(request)
    response = agent_request(method, path, params=request.query_params)
    try:
        payload = response.json()
    except ValueError:
        payload = {"detail": "The management agent returned an invalid response"}
    return JSONResponse(status_code=response.status_code, content=payload)


@app.get("/")
def home(request: Request):
    if not request.session.get("username"):
        return templates.TemplateResponse(request=request, name="login.html", context={})
    return templates.TemplateResponse(request=request, name="index.html", context={})


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/auth/login")
def login(credentials: LoginRequest, request: Request):
    if not PANEL_USERNAME or not PANEL_PASSWORD:
        raise HTTPException(status_code=503, detail="Panel login is not configured")
    if not (
        secrets.compare_digest(credentials.username.strip(), PANEL_USERNAME)
        and secrets.compare_digest(credentials.password, PANEL_PASSWORD)
    ):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    request.session.clear()
    request.session["username"] = PANEL_USERNAME
    return {"username": PANEL_USERNAME}


@app.get("/auth/me")
def current_user(request: Request):
    return {"username": require_login(request)}


@app.post("/auth/logout")
def logout(request: Request):
    request.session.clear()
    return {"ok": True}


@app.get("/vms")
def list_vms(request: Request):
    return proxy("GET", "/vms", request)


@app.get("/capacity")
def capacity(request: Request):
    return proxy("GET", "/capacity", request)


@app.post("/vms")
def create_vm(request: Request):
    return proxy("POST", "/vms", request)


@app.delete("/vms/{vmid}")
def delete_vm(vmid: int, request: Request):
    return proxy("DELETE", f"/vms/{vmid}", request)


@app.post("/vms/{vmid}/start")
def start_vm(vmid: int, request: Request):
    return proxy("POST", f"/vms/{vmid}/start", request)


@app.post("/vms/{vmid}/stop")
def stop_vm(vmid: int, request: Request):
    return proxy("POST", f"/vms/{vmid}/stop", request)


@app.get("/api/console/{vmid}")
def console(vmid: int, request: Request):
    return proxy("GET", f"/api/console/{vmid}", request)
