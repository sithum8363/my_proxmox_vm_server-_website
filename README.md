# Render + home Proxmox agent

`main.py` is the Render website.  It does not connect to your private Proxmox network.
`agent.py` runs on the Ubuntu management VM and is the only process that uses `proxmoxer`.

## 1. Proxmox

Create a dedicated API token for a restricted Proxmox account. Do not use `root@pam`.
Give it only the VM permissions your panel needs, scoped to the VMs or pool it manages.

## 2. Ubuntu management VM

Clone this repository (including the `novnc` directory), create a virtual environment,
install `requirements.txt`, copy `.env.example` to `.env`, and set the Ubuntu-agent variables.

Run the agent:

```bash
uvicorn agent:app --host 127.0.0.1 --port 8000
```

Keep it running with a systemd service in production.

## 3. Cloudflare Tunnel

Point two public hostnames, for example `api.example.com` and
`console.example.com`, to `http://127.0.0.1:8000`. Set
`PUBLIC_BASE_URL=https://console.example.com` in the Ubuntu `.env`.

Protect `api.example.com` with Cloudflare Access **service authentication**.
Put the generated service-token ID and secret in Render as `CF_ACCESS_CLIENT_ID`
and `CF_ACCESS_CLIENT_SECRET`. The additional `AGENT_SHARED_SECRET` is required
by every Render-to-agent API call.

`console.example.com` serves only noVNC static files and one-time console
WebSockets. It can have a Cloudflare browser-login policy, or be public when
the single-use ticket protection is acceptable for your use case. Do not apply
service-token-only Cloudflare Access to this hostname, because a browser cannot
send the Render service token.

The noVNC WebSocket is a one-time, 20-second ticket created only after an authenticated
Render request. Do not create a Cloudflare rule that blocks WebSockets for this hostname.

## 4. Render

Deploy this repository as a Python web service with:

```text
Build command: pip install -r requirements.txt
Start command: uvicorn main:app --host 0.0.0.0 --port $PORT
```

Set only the Render-website variables from `.env.example`: `SESSION_SECRET`,
`SESSION_HTTPS_ONLY`, `PANEL_USERNAME`, `PANEL_PASSWORD`, `AGENT_URL`,
`AGENT_SHARED_SECRET`, `CF_ACCESS_CLIENT_ID`, and `CF_ACCESS_CLIENT_SECRET`.
Never put `PVE_TOKEN_VALUE` in Render.
