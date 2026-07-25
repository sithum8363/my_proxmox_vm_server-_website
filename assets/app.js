async function responseData(response) {
    const text = await response.text();
    if (!text) return {};

    try {
        return JSON.parse(text);
    } catch {
        return { detail: "The server returned an unexpected error." };
    }
}

async function openConsole(vmid) {
    const response = await fetch(`/api/console/${vmid}`);
    if (response.status === 401) {
        window.location.href = "/";
        return;
    }
    const data = await responseData(response);
    if (!response.ok) {
        alert(data.detail || "Could not open the VM console.");
        return;
    }

    const useEncryption = window.location.protocol === "https:" ? "1" : "0";
    const port = window.location.port || (useEncryption === "1" ? "443" : "80");
    const websocketPath = `ws/console/${vmid}?connection_id=${data.connection_id}`;
    const url =
        `/novnc/vnc.html` +
        `?autoconnect=1` +
        `&encrypt=${useEncryption}` +
        `&host=${window.location.hostname}` +
        `&port=${port}` +
        `&path=${encodeURIComponent(websocketPath)}` +
        `#password=${encodeURIComponent(data.vnc_password)}`;

    window.open(url, "_blank");
}

async function loadVMs() {

    const response = await fetch("/vms");
    if (response.status === 401) {
        window.location.href = "/";
        return;
    }
    const data = await responseData(response);

    if (!response.ok) {
        alert(data.detail || "Could not load virtual machines.");
        return;
    }

    let html = "";

    data.forEach(vm => {

        const statusColor = vm.status === "running"
            ? "#16a34a"
            : "#dc2626";

        html += `
        <tr>

            <td>${vm.vmid}</td>

            <td>${vm.name}</td>

            <td>
                <span style="color:${statusColor};font-weight:bold;">
                    ${vm.status}
                </span>
            </td>

            <td>${(vm.cpu * 100).toFixed(1)}%</td>

            <td>
                ${(vm.memory / 1024 / 1024).toFixed(0)} MB used / 
                ${(vm.max_memory / 1024 / 1024).toFixed(0)} MB allocated
            </td>

<td>
    <button onclick="openConsole(${vm.vmid})">
        Console
    </button>
</td>
            <td>
                ${vm.status === "running"
                    ? `<button class="stop-button" onclick="changePower(${vm.vmid}, 'stop')">Stop</button>`
                    : `<button class="start-button" onclick="changePower(${vm.vmid}, 'start')">Start</button>`}
            </td>
            <td>
                <button onclick="deleteVM(${vm.vmid})">
                    Delete
                </button>
            </td>

        </tr>
        `;
    });

    document.getElementById("vmTable").innerHTML = html;
    loadCapacity();
}

async function loadCapacity() {
    const response = await fetch("/capacity");
    if (response.status === 401) {
        window.location.href = "/";
        return;
    }
    if (!response.ok) return;

    const capacity = await responseData(response);
    if (!capacity.available) {
        document.getElementById("capacity").textContent =
            "Host memory capacity is unavailable for this Proxmox role.";
        return;
    }
    document.getElementById("capacity").textContent =
        `Safe VM RAM: ${capacity.available_vm_memory_mb} MB available of ` +
        `${capacity.safe_vm_memory_mb} MB. ` +
        `${capacity.reserve_mb} MB is reserved for Proxmox ` +
        `(host total: ${capacity.host_memory_mb} MB).`;
}

async function loadCurrentUser() {
    const response = await fetch("/auth/me");
    if (response.status === 401) {
        window.location.href = "/";
        return;
    }

    const user = await responseData(response);
    document.getElementById("currentUser").textContent = user.username;
}

async function logout() {
    await fetch("/auth/logout", { method: "POST" });
    window.location.href = "/";
}

async function createVM() {

    const name = document.getElementById("vmname").value;
    const vmid = document.getElementById("vmid").value;

    const params = new URLSearchParams({ name, vmid });
    const response = await fetch(`/vms?${params}`, {
        method: "POST"
    });

    if (response.status === 401) {
        window.location.href = "/";
        return;
    }
    const result = await responseData(response);
    if (!response.ok) {
        alert(result.detail || "Could not create the VM.");
        return;
    }
    console.log(result);

    loadVMs();
}

async function deleteVM(id) {

    if (!confirm("Delete this VM?")) return;

    const response = await fetch(`/vms/${id}`, {
        method: "DELETE"
    });

    if (response.status === 401) {
        window.location.href = "/";
        return;
    }
    if (!response.ok) {
        alert((await responseData(response)).detail || "Could not delete the VM.");
        return;
    }

    loadVMs();
}

async function changePower(id, action) {
    const response = await fetch(`/vms/${id}/${action}`, {
        method: "POST"
    });
    if (response.status === 401) {
        window.location.href = "/";
        return;
    }
    const result = await responseData(response);

    if (!response.ok) {
        alert(result.detail || `Could not ${action} the VM.`);
        return;
    }

    loadVMs();
}

// Refresh every 5 seconds
setInterval(loadVMs, 5000);

loadVMs();
loadCurrentUser();
