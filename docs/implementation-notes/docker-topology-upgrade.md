# Docker topology upgrade: Docker Desktop → native Engine → gVisor

**Status: not applied.** As of 2026-11-23 the owner chose **Path A** (keep the
ADR-012 hardened-sidecar fallback). This file documents the upgrade path so
the decision stays reversible and the work is not re-derived later.

Read this only if gVisor becomes a hard requirement. Nothing here is needed
for v0.1.

## Why this is a topology change, not an install

`docker info` on the target host reports:

```
OperatingSystem=Docker Desktop   Name=docker-desktop
Server=29.9.2                    OSType=linux
```

The daemon runs inside Docker Desktop's own VM. `runsc` would have to exist
inside that VM, and there is no supported way to put it there. Adding a
`runtimes` entry to `daemon.json` via Settings → Docker Engine does nothing
without the binary, so gVisor is not installable on this host as configured.

The host:

| Fact | Value |
|---|---|
| Distro | Ubuntu 22.04.5 LTS on WSL2 |
| Kernel | `6.18.58.1-microsoft-standard-WSL2` |
| PID 1 | `init(Ubuntu)` — **systemd is disabled** |
| `/etc/wsl.conf` | absent |
| Docker CLI | default context → `unix:///var/run/docker.sock` (proxied) |

## What breaks, and how bad

Moving to native Docker Engine means:

- **Docker Desktop integration must be off** for this distro. Two daemons
  competing for `/var/run/docker.sock` is the usual failure mode.
- **Images, volumes and networks do not migrate.** The current stack
  (`postgres-data`, `omniroute-data`, `mlflow-data`) has to be rebuilt from
  an empty state, or exported and re-imported.
- **Host port bindings must be re-checked.** 18000/18001/18080/18081/20128
  were chosen to avoid collisions under Docker Desktop's proxy; native
  Engine binds them directly.
- **gVisor on WSL2 is unsupported.** There is no KVM, so `runsc` falls back
  to the `systrap` platform. It may work; it is not a tested target.
- **Every verified result is invalidated** until the stack is green again.

Treat this as an experiment on a branch, not a migration.

## Prerequisites

- Commit and push first. The current `master` is green: 14 services healthy,
  25 hermetic tests, 5 live tenancy tests.
- Note the volume names so you can confirm what was lost:
  `docker volume ls | grep citadel`
- Be able to get back: Docker Desktop can be re-enabled from Settings →
  Resources → WSL Integration at any time. That is the rollback.

## Steps

### 1. Disable Docker Desktop integration

Settings → Resources → WSL Integration → turn **off** for Ubuntu-22.04, then
quit Docker Desktop completely. From PowerShell, confirm:

```powershell
wsl --shutdown
```

### 2. Enable systemd

```bash
printf '[boot]\nsystemd=true\n' | sudo tee /etc/wsl.conf
```

`wsl --shutdown` from PowerShell again, reopen the shell, then:

```bash
ps -p 1 -o comm=     # must print: systemd
```

**Gate: do not continue until PID 1 is systemd.** The remainder uses
`systemctl`.

### 3. Install native Docker Engine

```bash
sudo apt-get update && sudo apt-get install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io \
  docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker "$USER"
sudo systemctl enable --now docker
```

Verify you are on the new daemon, not the proxy:

```bash
docker info --format '{{.OperatingSystem}}'
```

Expected: `Ubuntu 22.04.5 LTS` (or similar), **not** `Docker Desktop`.
If it still says Docker Desktop, the old socket is still winning.

### 4. Install runsc

```bash
curl -fsSL https://gvisor.dev/archive.key \
  | sudo gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] \
https://storage.googleapis.com/gvisor/releases release main" \
  | sudo tee /etc/apt/sources.list.d/gvisor.list >/dev/null
sudo apt-get update && sudo apt-get install -y runsc
```

### 5. Register the runtime

`/etc/docker/daemon.json`:

```json
{
  "runtimes": {
    "runsc": {
      "path": "/usr/bin/runsc"
    }
  }
}
```

```bash
sudo systemctl restart docker
```

### 6. Prove gVisor actually isolates

Do not trust the runtime listing alone — that only says the binary was found.

```bash
docker info --format '{{json .Runtimes}}' | grep -o '"runsc"'
docker run --rm --runtime=runsc alpine uname -r    # gVisor kernel, not 6.18.58.1
docker run --rm --runtime=runsc alpine cat /proc/version
```

The second command should report a gVisor kernel string, not the WSL2 kernel.
If it reports the WSL2 kernel, `runsc` silently fell back and gVisor is not
in effect.

### 7. Rebuild the stack and apply gVisor to the sandbox

```bash
docker compose up -d
set -a; . ./.env; set +a
CITADEL_LIVE_TESTS=1 uv run pytest tests/test_tenancy_live.py -v
```

Only after that is green, add to the `tool-runner` service in `compose.yaml`:

```yaml
    runtime: runsc
```

Then re-run the isolation checks in §4 of
`docs/implementation-notes/v0.1-verification.md`, including the socket
connect and read-only rootfs probes.

## Rollback

1. Remove `runtime: runsc` from `compose.yaml`.
2. `sudo systemctl disable --now docker` inside the distro.
3. Re-enable Docker Desktop → Settings → Resources → WSL Integration.
4. `docker compose up -d` and re-run the live tests.

Volumes created under native Engine are not visible to Docker Desktop; the
stack will come up empty and need `scripts/bootstrap-identity.py` again.

## Decision record

Path A was chosen 2026-11-23. It is the option ADR-012 already sanctions, so
**no ADR amendment is required** for staying on the hardened sidecar. This
document exists so that adopting gVisor later is a deliberate, reversible
topology change rather than an undocumented drift.
