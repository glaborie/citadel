# Host firewall policy

The stack is reachable only through loopback. Every published port in `compose.yaml` is
bound to `127.0.0.1` (#219), and the four ports that were once published on `0.0.0.0` are
additionally dropped on `eth0` and `tailscale0` in the host's `INPUT` chain (#223). This
runbook records the policy, the mechanism that makes it survive a reboot (#226), and the
drill that proves it. It is host configuration, not repository state — nothing in this
file is applied by `make` or Compose.

## The policy

| layer | what | covers |
| --- | --- | --- |
| Compose binds | every published port binds `127.0.0.1:port:container` | all ports; the primary control — nothing external connects at the socket level |
| host `INPUT` | `DROP` on `-i eth0` and `-i tailscale0`, dports `18000,18001,18081,20128` | the four ports #223 found exposed: `api` 18000, `approval-ui` 18001, `keycloak` 18081, `omniroute` 20128 |

The `INPUT` rules belong in `INPUT`, not `DOCKER-USER`: on this host (Docker Desktop on
WSL2) the published ports are local sockets in the distro's netns, so nothing is
forwarded — #223 recorded the counters that prove it. `temporal-ui` (18080) and the other
loopback-bound ports rely on the bind alone; the drops are deliberately narrow. If a port
is ever republished to a non-loopback interface, add it to both `DROP` lines and re-save
the ruleset (below), and restore the `DOCKER-USER` guard from #223 item 2.

```bash
sudo iptables -S INPUT
# -P INPUT ACCEPT
# -A INPUT -i tailscale0 -p tcp -m multiport --dports 18000,18001,18081,20128 -j DROP
# -A INPUT -i eth0 -p tcp -m multiport --dports 18000,18001,18081,20128 -j DROP
```

## Remote administration (#221)

Remote administration of the published services — above all the Keycloak admin
console on 18081, whose session is the root of trust for the whole stack — goes
through an authenticating hop to the loopback bind, never a wider bind: an SSH
local forward (`ssh -N -L 18081:127.0.0.1:18081 <host>`) or `tailscale serve`.
The binds and the drops stay as they are; convenience is never a reason to
reopen a port.

## Persistence

`iptables-persistent` / `netfilter-persistent` 1.0.16 (both services enabled) restore
`/etc/iptables/rules.v4` and `rules.v6` at boot. The saved ruleset carries the two
`INPUT` drops, the Docker chains as they were at save time, a `nat` table with no stale
container DNATs, and empty `mangle`/`raw`. `rules.v6` is the default `ACCEPT` policy: the
host has no global IPv6 address and none of the four ports has an IPv6 listener — revisit
if that changes.

```bash
sudo iptables-restore --test < /etc/iptables/rules.v4   # parse check
sudo netfilter-persistent save                          # write the live ruleset to rules.v4 / rules.v6
```

Save from the live kernel, never by hand-editing `rules.v4`, so the file and the kernel
cannot drift.

## Boot ordering and tailscale

`iptables-restore` replaces each table it loads wholesale. If it ran while tailscale was
up, it would delete `ts-input`/`ts-forward` and take the tailnet down with it. A drop-in
pins the order, so the restore completes before tailscaled installs its chains:

```ini
# /etc/systemd/system/netfilter-persistent.service.d/ordering.conf
[Unit]
# Restore before tailscaled installs ts-input/ts-forward: iptables-restore
# replaces whole tables, so a restore afterwards would delete tailscale rules.
Before=tailscaled.service
```

Verify with `systemctl show tailscaled -p After` — `netfilter-persistent.service` must be
in the list. Two caveats, measured on this host:

- A manual `netfilter-persistent restart` while tailscale is up re-runs the restore and
  wipes the tailscale chains regardless of the drop-in. Restart tailscaled
  (`sudo systemctl restart tailscaled`) afterwards, or re-run `tailscale up`.
- When the tailscale client is down there are no `ts-input`/`ts-forward` chains at all,
  and `iptables -S ts-input` fails with `incompatible` instead of listing rules. Check
  `tailscale status` before concluding the chains were clobbered.

## Reboot drill (#226 acceptance)

1. Reboot the Windows host; cold-start the distro.
2. `sudo iptables -S INPUT` shows both `DROP` rules with no manual intervention.
3. From another tailnet host (once `tailscale up`): `curl http://100.69.19.104:18000/`,
   and the same for `18001`, `18081`, `20128`, all fail. From the distro:
   `curl http://127.0.0.1:18001/` still answers. The Compose bind is the primary layer,
   the drops the second — both must hold.
4. `tailscale status` is healthy and `sudo iptables -S ts-input` lists tailscale's rules
   — the restore did not replace them.
5. `sudo iptables -S ts-forward` is intact and container egress returns 200.
6. `docker compose up -d --wait` reaches 22/22 healthy.
7. Reboot once more and repeat. The mechanism must be idempotent, not a one-off command.

## Open items from #223 (same host, same runbook)

| item | state on 2026-11-27 |
| --- | --- |
| default-deny input policy (`ufw` active or `INPUT` policy `DROP`) | `ufw` is `inactive`, `INPUT` policy is still `ACCEPT`; only the four-port drops are in force |
| `DOCKER-USER` forward-path rule | moot today — nothing is forwarded (loopback binds, WSL netns) — mandatory the moment any port is republished |
| narrow `sudo` (remove `NOPASSWD:ALL`) | `sudo -n true` still succeeds for the interactive account |
