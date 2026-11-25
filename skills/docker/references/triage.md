# Triage order

Cheapest evidence first, so a restart is the last thing you reach and not the
first thing you try.

1. `inspect_containers`: is the container present, running, restarting, or
   exited, and for how long? Record the image and the restart count.
2. `get_service_health`: does the service answer its own health check? A
   container can be "running" while the process inside is dead.
3. `read_logs`: last 200 lines of the unhealthy container only. Read the last
   error before the exit, not the first line that looks like an error.

## Exit codes worth naming

| Code | Usual cause |
|---|---|
| 0 | the process finished and the container was expected to keep running |
| 1 | application error; the log line above the exit names it |
| 137 | killed: out of memory, or a stop that outlived its grace period |
| 143 | SIGTERM handled, a deliberate stop |

## Stop instead of guessing

- The logs are empty and the container exited immediately: report what you
  checked and stop. A restart will loop.
- The evidence points at the host (disk, memory, kernel), not the container:
  no tool in this tier fixes that.
- `read_logs` returns a DLP block: the output may not be served, so say the
  logs were refused and stop. Do not try another path to the same text.
- The same container failed the same way after a restart: a second restart is
  not a diagnosis.

## What a finding must contain

The container, the state you observed, the exact log line you relied on, and
the next action you propose. If the next action is a write, the approval reason
has to stand on its own: a human reads it without your transcript.
