# Restart playbook

`restart_service` is a T1 write: an approver sees the exact arguments, and the
approval token names them. Getting the arguments right is the whole job.

## Arguments

- `service`: one service, the exact name from `inspect_containers`, no path, no
  shell syntax, no `$(...)`. If you cannot name it exactly, you do not have
  enough evidence to ask.
- One call, one service. A restart that takes a list cannot be approved with
  confidence, and the tier allows a single name.

## Before you propose it

- The container is unhealthy **now**, and you can quote the line or the health
  result that says so.
- The failure is not a configuration error, a missing secret, an image pull
  failure, or a host problem. A restart does not change any of those.
- You have not already restarted this service for this cause in this run. If
  you have, the answer is a different diagnosis, not another restart.

## The approval reason

Write the reason as if the approver has no context:

> checkout-api exited 137 twice in ten minutes; the log shows the OOM kill and
> the service has been down since 14:02.

Not "restart because it is unhealthy". Not "routine maintenance".

## After the restart

- Check the health result again and report it. "Restarted" is not "fixed".
- If it recovers, say what the state was, what you changed, and what to watch.
- If it does not recover, stop. A loop of restarts hides the cause and spends
  approvals.

## Never

- Restart the whole stack, or a database, to clear a symptom.
- Prune, remove or recreate a container, volume or image. Those tools are not
  in this tier and an approval cannot create one.
- Treat a deny or an expired approval as retryable. Both are answers.
