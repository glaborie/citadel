# Tool Output: Cap, Digest, Read Back

Three limits sit between a tool's stdout and a reviewer's eyes, and each one used
to hide what the one above it kept.

| Limit | Where | What it decides |
|---|---|---|
| 64 KB per stream, 512 KB for `pr_diff` | tool runner (`MAX_OUTPUT_BYTES`, or the command's `output_limit`) | what leaves the sandbox |
| 8 KB per stream in the record | activity (`EVENT_OUTPUT_LIMIT`) | what becomes Temporal event history |
| 1 MB per stream in storage | `tool_outputs` (`CITADEL_OUTPUT_STORE_MAX_BYTES`) | what the platform will keep |

## What the record carries

The activity result is event history. A 64 KB log dumped into it would be 64 KB of
history per call, and a handful of calls reaches Temporal's 256 KB warning. So the
stream is bounded to head + tail + marker, and the record keeps:

- the bounded text,
- `output_sha256` - the digest of the whole stream as the runner returned it,
- `stream_sha256` - a digest per stream, so stderr is not anonymous,
- `original_bytes` and `truncated`,
- `discarded_bytes` - what the sandbox measured and never handed over, so a size in
  the record is the size the tool produced, not the size that survived the cap.

A digest with no way to read the bytes is proof, not evidence. A reviewer could see
that a 100 KB diff existed and could not read line 4 000 of it without running the
tool again - which, for a T1 write, means repeating the side effect.

## What storage carries

`tool_outputs` keeps the text behind the digest:

```
(tenant_id, digest)  PRIMARY KEY
run_id, tool, stream
body  bytea  -- gzip of the redacted UTF-8 text
bytes        -- uncompressed length
```

Three properties, each of which is load-bearing:

**It is the redacted text.** The body stored is what the DLP gate already approved,
so the store cannot become a way around the output gate.

**The key includes the tenant.** A digest is content-addressed: two tenants that
hold identical bytes produce the same digest. Keying on `digest` alone would let one
tenant's row satisfy another's lookup, which is a leak with a plausible excuse. RLS
enforces the same boundary again at the table.

**Only over-cap streams are stored.** If the output fit in the record there is
nothing to retrieve, and writing a row anyway would put the log in two places for
no gain.

## Reading it back

```
GET /runs/{run_id}/outputs/{digest}
Authorization: Bearer <token>
```

The run must exist in the caller's tenant - checked before the store is queried, so
a foreign run cannot be probed for digests - and the read is audited as
`tool.output.read` with the digest and byte count. A miss returns 404 and writes no
event: an absence is not a read.

`output_ref` in the tool result and `output_ref` in the `tool.call` audit event name
the digest, so the record always says whether the bytes were kept (`output_stored`)
or refused for size.

## What this does not do

- **The sandbox cap still loses bytes, and the record now says how many.** A 10 MB log
  is cut inside the sandbox, before this store exists; streaming from the sandbox to
  storage would need object-store credentials in it, which is the one thing the
  sandbox is built not to have. Instead the cap is per command - a diff is the answer,
  a log is a stream to grep, so `gh.pr.diff` carries `output_limit: 524288` and
  everything else keeps 64 KB - and the record carries `original_bytes` (what the tool
  service measured before its own cap) and `discarded_bytes` (what never reached the
  platform). `output_ref` therefore points at the whole stream whenever
  `discarded_bytes` is 0, which is every diff that fits in 512 KB.
- **Retention is a job, not a trigger.** Bodies expire after 90 days (below), but the
  delete runs from `make outputs-purge` under a DSN that can see every tenant - so an
  environment that never runs the job still grows.
- **No download path for binaries.** Everything stored is UTF-8 text; a binary
  artifact would need a content type and a different route.

## What a replay must report

A repeated attempt that hits an existing idempotency key returns the stored payload
with `status=replayed`, and it must describe that payload exactly as the first
execution did: `output_sha256`, `output_bytes`, `output_truncated`, `output_ref` and
`output_stored`. The digest is in the payload either way, so the fields are derived
from it rather than stored twice - but a consumer that reads the audit event sees
the same numbers on the first call and on the replay, which is the point of writing
them at all.

## Retention

The run history is the record; a stored body is the working copy of it. Bodies expire
after **90 days** (`CITADEL_OUTPUT_STORE_TTL_DAYS`, or `make outputs-purge DAYS=30`),
because a table of tool output that is never deleted is a growing archive, and some of it
is one DLP miss away from being sensitive.

Only the body goes. `tool.call` keeps the digest, the byte count and the stream name, so
the record still says bytes existed - and the read-back route already answers 404 for a
digest it cannot serve, so an expired body is indistinguishable from one refused for size.
A caller learns "not available", never "never existed".

Who deletes matters as much as when. The job runs as a DSN that can see every tenant
(`CITADEL_OUTPUT_PURGE_DSN`, the owner or a `BYPASSRLS` role), because the app role is
tenant-scoped: under RLS it would delete nothing and exit 0. A retention job that reports
success while retaining everything is the failure this layer exists to prevent, one level
up. A period of zero is refused rather than obeyed.
