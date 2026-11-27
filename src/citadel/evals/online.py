"""Sample real runs into the MLflow eval dataset (ADR-017 decision 3).

Off by default: `CITADEL_EVAL_SAMPLE_RATE=0` samples nothing. A rate of 0.1 samples one
run in ten, and the draw is a hash of the run id rather than a clock, so a retried
activity decides the same way twice. The cap bounds a bad day: a thousand short runs at
0.1 must not become a thousand eval rows.

What lands in MLflow is the trajectory schema plus the metadata that makes two samples
comparable - model alias, prompt-pack version, dataset version and judge. Free text goes
through the `record` DLP surface first: a credential refuses the whole sample, PII is
redacted in place, and a tool answer that cannot be kept says so with `output_redacted`
rather than disappearing.

MLflow 3.18 answers `{}` to every `/datasets/search` filter, so the dataset id is
remembered in the audit ledger (`eval.sample` events) instead of discovered by name: the
first sample creates the dataset, and later ones reuse the id it recorded.
"""

from __future__ import annotations

import hashlib
import json
import os
import urllib.error
import urllib.request
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

from citadel.evals.graders import Grade, grade
from citadel.evals.schema import Case, check_events

DATASET_NAME: Final = "citadel-online-samples"
SALT: Final = "citadel-eval-online-v1"
DEFAULT_RATE: Final = 0.0
DEFAULT_CAP: Final = 25
ANSWER_LIMIT: Final = 4000
SEED: Final = "{tenant}|{run}|{salt}"
BYTE_ORDER: Final = "big"
SCALE: Final = 2**64

# The `record` DLP surface: text in, (text, report) out, raising when a credential is
# present. Injected so the export can be tested without an analyzer.
Gate = Callable[[str], tuple[str, dict[str, Any]]]
Opener = Callable[..., Any]


class SampleRefused(RuntimeError):
    """The run is not exportable: an incomplete trajectory, or a secret in it."""


class DatasetError(RuntimeError):
    """MLflow did not accept the record. The run is already over; nothing retries."""


@dataclass(frozen=True)
class Policy:
    rate: float
    cap: int
    day: str

    def admits(self, *, run_id: str, tenant_id: str, taken: int) -> bool:
        """Deterministic per run, bounded per day, and off unless a rate is set."""
        if self.rate <= 0 or taken >= self.cap:
            return False
        return bucket(run_id, tenant_id) < self.rate


@dataclass(frozen=True)
class Meta:
    """What makes two samples comparable later. Recorded with every row."""

    model_alias: str
    prompt_pack_version: str
    dataset_version: int
    judge: tuple[str, ...] = ()


@dataclass(frozen=True)
class Endpoint:
    """Where a sampled row goes. `dataset_id` is None until the dataset exists."""

    tracking_uri: str
    experiment_id: str
    dataset_id: str | None = None
    name: str = DATASET_NAME


@dataclass(frozen=True)
class Sample:
    """One run's candidacy, assembled by the caller that holds the ledger."""

    events: list[dict[str, Any]]
    tenant_id: str
    run_id: str
    meta: Meta
    policy: Policy
    taken: int


def bucket(run_id: str, tenant_id: str) -> float:
    """A stable uniform draw in [0, 1) for this run, from its identity alone."""
    seed = SEED.format(tenant=tenant_id, run=run_id, salt=SALT)
    draw = int.from_bytes(hashlib.sha256(seed.encode()).digest()[:8], BYTE_ORDER)
    return draw / SCALE


def policy_from_env(now: datetime | None = None) -> Policy:
    moment = now or datetime.now(UTC)
    return Policy(
        rate=_float_env("CITADEL_EVAL_SAMPLE_RATE", DEFAULT_RATE),
        cap=_int_env("CITADEL_EVAL_SAMPLE_CAP", DEFAULT_CAP),
        day=moment.strftime("%Y-%m-%d"),
    )


def build_record(sample: Sample, *, gate: Gate) -> dict[str, Any]:
    """A dataset row, or a refusal. Never a row carrying what the run saw."""
    problems = check_events(sample.events, tenant=sample.tenant_id)
    if problems:
        raise SampleRefused("incomplete trajectory: " + "; ".join(problems))

    redacted = [_redact_event(event, gate) for event in sample.events]
    problems = check_events(redacted, tenant=sample.tenant_id)
    if problems:
        # Redaction changed the shape. Refuse rather than export a row the grader
        # would reject later with no way to tell why.
        raise SampleRefused("trajectory invalid after redaction: " + "; ".join(problems))

    return {
        "inputs": {
            "run_id": sample.run_id,
            "tenant": sample.tenant_id,
            "model_alias": sample.meta.model_alias,
            "prompt_pack_version": sample.meta.prompt_pack_version,
            "dataset_version": sample.meta.dataset_version,
            "judge": list(sample.meta.judge),
        },
        "outputs": {"trajectory": redacted},
        "expectations": {},
    }


def _redact_event(event: dict[str, Any], gate: Gate) -> dict[str, Any]:
    """Gate the free text this event would carry. Everything else is already hashes."""
    kept = dict(event)
    if kept.get("type") == "run.end" and isinstance(kept.get("answer"), str) and kept["answer"]:
        kept["answer"] = gate(kept["answer"])[0][:ANSWER_LIMIT]
    if kept.get("type") == "approval.decision" and isinstance(kept.get("reason"), str):
        kept["reason"] = gate(kept["reason"])[0]
    if kept.get("type") == "tool.call" and kept.get("output") is not None:
        kept = _gate_output(kept, gate)
    return kept


def _gate_output(event: dict[str, Any], gate: Gate) -> dict[str, Any]:
    text = json.dumps(event["output"], ensure_ascii=False, sort_keys=True)
    gated, _report = gate(text)
    if gated == text:
        return event
    try:
        return {**event, "output": json.loads(gated)}
    except json.JSONDecodeError:
        # The detector cut into the JSON. The schema has a marker for exactly this:
        # say the body could not be kept instead of keeping a truncated one.
        kept = {key: value for key, value in event.items() if key != "output"}
        kept["output_redacted"] = True
        return kept


def replay(record: dict[str, Any]) -> list[Grade]:
    """The offline grader, on a sample, without an agent anywhere near it.

    A sampled run has no expectations - nobody wrote them - so only the graders that
    read the trajectory itself can speak, which is the subset this issue asks for.
    """
    inputs = record["inputs"]
    case = Case(
        id=str(inputs["run_id"]),
        version=int(inputs["dataset_version"]),
        tenant=str(inputs["tenant"]),
        prompt="(sampled run: the prompt is not stored)",
        expectations={},
        events=list(record["outputs"]["trajectory"]),
    )
    return grade(case)


def offer(
    sample: Sample, *, endpoint: Endpoint, gate: Gate, opener: Opener | None = None
) -> tuple[dict[str, Any], Endpoint] | None:
    """Decide, export, and return the row and where it was written - or None if skipped."""
    if not sample.policy.admits(
        run_id=sample.run_id, tenant_id=sample.tenant_id, taken=sample.taken
    ):
        return None
    record = build_record(sample, gate=gate)
    return record, push(record, endpoint=endpoint, opener=opener)


def create_dataset(*, endpoint: Endpoint, opener: Opener | None = None) -> str:
    """`POST /api/3.0/mlflow/datasets/create`, which takes a name and an experiment."""
    payload = _call(
        "POST",
        "/api/3.0/mlflow/datasets/create",
        {"name": endpoint.name, "experiment_id": endpoint.experiment_id},
        endpoint=endpoint,
        opener=opener,
    )
    return str(payload["dataset"]["dataset_id"])


def merge_records(
    record: dict[str, Any], *, endpoint: Endpoint, opener: Opener | None = None
) -> None:
    """`POST /api/3.0/mlflow/datasets/<id>/records`. MLflow merges on the inputs."""
    if endpoint.dataset_id is None:
        raise DatasetError("no dataset to merge into; create one first")
    payload = _call(
        "POST",
        f"/api/3.0/mlflow/datasets/{endpoint.dataset_id}/records",
        {"records": json.dumps([record], ensure_ascii=False)},
        endpoint=endpoint,
        opener=opener,
    )
    inserted = payload.get("inserted_count", 0)
    updated = payload.get("updated_count", 0)
    if not inserted and not updated:
        raise DatasetError(f"MLflow accepted no record for dataset {endpoint.dataset_id}")


def push(record: dict[str, Any], *, endpoint: Endpoint, opener: Opener | None = None) -> Endpoint:
    """Create the dataset when the ledger has no id yet, then merge the row."""
    target = endpoint
    if target.dataset_id is None:
        target = Endpoint(
            tracking_uri=endpoint.tracking_uri,
            experiment_id=endpoint.experiment_id,
            dataset_id=create_dataset(endpoint=endpoint, opener=opener),
            name=endpoint.name,
        )
    merge_records(record, endpoint=target, opener=opener)
    return target


def _call(
    method: str,
    path: str,
    body: dict[str, Any],
    *,
    endpoint: Endpoint,
    opener: Opener | None,
) -> dict[str, Any]:
    request = urllib.request.Request(
        f"{endpoint.tracking_uri.rstrip('/')}{path}",
        data=json.dumps(body).encode(),
        method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        with (opener or urllib.request.urlopen)(request, timeout=10) as response:
            return dict(json.loads(response.read()))
    except urllib.error.HTTPError as exc:
        raise DatasetError(_refused(method, path, f"HTTP {exc.code}")) from exc
    except (OSError, ValueError) as exc:
        raise DatasetError(_refused(method, path, str(exc))) from exc


def _refused(method: str, path: str, reason: str) -> str:
    return f"{method} {path}: {reason}"


def _float_env(name: str, default: float) -> float:
    try:
        number = float(os.environ.get(name, ""))
    except ValueError:
        return default
    return number if 0.0 <= number <= 1.0 else default


def _int_env(name: str, default: int) -> int:
    try:
        number = int(os.environ.get(name, ""))
    except ValueError:
        return default
    return number if number >= 0 else default


def dataset_id_from(ledger_rows: Sequence[tuple[Any, ...]]) -> str | None:
    """The dataset id the most recent `eval.sample` event recorded, if any."""
    for row in ledger_rows:
        payload = row[1]
        body = payload if isinstance(payload, dict) else json.loads(str(payload))
        candidate = body.get("dataset_id")
        if isinstance(candidate, str) and candidate:
            return candidate
    return None
