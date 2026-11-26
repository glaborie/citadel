"""Ingest knowledge sources into per-tenant Qdrant collections.

One collection per tenant, named ``citadel_<tenant>``; a point never exists in a
collection for another tenant, so a cross-tenant read is not a filter that can be
forgotten - it is a collection that does not hold the data.

Every chunk carries the digest of the whole file it came from. Re-ingesting an
unchanged file writes the same point ids, so it stores nothing new; a changed
file adds one revision and leaves the old one retrievable. Old revisions are not
pruned here (shortcut: re-index is idempotent, not a retention policy; add a
prune when storage matters).

Two named vectors: server-side BM25 in `text`, and a dense vector in `dense`
computed through the embedding endpoint. Without an embedder the point carries
only the sparse vector, which is what the unit tests and a sparse-only rebuild
use; the query path requires both.

    python -m citadel.retrieval.ingest --tenant lab-a --root /knowledge \
        --repo owner/runbooks

The container this runs in matters: the filesystem root is what it can see, and
GitHub reads need the existing ``GH_TOKEN`` plus the egress proxy.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import uuid
from collections import Counter
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final
from urllib.parse import quote
from urllib.request import Request

from qdrant_client import QdrantClient, models

from citadel import dlp, env, net
from citadel.retrieval.embed import Embedder, OmniRouteEmbedder
from citadel.retrieval.errors import RetrievalUnavailable

DEFAULT_QDRANT_URL: Final = os.environ.get("CITADEL_QDRANT_URL", "http://qdrant:6333")
DEFAULT_OMNIROUTE_URL: Final = os.environ.get("OMNIROUTE_URL", "http://omniroute:20128/v1")
DEFAULT_DLP_URL: Final = os.environ.get("CITADEL_DLP_URL", "http://presidio:3000")
GITHUB_API: Final = "https://api.github.com"
SPARSE: Final = "text"
DENSE: Final = "dense"
# A runbook is text. Larger files are a binary the model should not be fed, and
# a whole-repo tree can contain a lockfile larger than the whole value of the repo.
MAX_FILE_BYTES: Final = 1_000_000
MAX_CHUNK_CHARS: Final = 2_000
# One upsert per batch keeps a whole repository out of a single request.
BATCH: Final = 256
HTTP_TIMEOUT: Final = 30
TENANT: Final = re.compile(r"[a-z0-9][a-z0-9-]*\Z")
WORD: Final = re.compile(r"[a-z0-9]+")


class IngestRefused(RuntimeError):
    """The source is outside what the configuration allows. Nothing is written."""


@dataclass(frozen=True)
class Document:
    source_uri: str
    content: str


@dataclass(frozen=True)
class Report:
    collection: str
    documents: int
    chunks: int


def collection_name(tenant: str) -> str:
    """The one place a tenant becomes a collection name; refuse what is not one."""
    if not TENANT.fullmatch(tenant):
        raise IngestRefused(f"tenant {tenant!r} cannot name a collection")
    return f"citadel_{tenant}"


def revision(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest()


def point_id(tenant: str, source_uri: str, rev: str, index: int) -> str:
    """Deterministic, so re-ingesting an unchanged file updates in place."""
    name = f"citadel:{tenant}:{source_uri}:{rev}:{index}"
    return str(uuid.uuid5(uuid.NAMESPACE_URL, name))


def _wrap(block: str, limit: int) -> Iterator[str]:
    """One block, cut at whitespace so no piece is longer than the limit."""
    while len(block) > limit:
        cut = block.rfind(" ", 0, limit)
        cut = cut if cut > 0 else limit
        yield block[:cut].strip()
        block = block[cut:].strip()
    if block:
        yield block


def chunks(text: str, limit: int = MAX_CHUNK_CHARS) -> list[str]:
    """Paragraphs, then hard-wrapped at whitespace so no chunk is unbounded."""
    return [
        piece
        for block in (candidate.strip() for candidate in re.split(r"\n\s*\n", text))
        if block
        for piece in _wrap(block, limit)
    ]


def sparse(text: str) -> models.SparseVector:
    """Term frequencies; the collection's IDF modifier does the rest.

    Hashed indices mean no vocabulary is shipped and no token maps back to text.
    A collision adds to the same index, which is the same thing BM25 does with a
    shared term.
    """
    counts: Counter[int] = Counter()
    for term in WORD.findall(text.lower()):
        counts[int.from_bytes(hashlib.blake2b(term.encode(), digest_size=4).digest(), "big")] += 1
    indices = sorted(counts)
    return models.SparseVector(indices=indices, values=[float(counts[i]) for i in indices])


def filesystem(root: Path) -> Iterator[Document]:
    """Every text file under the configured root, and nothing that resolves out of it."""
    base = root.resolve()
    for path in sorted(base.rglob("*")):
        resolved = path.resolve()
        if not resolved.is_relative_to(base):
            raise IngestRefused(f"{path.name} resolves outside the ingest root")
        if not path.is_file() or resolved.stat().st_size > MAX_FILE_BYTES:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue  # a binary is not a document; it is not an error either
        yield Document(source_uri=f"fs:{resolved.relative_to(base)}", content=text)


def _github_json(request: Request, opener: Callable[..., Any] | None) -> Any:
    with net.open_url(request, timeout=HTTP_TIMEOUT, opener=opener) as response:
        try:
            return json.loads(response.read())
        except ValueError as exc:
            raise IngestRefused(f"{request.full_url}: GitHub answered with no JSON") from exc


def _tree(
    repo: str, ref: str, headers: dict[str, str], opener: Callable[..., Any] | None
) -> list[dict[str, Any]]:
    """The file entries of one revision, or a refusal - never a partial tree."""
    tree = _github_json(
        Request(
            f"{GITHUB_API}/repos/{repo}/git/trees/{quote(ref, safe='/')}?recursive=1",
            headers=headers,
        ),
        opener,
    )
    if not isinstance(tree, dict) or not isinstance(tree.get("tree"), list):
        raise IngestRefused(f"{repo}@{ref}: GitHub returned no tree")
    if tree.get("truncated"):
        raise IngestRefused(f"{repo}@{ref}: the tree is truncated; narrow the repository")
    return [
        entry
        for entry in tree["tree"]
        if isinstance(entry, dict)
        and isinstance(entry.get("path"), str)
        and isinstance(entry.get("sha"), str)
    ]


def _blob_text(
    repo: str, entry: dict[str, Any], headers: dict[str, str], opener: Callable[..., Any] | None
) -> str | None:
    """One file's text, or None for a binary or an oversized blob."""
    if entry.get("type") != "blob" or int(entry.get("size", 0)) > MAX_FILE_BYTES:
        return None
    blob = _github_json(
        Request(f"{GITHUB_API}/repos/{repo}/git/blobs/{entry['sha']}", headers=headers), opener
    )
    if not isinstance(blob, dict) or blob.get("encoding") != "base64":
        raise IngestRefused(f"{repo}: blob {entry.get('path')!r} is not base64")
    try:
        return base64.b64decode(blob["content"]).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None  # a binary is not a document


def github(
    repo: str,
    ref: str,
    *,
    token: str,
    opener: Callable[..., Any] | None = None,
) -> Iterator[Document]:
    """Selected repository, read through the token that already exists."""
    if not token:
        raise IngestRefused("GitHub ingestion needs GH_TOKEN or GH_TOKEN_FILE")
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    for entry in _tree(repo, ref, headers, opener):
        text = _blob_text(repo, entry, headers, opener)
        if text is not None:
            yield Document(source_uri=f"gh:{repo}@{ref}:{entry['path']}", content=text)


def allowed_root(configured: str, requested: str) -> Path:
    """The requested root must sit under the configured one, or nothing is read."""
    if not configured:
        raise IngestRefused("CITADEL_INGEST_ROOT is not set, so no root is allowed")
    base, want = Path(configured).resolve(), Path(requested).resolve()
    if not want.is_relative_to(base):
        raise IngestRefused(f"{requested} is outside the configured ingest root")
    return want


def allowed_repos(configured: str, requested: list[str]) -> tuple[str, ...]:
    """The CLI selects from the configured set; it cannot extend it."""
    known = {item.strip() for item in configured.split(",") if item.strip()}
    outside = sorted(set(requested) - known)
    if outside:
        raise IngestRefused(f"repositories not in CITADEL_INGEST_REPOS: {outside}")
    return tuple(requested)


def _create(client: QdrantClient, name: str, size: int | None) -> None:
    client.create_collection(
        name,
        vectors_config=(
            {DENSE: models.VectorParams(size=size, distance=models.Distance.COSINE)}
            if size is not None
            else {}
        ),
        sparse_vectors_config={SPARSE: models.SparseVectorParams(modifier=models.Modifier.IDF)},
    )


def _point(
    tenant: str, document: Document, rev: str, chunk: tuple[int, str], dense: list[float] | None
) -> models.PointStruct:
    index, text = chunk
    vector: dict[str, Any] = {SPARSE: sparse(text)}
    if dense is not None:
        vector[DENSE] = dense
    return models.PointStruct(
        id=point_id(tenant, document.source_uri, rev, index),
        vector=vector,
        payload={
            "tenant_id": tenant,
            "source_uri": document.source_uri,
            "revision": rev,
            "chunk_index": index,
            "text": text,
            "acl": [f"tenant:{tenant}", f"doc:{document.source_uri}"],
        },
    )


def _chunked(documents: Iterable[Document]) -> list[tuple[Document, str, list[str]]]:
    """Every document and its chunks, before any vector is computed."""
    return [
        (document, revision(document.content), chunks(document.content)) for document in documents
    ]


def _vectors(
    texts: list[str], embedder: Embedder | None, redact: Callable[[str], str] | None
) -> list[list[float]]:
    if embedder is None or not texts:
        return []
    embedded = [redact(text) if redact is not None else text for text in texts]
    vectors = embedder.embed(embedded)
    if len(vectors) != len(texts):
        raise IngestRefused("the embedder returned a different number of vectors than chunks")
    return vectors


def _points(
    tenant: str,
    prepared: list[tuple[Document, str, list[str]]],
    vectors: list[list[float]],
) -> list[models.PointStruct]:
    points: list[models.PointStruct] = []
    position = 0
    for document, rev, pieces in prepared:
        for index, text in enumerate(pieces):
            dense = vectors[position] if vectors else None
            points.append(_point(tenant, document, rev, (index, text), dense))
            position += 1
    return points


def _index(
    tenant: str,
    documents: Iterable[Document],
    embedder: Embedder | None,
    redact: Callable[[str], str] | None,
) -> tuple[int, list[models.PointStruct]]:
    prepared = _chunked(documents)
    texts = [text for _, _, pieces in prepared for text in pieces]
    return len(prepared), _points(tenant, prepared, _vectors(texts, embedder, redact))


def ingest(
    client: QdrantClient,
    *,
    tenant: str,
    documents: Iterable[Document],
    embedder: Embedder | None = None,
    redact: Callable[[str], str] | None = None,
) -> Report:
    """Upsert every chunk into the tenant's collection. Idempotent by point id.

    `redact` runs before the embedding call: the hosted endpoint sees the same
    DLP-cleaned text the query path serves, while the stored chunk stays as written.
    """
    name = collection_name(tenant)
    files, points = _index(tenant, documents, embedder, redact)
    if points and not client.collection_exists(name):
        vector = points[0].vector
        dense = vector.get(DENSE) if isinstance(vector, dict) else None
        _create(client, name, len(dense) if isinstance(dense, list) else None)
    for start in range(0, len(points), BATCH):
        client.upsert(name, points=points[start : start + BATCH], wait=True)
    return Report(collection=name, documents=files, chunks=len(points))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Ingest documents into a tenant's collection")
    parser.add_argument("--tenant", required=True)
    parser.add_argument("--root", help="filesystem root (default: CITADEL_INGEST_ROOT)")
    parser.add_argument("--repo", action="append", default=[], help="owner/name (repeatable)")
    parser.add_argument("--ref", default="HEAD")
    parser.add_argument("--qdrant-url", default=DEFAULT_QDRANT_URL)
    return parser


def _sources(args: argparse.Namespace) -> list[Iterable[Document]]:
    """What the configuration allows this run to read, or a refusal."""
    root = args.root or os.environ.get("CITADEL_INGEST_ROOT", "")
    repos = allowed_repos(
        os.environ.get("CITADEL_INGEST_REPOS", ""),
        [repo.strip() for repo in args.repo if repo.strip()],
    )
    sources: list[Iterable[Document]] = []
    if root:
        sources.append(filesystem(allowed_root(os.environ.get("CITADEL_INGEST_ROOT", ""), root)))
    if repos:
        token = env.optional_secret("GH_TOKEN")
        sources.extend(github(repo, args.ref, token=token) for repo in repos)
    if not sources:
        raise IngestRefused("no source given: pass --root, --repo, or both")
    return sources


def _embedder() -> Embedder:
    """The endpoint is configuration, and a chunk without a dense vector is unfindable."""
    model = os.environ.get("CITADEL_EMBEDDING_MODEL", "")
    if not model:
        raise IngestRefused("CITADEL_EMBEDDING_MODEL is not set, so no dense vector can be built")
    return OmniRouteEmbedder(
        base_url=os.environ.get("OMNIROUTE_URL", DEFAULT_OMNIROUTE_URL),
        api_key=env.optional_secret("OMNIROUTE_API_KEY"),
        model=model,
    )


def _redactor() -> Callable[[str], str]:
    """The embedding endpoint is hosted, so it sees the same DLP-cleaned text."""

    def redact(text: str) -> str:
        clean, _ = dlp.gate(
            text, surface="output", analyzer_url=os.environ.get("CITADEL_DLP_URL", DEFAULT_DLP_URL)
        )
        return clean

    return redact


def _run(sources: list[Iterable[Document]], args: argparse.Namespace) -> None:
    client = QdrantClient(url=args.qdrant_url)
    embedder = _embedder()
    redact = _redactor()
    for source in sources:
        report = ingest(
            client, tenant=args.tenant, documents=source, embedder=embedder, redact=redact
        )
        print(f"{report.collection}: {report.documents} documents, {report.chunks} chunks")


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        _run(_sources(args), args)
    except (IngestRefused, RetrievalUnavailable, dlp.DlpBlocked, OSError) as exc:
        # A source read fails closed: what was already upserted is idempotent, so
        # re-running after the fix completes rather than duplicates.
        print(f"ingest refused: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
