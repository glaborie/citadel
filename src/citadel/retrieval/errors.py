"""Retrieval failures. Both are refusals: a caller must not search on."""


class QueryRefused(RuntimeError):
    """The request cannot be served without widening what the subject may read."""


class RetrievalUnavailable(RuntimeError):
    """An endpoint retrieval depends on did not answer usefully."""
