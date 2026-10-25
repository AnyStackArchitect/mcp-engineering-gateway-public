#!/usr/bin/env python3
"""Bounded common event-clock semantics for private cross-source evidence.

An explicit UTC timestamp is a parsed field, NOT proof that source clocks agree.
Unknown local timestamps remain unanchored; no synthetic year, skew or identity.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from casework import CaseError

MODEL_VERSION = "1"
MAX_WINDOW_MS = 300_000
TIMED_QUALITIES = frozenset({"OFFSET", "EXPLICIT_EPOCH"})
UNTIMED_QUALITIES = frozenset({
    "NO_TIMESTAMP", "NO_TIMEZONE", "NO_YEAR_OR_TIMEZONE",
    "AMBIGUOUS_NUMERIC", "INVALID",
})
OBSERVED_BASIS = "DECLARED_UTC_CLOCK_UNVERIFIED"
UNANCHORED_BASIS = "UNANCHORED_NO_UTC"


def parse_declared_utc(utc: str) -> datetime:
    """Require a bounded, aware UTC field from an approved upstream decoder."""
    if type(utc) is not str or not 1 <= len(utc) <= 80 or "T" not in utc:
        raise CaseError("Correlated UTC evidence timestamp invalid")
    try:
        dt = datetime.fromisoformat(utc.replace("Z", "+00:00"))
        if dt.tzinfo is None or dt.utcoffset() != timedelta(0):
            raise ValueError("time is not explicitly UTC")
        return dt.astimezone(timezone.utc)
    except (ValueError, OverflowError) as exc:
        raise CaseError("Correlated UTC evidence timestamp invalid") from exc


def checked_time_basis(utc: str | None, quality: str) -> str:
    """Fail closed on contradictions in provider-derived clock metadata."""
    if type(quality) is not str:
        raise CaseError("Correlated clock quality invalid")
    if utc is None:
        if quality not in UNTIMED_QUALITIES:
            raise CaseError("Correlated source claims timed quality without UTC")
        return UNANCHORED_BASIS
    parse_declared_utc(utc)
    if quality not in TIMED_QUALITIES:
        raise CaseError("Correlated UTC lacks explicit time-basis quality")
    return OBSERVED_BASIS


def window_bounds(utc: str, before_ms: int, after_ms: int) -> tuple[str, str]:
    if (type(before_ms) is not int or type(after_ms) is not int or
            not 0 <= before_ms <= MAX_WINDOW_MS or
            not 0 <= after_ms <= MAX_WINDOW_MS):
        raise CaseError("Correlation window must be bounded integer milliseconds")
    center = parse_declared_utc(utc)
    try:
        start = center - timedelta(milliseconds=before_ms)
        end = center + timedelta(milliseconds=after_ms)
    except OverflowError as exc:
        raise CaseError("Correlation window exceeds representable UTC") from exc
    return (start.isoformat(timespec="microseconds"),
            end.isoformat(timespec="microseconds"))


def observed_delta_ms(anchor_utc: str, event_utc: str) -> float:
    """Signed observation delta, not a measured one-way latency."""
    difference = parse_declared_utc(event_utc) - parse_declared_utc(anchor_utc)
    microseconds = (difference.days * 86_400_000_000 +
                    difference.seconds * 1_000_000 + difference.microseconds)
    return microseconds / 1000
