"""LLM backends for tier 3, the resilience wrapper, and the cassette.

A ``Backend`` is one thing: turn a prompt string into a raw completion string.
Everything about strict parsing, literal verification and fail-closed handling
lives in ``llm_tier.py``, which treats the backend as untrusted the same way it
treats the model's output.

**System role.** A prompt arrives as one string so that cassettes, caches and
fakes all key on a single value. Inside a real backend the string is split at
the data fence (``split_prompt``): the instructions before it go to the
provider's system role, the fenced data goes to the user role. The cassette
key is the hash of the whole string, so recordings made before this split
still replay.

**Resilience.** ``ResilientBackend`` wraps any backend with bounded retries
(exponential backoff with jitter), a circuit breaker that stops hammering a
provider that keeps failing, and an optional fallback backend tried once the
primary has failed or the breaker is open. Every exhausted path still raises
``BackendError``: the pipeline fails closed, never open.

**Usage.** Backends that see a provider's token counts add them to a shared,
thread-safe ``UsageMeter`` so a run can report measured tokens and a list-price
cost rather than a character-count estimate.

The cassette is what makes a committed metrics file checkable by somebody who
does not have an API key: a real backend is run once to record request/response
pairs to a JSONL file, and every later ``eval`` run replays from that file with
no network access at all. The first line of a cassette recorded by this
version is a header naming the prompt version, model and backend that produced
it, so a published number is traceable to the exact prompt and model.
"""

from __future__ import annotations

import hashlib
import json
import os
import random
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Protocol

#: The fence that separates instructions from data in every tier 3 prompt.
#: ``split_prompt`` cuts the prompt here; ``llm_tier.build_prompt`` writes it.
DATA_FENCE = "\n\n<<<DATA"


class Backend(Protocol):
    name: str

    def complete(self, prompt: str) -> str:
        """Return the raw completion text for ``prompt``. May raise on any
        transport, auth, or rate-limit failure; callers must not treat a raised
        exception as "no findings" - that would be failing open."""
        ...


class BackendError(RuntimeError):
    """A backend could not produce a completion at all."""


def split_prompt(prompt: str) -> tuple[str | None, str]:
    """(system, user) for a tier 3 prompt.

    Everything before the first data fence is instructions and goes to the
    system role; the fence and everything after it is untrusted data and goes
    to the user role. A prompt without a fence is sent whole as the user
    message, which is what every backend did before the split existed.
    """
    i = prompt.find(DATA_FENCE)
    if i <= 0:
        return None, prompt
    return prompt[:i], prompt[i + 2:]  # drop the blank line, keep the fence


# ---------------------------------------------------------------------------
# Usage metering
# ---------------------------------------------------------------------------

#: List prices, US dollars per million tokens (input, output). Only models
#: whose price is known for certain are listed; an unlisted model's cost is
#: reported as unpriced rather than guessed.
PRICES_USD_PER_M: dict[str, tuple[float, float]] = {
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-4o": (2.50, 10.00),
    "claude-haiku-4-5-20251001": (1.00, 5.00),
    "claude-haiku-4-5": (1.00, 5.00),
}


def price_for(model: str | None) -> tuple[float, float] | None:
    if not model:
        return None
    if model in PRICES_USD_PER_M:
        return PRICES_USD_PER_M[model]
    # Dated snapshots ("gpt-4o-mini-2024-07-18") share the base model's price.
    for name, p in sorted(PRICES_USD_PER_M.items(), key=lambda kv: -len(kv[0])):
        if model.startswith(name):
            return p
    return None


@dataclass
class UsageMeter:
    """Thread-safe token and call counters, by model."""

    calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    by_model: dict[str, dict[str, int]] = field(default_factory=dict)
    # Reentrant: to_dict() reads under the lock and calls cost_usd(), which
    # locks again.
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    def add(self, model: str | None, input_tokens: int | None, output_tokens: int | None) -> None:
        with self._lock:
            self.calls += 1
            self.input_tokens += int(input_tokens or 0)
            self.output_tokens += int(output_tokens or 0)
            m = self.by_model.setdefault(model or "?", {"calls": 0, "input_tokens": 0,
                                                        "output_tokens": 0})
            m["calls"] += 1
            m["input_tokens"] += int(input_tokens or 0)
            m["output_tokens"] += int(output_tokens or 0)

    def cost_usd(self) -> float | None:
        """Measured tokens times list price; ``None`` if any model is unpriced."""
        total = 0.0
        with self._lock:
            for model, m in self.by_model.items():
                p = price_for(model)
                if p is None:
                    return None
                total += m["input_tokens"] / 1e6 * p[0] + m["output_tokens"] / 1e6 * p[1]
        return round(total, 6)

    def to_dict(self) -> dict:
        with self._lock:
            return {
                "calls": self.calls,
                "input_tokens": self.input_tokens,
                "output_tokens": self.output_tokens,
                "by_model": {k: dict(v) for k, v in self.by_model.items()},
                "cost_usd_list_price": self.cost_usd(),
            }


# ---------------------------------------------------------------------------
# Real backends
# ---------------------------------------------------------------------------


@dataclass
class OpenAIBackend:
    """Calls an OpenAI-compatible chat completions API. Requires ``openai``.

    Imported lazily inside ``__init__`` rather than at module load, so nothing
    in this package requires the dependency, or a key, unless this specific
    backend is constructed. ``base_url`` points it at any OpenAI-compatible
    server (a local model, a different vendor's gateway); ``json_mode`` asks
    for a JSON object via ``response_format`` so the shape is enforced by the
    provider as well as by our parser. Retries are left to
    ``ResilientBackend``: the SDK's own are turned off so one policy applies.
    """

    model: str = "gpt-4o-mini"
    api_key: str | None = None
    base_url: str | None = None
    timeout_s: float = 30.0
    json_mode: bool = True
    max_tokens: int = 1024
    usage: UsageMeter | None = None
    name: str = "openai"

    def __post_init__(self) -> None:
        try:
            from openai import OpenAI
        except ImportError as e:
            raise BackendError(
                "the 'openai' package is required for OpenAIBackend; install "
                "hider's 'llm' extra"
            ) from e
        key = self.api_key or os.environ.get("OPENAI_API_KEY")
        if not key and not self.base_url:
            raise BackendError("OPENAI_API_KEY is not set and no api_key was given")
        self._client = OpenAI(api_key=key or "none", base_url=self.base_url,
                              timeout=self.timeout_s, max_retries=0)

    def complete(self, prompt: str) -> str:
        system, user = split_prompt(prompt)
        messages = ([{"role": "system", "content": system}] if system else []) + [
            {"role": "user", "content": user}]
        kwargs: dict = {}
        if self.json_mode:
            kwargs["response_format"] = {"type": "json_object"}
        try:
            resp = self._client.chat.completions.create(
                model=self.model, temperature=0, max_tokens=self.max_tokens,
                messages=messages, **kwargs,
            )
        except Exception as e:  # noqa: BLE001 - any transport failure fails closed upstream
            raise BackendError(f"OpenAI request failed: {e}") from e
        if self.usage is not None:
            u = getattr(resp, "usage", None)
            self.usage.add(getattr(resp, "model", None) or self.model,
                           getattr(u, "prompt_tokens", None),
                           getattr(u, "completion_tokens", None))
        choice = resp.choices[0].message.content if resp.choices else None
        if not choice:
            raise BackendError("OpenAI response carried no content")
        return choice


@dataclass
class AnthropicBackend:
    """Calls the Anthropic Messages API. Requires the ``anthropic`` package.

    Same contract as ``OpenAIBackend``: instructions go to the system
    parameter, the fenced data to the user turn, and any failure raises
    ``BackendError``.
    """

    model: str = "claude-haiku-4-5-20251001"
    api_key: str | None = None
    base_url: str | None = None
    timeout_s: float = 30.0
    max_tokens: int = 1024
    usage: UsageMeter | None = None
    name: str = "anthropic"

    def __post_init__(self) -> None:
        try:
            from anthropic import Anthropic
        except ImportError as e:
            raise BackendError(
                "the 'anthropic' package is required for AnthropicBackend; install "
                "hider's 'llm' extra"
            ) from e
        key = self.api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            raise BackendError("ANTHROPIC_API_KEY is not set and no api_key was given")
        # An empty ANTHROPIC_BASE_URL in the environment (some tool sessions
        # export one) would otherwise be taken literally by the SDK.
        base = self.base_url or os.environ.get("ANTHROPIC_BASE_URL") or "https://api.anthropic.com"
        self._client = Anthropic(api_key=key, base_url=base, timeout=self.timeout_s,
                                 max_retries=0)

    def complete(self, prompt: str) -> str:
        system, user = split_prompt(prompt)
        kwargs: dict = {"system": system} if system else {}
        try:
            # No temperature: the 2.x SDK's Messages.create does not take one.
            resp = self._client.messages.create(
                model=self.model, max_tokens=self.max_tokens,
                messages=[{"role": "user", "content": user}], **kwargs,
            )
        except Exception as e:  # noqa: BLE001
            raise BackendError(f"Anthropic request failed: {e}") from e
        if self.usage is not None:
            u = getattr(resp, "usage", None)
            self.usage.add(getattr(resp, "model", None) or self.model,
                           getattr(u, "input_tokens", None),
                           getattr(u, "output_tokens", None))
        text = "".join(getattr(b, "text", "") for b in (resp.content or []))
        if not text:
            raise BackendError("Anthropic response carried no text content")
        return text


# ---------------------------------------------------------------------------
# Retries, circuit breaker, fallback
# ---------------------------------------------------------------------------


@dataclass
class ResilientBackend:
    """Bounded retries, a circuit breaker and an optional fallback.

    * Each call to ``inner`` is tried up to ``retries + 1`` times, sleeping
      ``base_delay * 2**attempt`` seconds (capped, with jitter) between tries.
    * ``breaker_threshold`` consecutive exhausted calls open the breaker for
      ``cooldown_s``; while open, ``inner`` is not called at all. One trial
      call is allowed after the cooldown; success closes the breaker.
    * When ``inner`` is exhausted or the breaker is open, ``fallback`` is tried
      once (with its own retries if it is itself resilient). If there is no
      fallback, or it fails too, ``BackendError`` propagates and the pipeline
      fails closed.

    ``sleep`` is injectable so tests do not wait.
    """

    inner: Backend
    retries: int = 2
    base_delay: float = 0.5
    max_delay: float = 8.0
    breaker_threshold: int = 5
    cooldown_s: float = 30.0
    fallback: Backend | None = None
    sleep: Callable[[float], None] = time.sleep
    clock: Callable[[], float] = time.monotonic
    name: str = "resilient"

    def __post_init__(self) -> None:
        self._lock = threading.Lock()
        self._consecutive_failures = 0
        self._opened_at: float | None = None
        self._rng = random.Random(0xC1C)
        self.stats = {"calls": 0, "retries": 0, "failures": 0, "fallbacks": 0,
                      "breaker_trips": 0, "breaker_short_circuits": 0}
        self.name = f"resilient({getattr(self.inner, 'name', '?')})"

    @property
    def model(self) -> str | None:
        return getattr(self.inner, "model", None)

    # -- breaker -----------------------------------------------------------

    def _breaker_allows(self) -> bool:
        with self._lock:
            if self._opened_at is None:
                return True
            if self.clock() - self._opened_at >= self.cooldown_s:
                return True  # half-open: let one trial through
            return False

    def _record_success(self) -> None:
        with self._lock:
            self._consecutive_failures = 0
            self._opened_at = None

    def _record_failure(self) -> None:
        with self._lock:
            self._consecutive_failures += 1
            self.stats["failures"] += 1
            if self._consecutive_failures >= self.breaker_threshold:
                if self._opened_at is None:
                    self.stats["breaker_trips"] += 1
                self._opened_at = self.clock()

    @property
    def breaker_open(self) -> bool:
        with self._lock:
            return self._opened_at is not None and \
                self.clock() - self._opened_at < self.cooldown_s

    # -- the call ----------------------------------------------------------

    def complete(self, prompt: str) -> str:
        with self._lock:
            self.stats["calls"] += 1
        primary_error: BackendError | None = None
        if self._breaker_allows():
            for attempt in range(self.retries + 1):
                try:
                    out = self.inner.complete(prompt)
                except BackendError as e:
                    primary_error = e
                    if attempt < self.retries:
                        with self._lock:
                            self.stats["retries"] += 1
                        delay = min(self.max_delay, self.base_delay * (2 ** attempt))
                        self.sleep(delay * (0.5 + self._rng.random()))
                        continue
                    self._record_failure()
                else:
                    self._record_success()
                    return out
        else:
            with self._lock:
                self.stats["breaker_short_circuits"] += 1
            primary_error = BackendError(
                f"circuit open for {getattr(self.inner, 'name', '?')}: "
                f"{self._consecutive_failures} consecutive failures")
        if self.fallback is not None:
            with self._lock:
                self.stats["fallbacks"] += 1
            try:
                return self.fallback.complete(prompt)
            except BackendError as e:
                raise BackendError(
                    f"primary failed ({primary_error}); fallback failed ({e})") from e
        raise primary_error  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Cassette record / replay
# ---------------------------------------------------------------------------


CASSETTE_SCHEMA = "hider.cassette.v1"


def _key(prompt: str) -> str:
    return hashlib.sha256(prompt.encode("utf-8")).hexdigest()


@dataclass
class CassetteBackend:
    """Wraps a real backend to record calls, or replays a prior recording
    without ever importing the real backend's dependency or touching the
    network.

    ``mode="record"`` requires ``inner``; every call is appended to ``path`` as
    one JSON line keyed by a content hash of the prompt, so a rerun with an
    unchanged prompt does not grow the file. A new file starts with a header
    line (``CASSETTE_SCHEMA``) naming the prompt version, model and backend.

    ``mode="replay"`` requires no ``inner`` and no network. A prompt with no
    matching entry raises ``BackendError`` - fails closed, the same as every
    other unresolvable state in this pipeline - rather than silently falling
    back to "no findings", which would look identical to a clean line.
    """

    path: Path
    mode: str = "replay"
    inner: Backend | None = None
    prompt_version: str | None = None
    name: str = "cassette"

    def __post_init__(self) -> None:
        self.path = Path(self.path)
        self._entries: dict[str, str] = {}
        self.header: dict | None = None
        self._lock = threading.Lock()
        if self.path.exists():
            for line in self.path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                rec = json.loads(line)
                if rec.get("schema") == CASSETTE_SCHEMA:
                    self.header = rec
                    continue
                self._entries[rec["prompt_sha256"]] = rec["response"]
        if self.mode == "record" and self.inner is None:
            raise ValueError("recording requires an inner backend")

    @property
    def model(self) -> str | None:
        if self.inner is not None:
            return getattr(self.inner, "model", None)
        return (self.header or {}).get("model")

    def provenance(self) -> dict:
        """What produced the recorded responses, for the metrics file."""
        h = self.header or {}
        return {
            "cassette": str(self.path),
            "entries": len(self._entries),
            "backend": h.get("backend") or (getattr(self.inner, "name", None)
                                             if self.inner else None),
            "model": self.model,
            "prompt_version": h.get("prompt_version") or self.prompt_version,
            "recorded_at": h.get("recorded_at"),
        }

    def _write_header(self) -> None:
        self.header = {
            "schema": CASSETTE_SCHEMA,
            "prompt_version": self.prompt_version,
            "model": self.model,
            "backend": getattr(self.inner, "name", None),
            "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(self.header) + "\n")

    def complete(self, prompt: str) -> str:
        key = _key(prompt)
        if self.mode == "replay":
            try:
                return self._entries[key]
            except KeyError:
                raise BackendError(
                    f"no cassette entry for this prompt at {self.path}; "
                    "record one with mode='record' before replaying"
                ) from None
        with self._lock:
            response = self._entries.get(key)
        if response is None:
            response = self.inner.complete(prompt)  # type: ignore[union-attr]
            with self._lock:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                if not self.path.exists() or self.path.stat().st_size == 0:
                    self._write_header()
                self._entries[key] = response
                with self.path.open("a", encoding="utf-8") as f:
                    f.write(json.dumps({"prompt_sha256": key, "prompt": prompt,
                                         "response": response}) + "\n")
        return response
