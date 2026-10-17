"""LLM backends for tier 3, plus the cassette that makes a run replayable.

A ``Backend`` is one thing: turn a prompt string into a raw completion string.
Everything about strict parsing, literal verification and fail-closed handling
lives in ``llm_tier.py``, which treats the backend as untrusted the same way it
treats the model's output.

The cassette is what makes a committed metrics file checkable by somebody who
does not have an API key: a real backend is run once to record request/response
pairs to a JSONL file, and every later ``eval`` run replays from that file with
no network access at all. This is the same shape as Arbiter's cassette, kept
deliberately small here because there is one call type instead of several.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


class Backend(Protocol):
    """Anything that turns a prompt into raw completion text."""

    name: str

    def complete(self, prompt: str) -> str:
        """Return the raw completion text for ``prompt``. May raise on any
        transport, auth, or rate-limit failure; callers must not treat a raised
        exception as "no findings" - that would be failing open."""
        ...


class BackendError(RuntimeError):
    """A backend could not produce a completion at all."""


# ---------------------------------------------------------------------------
# A real backend
# ---------------------------------------------------------------------------


@dataclass
class OpenAIBackend:
    """Calls the OpenAI chat completions API. Requires the ``openai`` package.

    Imported lazily inside ``__init__`` rather than at module load, so nothing
    in this package requires the dependency, or a key, unless this specific
    backend is constructed.
    """

    model: str = "gpt-4o-mini"
    api_key: str | None = None
    name: str = "openai"

    def __post_init__(self) -> None:
        try:
            from openai import OpenAI
        except ImportError as e:
            raise BackendError(
                "the 'openai' package is required for OpenAIBackend; install hider's 'llm' extra"
            ) from e
        key = self.api_key or os.environ.get("OPENAI_API_KEY")
        if not key:
            raise BackendError("OPENAI_API_KEY is not set and no api_key was given")
        self._client = OpenAI(api_key=key)

    def complete(self, prompt: str) -> str:
        """Send ``prompt`` as one user message at temperature 0 and return the reply.

        Any transport failure, or a reply with no content, raises BackendError so
        the tier fails closed.
        """
        try:
            resp = self._client.chat.completions.create(
                model=self.model,
                temperature=0,
                max_tokens=1024,
                messages=[{"role": "user", "content": prompt}],
            )
        except Exception as e:  # noqa: BLE001 - any transport failure fails closed upstream
            raise BackendError(f"OpenAI request failed: {e}") from e
        choice = resp.choices[0].message.content if resp.choices else None
        if not choice:
            raise BackendError("OpenAI response carried no content")
        return choice


# ---------------------------------------------------------------------------
# Cassette record / replay
# ---------------------------------------------------------------------------


def _key(prompt: str) -> str:
    return hashlib.sha256(prompt.encode("utf-8")).hexdigest()


@dataclass
class CassetteBackend:
    """Wraps a real backend to record calls, or replays a prior recording
    without ever importing the real backend's dependency or touching the
    network.

    ``mode="record"`` requires ``inner``; every call is appended to ``path`` as
    one JSON line keyed by a content hash of the prompt, so a rerun with an
    unchanged prompt does not grow the file.

    ``mode="replay"`` requires no ``inner`` and no network. A prompt with no
    matching entry raises ``BackendError`` - fails closed, the same as every
    other unresolvable state in this pipeline - rather than silently falling
    back to "no findings", which would look identical to a clean line.
    """

    path: Path
    mode: str = "replay"
    inner: Backend | None = None
    name: str = "cassette"

    def __post_init__(self) -> None:
        self.path = Path(self.path)
        self._entries: dict[str, str] = {}
        if self.path.exists():
            for line in self.path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                rec = json.loads(line)
                self._entries[rec["prompt_sha256"]] = rec["response"]
        if self.mode == "record" and self.inner is None:
            raise ValueError("recording requires an inner backend")

    def complete(self, prompt: str) -> str:
        """Return the recorded response for ``prompt``.

        In replay mode a prompt with no entry raises BackendError. In record mode a
        miss calls the wrapped backend and appends the new entry to the cassette
        file.
        """
        key = _key(prompt)
        if self.mode == "replay":
            try:
                return self._entries[key]
            except KeyError:
                raise BackendError(
                    f"no cassette entry for this prompt at {self.path}; "
                    "record one with mode='record' before replaying"
                ) from None
        response = self._entries.get(key)
        if response is None:
            response = self.inner.complete(prompt)  # type: ignore[union-attr]
            self._entries[key] = response
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as f:
                f.write(
                    json.dumps({"prompt_sha256": key, "prompt": prompt, "response": response})
                    + "\n"
                )
        return response
