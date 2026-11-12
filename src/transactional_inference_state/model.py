"""Untrusted model adapters; the transaction core does not depend on them."""
from __future__ import annotations

import json
from typing import Protocol, runtime_checkable
import urllib.error
import urllib.request


@runtime_checkable
class ModelAdapter(Protocol):
    def generate(self, prompt: str, *, retrieved_content: str | None = None) -> str: ...


class DeterministicModelAdapter:
    """Reproducible adapter returning configured untrusted text verbatim."""
    def __init__(self, output: str) -> None:
        self.output = output

    def generate(self, prompt: str, *, retrieved_content: str | None = None) -> str:
        return self.output


class OllamaUnavailableError(RuntimeError):
    """Optional local Ollama endpoint/model could not produce usable text."""


class OllamaModelAdapter:
    """Optional localhost-only Ollama adapter using the standard library."""

    def __init__(self, model: str, *, base_url: str = "http://127.0.0.1:11434",
                 timeout_seconds: float = 30.0, temperature: float = 0.0,
                 seed: int | None = 0, top_p: float = 0.9,
                 maximum_output_tokens: int = 1024,
                 native_schema: dict | None = None) -> None:
        if not model:
            raise ValueError("model must not be empty")
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.temperature, self.seed, self.top_p = temperature, seed, top_p
        self.maximum_output_tokens = maximum_output_tokens
        self.native_schema = native_schema

    def generate(self, prompt: str, *, retrieved_content: str | None = None) -> str:
        combined = prompt
        if retrieved_content is not None:
            combined += f"\n\nUntrusted retrieved content:\n{retrieved_content}"
        request = urllib.request.Request(
            f"{self.base_url}/api/generate",
            data=json.dumps({"model": self.model, "prompt": combined,
                             "stream": False,
                             "format": self.native_schema or "json",
                             "options": {**{"temperature": self.temperature,
                                             "top_p": self.top_p,
                                             "num_predict": self.maximum_output_tokens},
                                         **({"seed": self.seed}
                                            if self.seed is not None else {})}}).encode(),
            headers={"Content-Type": "application/json"}, method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                payload = json.loads(response.read().decode())
        except (OSError, urllib.error.URLError, json.JSONDecodeError) as error:
            raise OllamaUnavailableError(f"Ollama unavailable: {error}") from error
        output = payload.get("response")
        if not isinstance(output, str):
            raise OllamaUnavailableError("Ollama response did not contain model text")
        return output
