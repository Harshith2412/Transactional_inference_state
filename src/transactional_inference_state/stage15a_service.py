"""Localhost-only deterministic Stage 15A HTTP service."""
from __future__ import annotations

import argparse
import json
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .stage15a import RagCacheState, ToolServiceState, canonical_digest


class StateHandler(BaseHTTPRequestHandler):
    state: ToolServiceState | RagCacheState
    protocol_version = "HTTP/1.1"
    padding = ""

    def _reply(self, status: int, value: Any) -> None:
        body = json.dumps(value, sort_keys=True).encode()
        self.send_response(status); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/state": self._reply(200, self.state.document()); return
        if self.path == "/digest": self._reply(200, {"digest": canonical_digest({"state": self.state.document(), "padding": self.padding})}); return
        self._reply(404, {"error": "not found"})

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length) or b"{}")
        if self.path == "/populate":
            type(self).padding = "x" * (int(payload["megabytes"]) * 1024 * 1024)
            self._reply(200, {"bytes": len(self.padding)}); return
        if self.path in {"/write_file", "/notify_observer"}:
            Path(str(payload["path"])).write_text(str(payload["value"])); self._reply(200, {"written": True}); return
        if self.path == "/spawn_child":
            child = subprocess.Popen(["sleep", "3600"]); self._reply(200, {"pid": child.pid}); return
        if isinstance(self.state, ToolServiceState):
            if self.path == "/increment": self.state.counter += 1
            elif self.path == "/set": self.state.key_value_store[str(payload["key"])] = str(payload["value"])
            elif self.path == "/append": self.state.history.append(str(payload["value"]))
            else: self._reply(404, {"error": "not found"}); return
        else:
            if self.path == "/cache_write": self.state.retrieval_cache[str(payload["key"])] = str(payload["value"])
            elif self.path == "/cache_read": self._reply(200, {"value": self.state.retrieval_cache.get(str(payload["key"]))}); return
            elif self.path == "/add_document": self.state.documents[str(payload["key"])] = str(payload["value"])
            elif self.path == "/authorize": self.state.authorization = str(payload["value"])
            elif self.path == "/retrieve": self._reply(200, self.state.retrieve(str(payload["query"]))); return
            else: self._reply(404, {"error": "not found"}); return
        self._reply(200, self.state.document())

    def log_message(self, format: str, *args: object) -> None:
        return


def main() -> None:
    parser = argparse.ArgumentParser(); parser.add_argument("kind", choices=("tool", "rag"))
    parser.add_argument("--port", type=int, required=True); args = parser.parse_args()
    StateHandler.state = ToolServiceState() if args.kind == "tool" else RagCacheState()
    ThreadingHTTPServer(("127.0.0.1", args.port), StateHandler).serve_forever()


if __name__ == "__main__":
    main()
