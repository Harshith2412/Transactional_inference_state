"""Dependency-free localhost Redis transport for opt-in prototype evaluation."""
from __future__ import annotations
import socket
from typing import Mapping
from .redis_participant import (BufferedRedisWrite, ExpectedRedisValue,
                                RedisApplyResult, RedisWriteOperation)

_SCRIPT = b"""
for i,key in ipairs(KEYS) do
  local base=(i-1)*4
  local current=redis.call('GET',key)
  local exists=ARGV[base+1]
  if (exists=='0' and current) or (exists=='1' and current~=ARGV[base+2]) then return 0 end
end
for i,key in ipairs(KEYS) do
  local base=(i-1)*4
  local op=ARGV[base+3]
  if op=='S' then redis.call('SET',key,ARGV[base+4])
  elseif op=='D' then redis.call('DEL',key) end
end
return 1
"""

class SocketRedisTransport:
    """Tiny RESP2 transport restricted to PING, GET, and a fixed EVAL script."""
    def __init__(self, host: str = "127.0.0.1", port: int = 6379, *,
                 database: int = 0, timeout: float = 2.0) -> None:
        if host not in {"127.0.0.1", "localhost", "::1"}:
            raise ValueError("prototype Redis transport is localhost-only")
        self.host, self.port, self.database, self.timeout = host, port, database, timeout

    def ping(self) -> bool: return self._command(b"PING") == b"PONG"
    def get(self, key: bytes) -> bytes | None: return self._command(b"GET", key)

    def validate(self, expected: Mapping[bytes, ExpectedRedisValue]) -> bool:
        return self._apply(expected, {})

    def compare_and_apply(self, expected: Mapping[bytes, ExpectedRedisValue],
                          writes: Mapping[bytes, BufferedRedisWrite]) -> RedisApplyResult:
        applied = self._apply(expected, writes)
        return RedisApplyResult(applied, not applied)

    def _apply(self, expected: Mapping[bytes, ExpectedRedisValue],
               writes: Mapping[bytes, BufferedRedisWrite]) -> bool:
        keys = list(expected)
        arguments: list[bytes] = [b"EVAL", _SCRIPT, str(len(keys)).encode(), *keys]
        for key in keys:
            item, write = expected[key], writes.get(key)
            op = (b"S" if write and write.operation is RedisWriteOperation.SET else
                  b"D" if write else b"N")
            arguments.extend((b"1" if item.exists else b"0", item.value or b"", op,
                              write.value if write and write.value is not None else b""))
        return self._command(*arguments) == 1

    def _command(self, *parts: bytes):
        payload = b"*" + str(len(parts)).encode() + b"\r\n" + b"".join(
            b"$" + str(len(part)).encode() + b"\r\n" + part + b"\r\n"
            for part in parts
        )
        with socket.create_connection((self.host, self.port), self.timeout) as connection:
            stream = connection.makefile("rb")
            if self.database:
                connection.sendall(self._encode(b"SELECT", str(self.database).encode()))
                self._read(stream)
            connection.sendall(payload); return self._read(stream)

    @staticmethod
    def _encode(*parts: bytes) -> bytes:
        return b"*" + str(len(parts)).encode() + b"\r\n" + b"".join(
            b"$" + str(len(x)).encode() + b"\r\n" + x + b"\r\n" for x in parts)

    def _read(self, stream):
        prefix, line = stream.read(1), stream.readline()[:-2]
        if prefix == b"+": return line
        if prefix == b":": return int(line)
        if prefix == b"-": raise RuntimeError(line.decode("utf-8", "replace"))
        if prefix == b"$":
            length = int(line)
            if length == -1: return None
            value = stream.read(length); stream.read(2); return value
        raise RuntimeError("invalid Redis response")
