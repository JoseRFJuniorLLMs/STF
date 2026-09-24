"""Cliente loopback do NÚCLEO do HeraclitusDB (gRPC `heraclitus.v1.Heraclitus`).

O adapter REST (`heraclitus_adapter.py`) fala com o Agent Black Box (porta 8080),
que só aceita eventos de red-team. O log processual precisa do primitivo
genérico do núcleo — `Append` (evento imutável com `parents` e chave de
idempotência) e `Query` (GQL com `AS OF LSN`) — que só existe em gRPC.

A POC continua a correr só com a biblioteca padrão: as mensagens protobuf são
codificadas à mão (são quatro, todas planas) e o `grpcio` é importado apenas
quando se liga ao servidor. Sem ele, o cliente responde "indisponível" em vez
de rebentar.
"""
from __future__ import annotations

import json
from typing import Any

ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1"}
SERVICE = "/heraclitus.v1.Heraclitus/"
MAX_MESSAGE_BYTES = 16 * 1024 * 1024


class CoreUnavailable(RuntimeError):
    """O núcleo não está alcançável (grpcio ausente, porta fechada, timeout)."""


# --------------------------------------------------------------- protobuf mínimo
def _varint(value: int) -> bytes:
    if value < 0:
        raise ValueError("varint negativo")
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _field_bytes(number: int, data: bytes) -> bytes:
    return _varint((number << 3) | 2) + _varint(len(data)) + data


def _field_str(number: int, text: str) -> bytes:
    return _field_bytes(number, text.encode("utf-8")) if text else b""


def _read_varint(buf: bytes, pos: int) -> tuple[int, int]:
    shift = result = 0
    while True:
        if pos >= len(buf):
            raise ValueError("varint truncado")
        byte = buf[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7
        if shift > 63:
            raise ValueError("varint demasiado longo")


def _fields(buf: bytes):
    """Itera (número, valor) de uma mensagem; ignora campos desconhecidos."""
    pos = 0
    while pos < len(buf):
        key, pos = _read_varint(buf, pos)
        number, wire = key >> 3, key & 7
        if wire == 0:
            value, pos = _read_varint(buf, pos)
        elif wire == 2:
            size, pos = _read_varint(buf, pos)
            if pos + size > len(buf):
                raise ValueError("campo truncado")
            value, pos = buf[pos:pos + size], pos + size
        elif wire == 1:
            value, pos = buf[pos:pos + 8], pos + 8
        elif wire == 5:
            value, pos = buf[pos:pos + 4], pos + 4
        else:
            raise ValueError(f"wire type {wire} não suportado")
        yield number, value


def encode_append_request(agent_id: str, session_id: str, kind: str, content: bytes,
                          attrs: dict[str, str] | None = None, parents: list[str] | None = None,
                          idempotency_key: str = "") -> bytes:
    out = _field_str(1, agent_id) + _field_str(2, session_id) + _field_str(3, kind)
    if content:
        out += _field_bytes(4, content)
    for key, value in sorted((attrs or {}).items()):
        out += _field_bytes(8, _field_str(1, str(key)) + _field_str(2, str(value)))
    for parent in parents or []:
        out += _field_str(9, parent)
    return out + _field_str(10, idempotency_key)


def decode_append_response(buf: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {"lsn": 0, "deduplicated": False, "event_id": ""}
    for number, value in _fields(buf):
        if number == 1:
            out["lsn"] = value
        elif number == 2:
            out["deduplicated"] = bool(value)
        elif number == 3:
            out["event_id"] = value.decode("utf-8")
    return out


def encode_query_request(gql: str) -> bytes:
    return _field_str(1, gql)


def decode_query_response(buf: bytes) -> str:
    for number, value in _fields(buf):
        if number == 1:
            return value.decode("utf-8")
    return "[]"


# --------------------------------------------------------------------- cliente
class HeraclitusCore:
    def __init__(self, addr: str = "127.0.0.1:17474", timeout: float = 3.0) -> None:
        host = addr.rsplit(":", 1)[0].strip("[]")
        if host not in ALLOWED_HOSTS:
            raise ValueError("Safety gate: o núcleo HeraclitusDB só é aceito em loopback")
        self.addr = addr
        self.timeout = timeout
        self._channel = None

    def _call(self, method: str, request: bytes) -> bytes:
        try:
            import grpc
        except ImportError as exc:
            raise CoreUnavailable("pacote grpcio não instalado (pip install grpcio)") from exc
        if self._channel is None:
            channel = grpc.insecure_channel(self.addr, options=[
                ("grpc.max_receive_message_length", MAX_MESSAGE_BYTES),
            ])
            try:
                grpc.channel_ready_future(channel).result(timeout=self.timeout)
            except grpc.FutureTimeoutError as exc:
                channel.close()
                raise CoreUnavailable(f"núcleo HeraclitusDB inacessível em {self.addr}") from exc
            self._channel = channel
        stub = self._channel.unary_unary(SERVICE + method)
        try:
            return stub(request, timeout=self.timeout)
        except grpc.RpcError as exc:
            if exc.code() in (grpc.StatusCode.UNAVAILABLE, grpc.StatusCode.DEADLINE_EXCEEDED):
                self.close()
                raise CoreUnavailable(f"núcleo HeraclitusDB inacessível em {self.addr}") from exc
            raise

    def append(self, *, agent_id: str, session_id: str, kind: str, content: dict[str, Any],
               attrs: dict[str, str], parents: list[str], idempotency_key: str) -> dict[str, Any]:
        raw = json.dumps(content, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        request = encode_append_request(agent_id, session_id, kind, raw, attrs, parents, idempotency_key)
        return decode_append_response(self._call("Append", request))

    def query(self, gql: str) -> list[dict[str, Any]]:
        rows = json.loads(decode_query_response(self._call("Query", encode_query_request(gql))))
        return rows if isinstance(rows, list) else []

    def close(self) -> None:
        if self._channel is not None:
            self._channel.close()
            self._channel = None
