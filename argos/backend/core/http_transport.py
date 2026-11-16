"""Fixed isolated HTTP/1.1 entry point. Standard library only; never follows URLs."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import socket
import ssl
import struct
import sys
import time


class ProtocolError(ValueError):
    pass


class Reader:
    def __init__(self, connection: socket.socket, deadline: float):
        self.connection = connection
        self.deadline = deadline
        self.buffer = bytearray()

    def receive(self, count: int) -> bytes:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        self.connection.settimeout(remaining)
        return self.connection.recv(count)

    def exact(self, count: int) -> bytes:
        while len(self.buffer) < count:
            data = self.receive(min(8192, count - len(self.buffer)))
            if not data:
                raise ProtocolError("unexpected_eof")
            self.buffer.extend(data)
        result = bytes(self.buffer[:count])
        del self.buffer[:count]
        return result

    def line(self, maximum: int) -> bytes:
        # No unbounded readline(), including for chunk sizes and trailers.
        while b"\r\n" not in self.buffer:
            if len(self.buffer) >= maximum:
                raise ProtocolError("line_limit")
            data = self.receive(min(1024, maximum - len(self.buffer)))
            if not data:
                raise ProtocolError("unexpected_eof")
            self.buffer.extend(data)
        index = self.buffer.index(b"\r\n") + 2
        if index > maximum:
            raise ProtocolError("line_limit")
        return self.exact(index)

    def copy(self, count: int, body: bytearray) -> None:
        """Retain every received chunk, including before timeout/early EOF."""
        while count:
            if self.buffer:
                data = self.exact(min(count, len(self.buffer)))
            else:
                data = self.receive(min(count, 8192))
                if not data:
                    raise ProtocolError("unexpected_eof")
            body.extend(data)
            count -= len(data)


def headers(reader: Reader, config: dict) -> tuple[int, list[list[str]]]:
    total = 0
    for _ in range(6):
        line = reader.line(config["header_line_bytes"])
        total += len(line)
        if not re.fullmatch(rb"HTTP/1\.[01] [1-5][0-9]{2}(?: [^\r\n\x00]*)?\r\n", line):
            raise ProtocolError("status_line")
        status = int(line.split(b" ", 2)[1])
        fields = []
        while True:
            line = reader.line(config["header_line_bytes"])
            total += len(line)
            if total > config["response_header_bytes"]:
                raise ProtocolError("header_limit")
            if line == b"\r\n":
                break
            name, separator, value = line[:-2].partition(b":")
            if not separator or not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name):
                raise ProtocolError("header_syntax")
            if any(byte < 32 and byte != 9 or byte == 127 for byte in value):
                raise ProtocolError("header_syntax")
            fields.append([name.decode("ascii"), value.strip().decode("latin1")])
            if len(fields) > config["response_header_count"]:
                raise ProtocolError("header_count")
        if status == 101:
            raise ProtocolError("upgrade_denied")
        if status >= 200:
            return status, fields
    raise ProtocolError("informational_limit")


def exchange(config: dict) -> tuple[dict, bytes]:
    """Private primitive; caller must establish the firewall before invoking."""
    body = bytearray()
    result: dict = {
        "error": None,
        "status": None,
        "headers": [],
        "body_complete": False,
    }
    connection = None
    deadline = time.monotonic() + config["timeout_ms"] / 1000
    phase = "connect_failed"
    try:
        address = ipaddress.ip_address(config["connect_ip"])
        connection = socket.socket(
            socket.AF_INET6 if address.version == 6 else socket.AF_INET
        )
        connection.settimeout(max(0.001, deadline - time.monotonic()))
        connection.connect((str(address), config["port"]))
        if config["tls_hostname"] is not None:
            phase = "tls_failed"
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.load_verify_locations(cafile="/argos-ca.pem")
            context.set_alpn_protocols(["http/1.1"])
            connection.settimeout(max(0.001, deadline - time.monotonic()))
            connection = context.wrap_socket(
                connection, server_hostname=config["tls_hostname"]
            )
        phase = "protocol_failed"
        connection.settimeout(max(0.001, deadline - time.monotonic()))
        connection.sendall(
            (
                f"{config['method']} {config['request_target']} HTTP/1.1\r\n"
                f"Host: {config['host_header']}\r\n"
                "Accept-Encoding: identity\r\nConnection: close\r\n"
                "User-Agent: Argos/1\r\n\r\n"
            ).encode("ascii")
        )
        reader = Reader(connection, deadline)
        status, fields = headers(reader, config)
        result.update(status=status, headers=fields)
        values: dict[str, list[str]] = {}
        for name, value in fields:
            values.setdefault(name.lower(), []).append(value)
        lengths = values.get("content-length", [])
        transfers = values.get("transfer-encoding", [])
        if lengths and (
            len(lengths) != 1 or not re.fullmatch(r"[0-9]{1,20}", lengths[0])
        ):
            raise ProtocolError("content_length")
        if transfers and (lengths or transfers != ["chunked"]):
            raise ProtocolError("transfer_encoding")
        if values.get("content-encoding", ["identity"]) != ["identity"]:
            result["error"] = "unsupported_encoding"
            return result, bytes(body)
        maximum = config["body_bytes"]
        if config["method"] == "HEAD" or status in (204, 304):
            result["body_complete"] = True
        elif transfers:
            chunks = 0
            while True:
                chunks += 1
                if chunks > 65536:
                    raise ProtocolError("chunk_limit")
                line = reader.line(config["header_line_bytes"])[:-2]
                # Extensions/trailers are deliberately unsupported in this slice.
                if not re.fullmatch(rb"[0-9a-fA-F]{1,16}", line):
                    raise ProtocolError("chunk_syntax")
                size = int(line, 16)
                if size == 0:
                    if reader.line(2) != b"\r\n":
                        raise ProtocolError("trailers_denied")
                    result["body_complete"] = True
                    break
                retain = min(size, maximum - len(body))
                reader.copy(retain, body)
                if retain < size:
                    result["error"] = "response_limit"
                    break
                if reader.exact(2) != b"\r\n":
                    raise ProtocolError("chunk_syntax")
        elif lengths:
            size = int(lengths[0])
            reader.copy(min(size, maximum), body)
            result["body_complete"] = size <= maximum
            if size > maximum:
                result["error"] = "response_limit"
        else:
            while len(body) <= maximum:
                data = (
                    reader.exact(len(reader.buffer))
                    if reader.buffer
                    else reader.receive(min(8192, maximum + 1 - len(body)))
                )
                if not data:
                    result["body_complete"] = True
                    break
                body.extend(data)
            if len(body) > maximum:
                del body[maximum:]
                result["error"] = "response_limit"
    except TimeoutError:
        result["error"] = "request_timeout"
    except ssl.SSLError:
        result["error"] = "tls_failed"
    except (OSError, ValueError):
        result["error"] = phase
    finally:
        if connection is not None:
            connection.close()
    return result, bytes(body)


def frame(metadata: dict, body: bytes) -> bytes:
    metadata = dict(
        metadata, body_bytes=len(body), body_sha256=hashlib.sha256(body).hexdigest()
    )
    encoded = json.dumps(metadata, ensure_ascii=True, separators=(",", ":")).encode()
    if len(encoded) > 65536:
        # Latin-1 headers can expand sixfold in ASCII JSON. Keep the bounded
        # body but never advertise complete headers after their removal.
        metadata.update(headers=[], error="response_limit", body_complete=False)
        encoded = json.dumps(metadata, separators=(",", ":")).encode()
    return struct.pack("!I", len(encoded)) + encoded + body


def main() -> int:
    try:
        payload = sys.stdin.buffer.read(65537)
        if len(payload) > 65536:
            return 125
        config = json.loads(payload)
        metadata, body = exchange(config)
        sys.stdout.buffer.write(frame(metadata, body))
        return 0
    except (OSError, ValueError, KeyError, TypeError):
        return 125


if __name__ == "__main__":
    raise SystemExit(main())
