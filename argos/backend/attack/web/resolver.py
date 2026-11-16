"""Supervised system DNS; cancellation terminates the resolver process itself."""

from __future__ import annotations

import ipaddress
import json
import subprocess
import tempfile
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from threading import Event

from .contracts import ResolvedWebTarget, WebErrorCode
from .policy import WebPolicyError, WebPreflight


class WebResolver:
    def resolve(
        self,
        preflight: WebPreflight,
        *,
        cancel: Event | None = None,
        active: Callable[[], bool] | None = None,
    ) -> ResolvedWebTarget:
        if (
            cancel is not None
            and cancel.is_set()
            or active is not None
            and not active()
        ):
            raise WebPolicyError(WebErrorCode.CANCELLED)
        try:
            literal = ipaddress.ip_address(preflight.hostname)
        except ValueError:
            literal = None
        if literal is not None:
            return ResolvedWebTarget(
                preflight.hostname, (str(literal),), datetime.now(UTC)
            )
        timeout = min(
            preflight.execution_limits.dns_timeout_seconds, preflight.timeout_ms / 1000
        )
        deadline = time.monotonic() + timeout
        payload = json.dumps(
            {
                "hostname": preflight.hostname,
                "maximum": preflight.execution_limits.max_dns_addresses,
            }
        ).encode()
        if (
            cancel is not None
            and cancel.is_set()
            or active is not None
            and not active()
        ):
            raise WebPolicyError(WebErrorCode.CANCELLED)
        with tempfile.TemporaryFile() as source, tempfile.TemporaryFile() as output:
            source.write(payload)
            source.seek(0)
            try:
                process = subprocess.Popen(
                    [
                        "/usr/bin/python3",
                        "-I",
                        str(Path(__file__).with_name("dns_child.py")),
                    ],
                    stdin=source,
                    stdout=output,
                    stderr=subprocess.DEVNULL,
                    close_fds=True,
                    env={"LANG": "C.UTF-8"},
                )
            except OSError:
                raise WebPolicyError(WebErrorCode.DNS_FAILED) from None
            try:
                while process.poll() is None:
                    if (
                        cancel is not None
                        and cancel.is_set()
                        or active is not None
                        and not active()
                    ):
                        raise WebPolicyError(WebErrorCode.CANCELLED)
                    if time.monotonic() >= deadline:
                        raise WebPolicyError(WebErrorCode.DNS_TIMEOUT)
                    if output.tell() > 4096:
                        raise WebPolicyError(WebErrorCode.DNS_DENIED)
                    time.sleep(0.02)
                if time.monotonic() >= deadline:
                    raise WebPolicyError(WebErrorCode.DNS_TIMEOUT)
                if (
                    cancel is not None
                    and cancel.is_set()
                    or active is not None
                    and not active()
                ):
                    raise WebPolicyError(WebErrorCode.CANCELLED)
                if process.returncode != 0:
                    raise WebPolicyError(WebErrorCode.DNS_FAILED)
                output.seek(0)
                data = output.read(4097)
                if len(data) > 4096:
                    raise WebPolicyError(WebErrorCode.DNS_DENIED)
                try:
                    addresses = json.loads(data)
                    if (
                        not isinstance(addresses, list)
                        or not 1
                        <= len(addresses)
                        <= preflight.execution_limits.max_dns_addresses
                    ):
                        raise ValueError
                    return ResolvedWebTarget(
                        preflight.hostname, tuple(addresses), datetime.now(UTC)
                    )
                except (ValueError, TypeError):
                    raise WebPolicyError(WebErrorCode.DNS_DENIED) from None
            finally:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=1)
