"""The session headers reach sqlmap.

A scan can name an identity: the task carries the identity's cookies and
headers, and the worker has to hand them to sqlmap, because a target
that needs a session answers an anonymous request with a login page.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import sqlmapm.sqlmapm as sqlmapm_module  # noqa: E402
from sqlmapm.sqlmapm import sqlmapm  # noqa: E402


class _Task:
    """A task that carries nothing but a payload."""

    def __init__(self, payload: Any) -> None:
        self.payload = payload


class _Worker(sqlmapm):
    """A worker without a configuration file and without a database."""

    def __init__(self) -> None:
        pass


class _Process:
    """The process sqlmap's output would come from."""

    def communicate(self, *args: Any, **kwargs: Any) -> tuple[bytes, None]:
        return b"", None


class _Subprocess:
    """A subprocess module that records the commands instead of running them."""

    PIPE = subprocess.PIPE

    def __init__(self) -> None:
        self.commands: list[list[str]] = []

    def Popen(self, argv: list[str], **kwargs: Any) -> _Process:
        self.commands.append(argv)
        return _Process()


def _worker(monkeypatch: Any) -> tuple[_Worker, _Subprocess]:
    worker = _Worker()
    subprocess = _Subprocess()
    monkeypatch.setattr(sqlmapm_module, "subprocess", subprocess)
    return worker, subprocess


def test_the_session_headers_reach_sqlmap(monkeypatch: Any) -> None:
    worker, subprocess = _worker(monkeypatch)
    task = _Task(payload={"auth": {"cookies": {"JSESSIONID": "abc"}, "headers": {"X-Test": "1"}}})

    sqlmapm_module.runsqlmap("http://example.test/?id=1", worker.auth_headers(task))

    assert "--headers" in subprocess.commands[0]
    value = subprocess.commands[0][subprocess.commands[0].index("--headers") + 1]
    assert "Cookie: JSESSIONID=abc" in value
    assert "X-Test: 1" in value


def test_sqlmap_gets_no_header_without_an_identity(monkeypatch: Any) -> None:
    worker, subprocess = _worker(monkeypatch)
    task = _Task(payload={})

    sqlmapm_module.runsqlmap("http://example.test/?id=1", worker.auth_headers(task))

    assert "--headers" not in subprocess.commands[0]


def test_the_session_headers_reach_the_subdomain_scan(monkeypatch: Any) -> None:
    worker, subprocess = _worker(monkeypatch)
    task = _Task(payload={"auth": {"headers": {"X-Test": "1"}}})

    sqlmapm_module.runsqlmapsubdomain("http://example.test/?id=1", worker.auth_headers(task))

    assert "--headers" in subprocess.commands[0]
    value = subprocess.commands[0][subprocess.commands[0].index("--headers") + 1]
    assert "X-Test: 1" in value
