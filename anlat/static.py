"""Static inspection: looks at the file without running it."""
import hashlib
import re
from pathlib import Path

URL_RE = re.compile(rb"https?://[\x21-\x7e]{4,200}")
IP_RE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SUSPICIOUS = [
    b"powershell", b"cmd.exe", b"/bin/sh", b"wget ", b"curl ", b"chmod +x",
    b"crontab", b"LD_PRELOAD", b"ptrace", b"Login Data", b"wallet", b"discord",
    b"keylog", b"base64 -d",
]


def kind_of(head: bytes) -> str:
    if head.startswith(b"\x7fELF"):
        return "elf"
    if head.startswith(b"MZ"):
        return "pe"
    if head.startswith(b"#!"):
        return "script"
    if head.startswith(b"PK"):
        return "zip"
    return "unknown"


def inspect(path: Path) -> dict:
    data = path.read_bytes()
    urls = sorted({u.decode(errors="ignore") for u in URL_RE.findall(data)})[:20]
    ips = sorted({i.decode() for i in IP_RE.findall(data)
                  if all(int(p) <= 255 for p in i.decode().split("."))})[:20]
    hits = sorted({s.decode() for s in SUSPICIOUS if s.lower() in data.lower()})
    return {
        "name": path.name,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "kind": kind_of(data[:4]),
        "urls": urls,
        "ips": ips,
        "keywords": hits,
    }
