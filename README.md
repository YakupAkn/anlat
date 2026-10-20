# Anlat

Explains in plain language what a suspicious file does.

Run a file in a locked-down sandbox full of **fake** passwords, cookies, tokens and wallet files.
Anlat then tells you what the file touched and what would have been stolen on a real PC.

```
anlat suspicious_file --lang en
```

## How it works
1. **Static look:** hash, file type, URLs, suspicious words.
2. **Sandbox:** the file runs in a Docker container with no network, a fake user profile (honeytokens) and a fake 16 GB RAM.
3. **Translator:** raw system calls become sentences. Each fake secret has a unique marker, so "read" and "tried to send out" are told apart.
4. **Report:** one HTML page.

## Install
```
pip install -e .
docker --version
```

## Status (v0.2)
- Linux binaries and scripts with a `#!` line run in the sandbox.
- Windows `.exe`, zip and unknown files get a static report only (VM support planned for v0.3).
- Downloader/installer chain analysis is planned.

## Limits (read this)
- Docker is **not** a perfect wall. For real malware, run Anlat inside a throwaway VM.
- A clever program can detect sandboxes and stay quiet. A clean report is not a guarantee.
- Fake RAM works through a mounted `/proc/meminfo`. Use `--no-spoof` if your Docker rejects it.
- Only analyze files you are allowed to analyze.

MIT License.
