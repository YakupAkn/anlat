import argparse
import sys
import webbrowser
from pathlib import Path

from . import report, sandbox, static, translate


def main():
    p = argparse.ArgumentParser(prog="anlat", description="Explains what a suspicious file does.")
    p.add_argument("file")
    p.add_argument("--lang", choices=["en", "tr"], default="en")
    p.add_argument("--timeout", type=int, default=30)
    p.add_argument("--ram", type=int, default=16, help="fake RAM shown to the program (GB)")
    p.add_argument("--no-spoof", action="store_true")
    p.add_argument("--out", default="anlat-report.html")
    p.add_argument("--no-open", action="store_true")
    a = p.parse_args()

    path = Path(a.file)
    if not path.is_file():
        sys.exit("File not found.")
    info = static.inspect(path)

    if info["kind"] in ("pe", "zip", "unknown"):
        print(f"[!] {info['kind']} files cannot run in the Linux sandbox yet (planned for v0.3). "
              "Static report only.")
        trace, markers = "", {}
    elif not sandbox.docker_ok():
        sys.exit("Docker is not running. Install Docker and try again.")
    else:
        sandbox.ensure_image()
        print("Running in sandbox...")
        trace, markers = sandbox.run(path, a.timeout, a.ram, not a.no_spoof)

    score, findings, stolen = translate.analyze(trace, markers, a.lang)
    label = translate.risk_label(score, a.lang)
    Path(a.out).write_text(report.render(info, score, label, findings, stolen, a.lang), encoding="utf-8")
    print(f"{label} ({score}/100) -> {a.out}")
    if not a.no_open:
        webbrowser.open(Path(a.out).resolve().as_uri())


if __name__ == "__main__":
    main()
