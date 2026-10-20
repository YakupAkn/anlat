"""Runs the file in a locked-down Docker container and returns the trace."""
import shutil
import subprocess
import tempfile
from pathlib import Path

from . import honey

IMAGE = "anlat-sandbox:0.2"
SANDBOX_DIR = Path(__file__).resolve().parent.parent / "sandbox"


def docker_ok() -> bool:
    return shutil.which("docker") is not None and \
        subprocess.run(["docker", "info"], capture_output=True).returncode == 0


def ensure_image():
    if subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True).returncode != 0:
        subprocess.run(["docker", "build", "-t", IMAGE, str(SANDBOX_DIR)], check=True)


def run(sample: Path, timeout: int = 30, ram_gb: int = 16, spoof: bool = True):
    """Returns (trace_text, markers)."""
    work = Path(tempfile.mkdtemp(prefix="anlat-"))
    home, out = work / "home", work / "out"
    home.mkdir()
    out.mkdir()
    markers = honey.build(home)
    # container user "user" must be able to write in its fake home
    subprocess.run(["chmod", "-R", "a+rwX", str(home), str(out)])
    cmd = [
        "docker", "run", "--rm",
        "--network", "none",
        "--cap-drop", "ALL", "--cap-add", "SYS_PTRACE",
        "--security-opt", "no-new-privileges",
        "--pids-limit", "128", "--memory", "512m", "--cpus", "2",
        "--read-only", "--tmpfs", "/tmp:exec,size=64m",
        "-e", f"ANLAT_TIMEOUT={timeout}",
        "-v", f"{sample.resolve()}:/sample/target:ro",
        "-v", f"{home}:/home/user",
        "-v", f"{out}:/out",
    ]
    if spoof:
        mi = work / "meminfo"
        mi.write_text(honey.meminfo(ram_gb))
        cmd += ["-v", f"{mi}:/proc/meminfo:ro"]
    cmd += ["--user", "user", IMAGE]
    subprocess.run(cmd, timeout=timeout + 30)
    trace = (out / "trace.log").read_text(errors="ignore") if (out / "trace.log").exists() else ""
    shutil.rmtree(work, ignore_errors=True)
    return trace, markers
