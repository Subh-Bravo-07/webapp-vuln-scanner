import subprocess
from shutil import which


def run_tool_version(tool_name: str, timeout_sec: int = 8) -> dict[str, str]:
    executable = which(tool_name)
    if not executable:
        return {"tool": tool_name, "status": "not_installed", "output": ""}
    try:
        result = subprocess.run(  # noqa: S603
            [executable, "--version"],
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            check=False,
        )
        output = (result.stdout or result.stderr).strip()
        return {"tool": tool_name, "status": "available", "output": output[:500]}
    except Exception as exc:  # noqa: BLE001
        return {"tool": tool_name, "status": "error", "output": str(exc)}


def run_nuclei_scan(target_url: str, timeout_sec: int = 45) -> dict[str, str]:
    executable = which("nuclei")
    if not executable:
        return {"tool": "nuclei", "status": "not_installed", "output": ""}
    try:
        result = subprocess.run(  # noqa: S603
            [executable, "-u", target_url, "-silent", "-jsonl"],
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            check=False,
        )
        output = (result.stdout or result.stderr).strip()
        return {"tool": "nuclei", "status": "executed", "output": output[:4000]}
    except Exception as exc:  # noqa: BLE001
        return {"tool": "nuclei", "status": "error", "output": str(exc)}


def run_nikto_scan(target_url: str, timeout_sec: int = 90) -> dict[str, str]:
    executable = which("nikto")
    if not executable:
        return {"tool": "nikto", "status": "not_installed", "output": ""}
    try:
        result = subprocess.run(  # noqa: S603
            [executable, "-h", target_url, "-maxtime", "1m"],
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            check=False,
        )
        output = (result.stdout or result.stderr).strip()
        return {"tool": "nikto", "status": "executed", "output": output[:4000]}
    except Exception as exc:  # noqa: BLE001
        return {"tool": "nikto", "status": "error", "output": str(exc)}


def run_sqlmap_scan(target_url: str, timeout_sec: int = 90) -> dict[str, str]:
    executable = which("sqlmap")
    if not executable:
        return {"tool": "sqlmap", "status": "not_installed", "output": ""}
    try:
        result = subprocess.run(  # noqa: S603
            [
                executable,
                "-u",
                target_url,
                "--batch",
                "--level",
                "1",
                "--risk",
                "1",
                "--output-dir",
                ".",
            ],
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            check=False,
        )
        output = (result.stdout or result.stderr).strip()
        return {"tool": "sqlmap", "status": "executed", "output": output[:4000]}
    except Exception as exc:  # noqa: BLE001
        return {"tool": "sqlmap", "status": "error", "output": str(exc)}
