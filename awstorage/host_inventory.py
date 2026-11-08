"""host_inventory.py -- the ``hardware``, ``software`` and ``services`` inventory kinds.

Each collector answers one small JSON document about THIS host and rides the same
signed transport as ``kind=files`` (``inventory.publish --kind hardware`` ...). Stdlib
only: ``psutil`` is used when it happens to be installed, never required.

Two rules every collector obeys:

* **Degrade, never raise.** A missing tool (no ``nvidia-smi``, no ``dpkg-query``, no
  ``systemctl``), a non-zero exit, a timeout or a parser surprise becomes one row of
  ``unavailable`` (``{"source", "reason"}``) and the rest of the document still ships.
* **No secrets.** No environment variables, no command lines, no unit descriptions, no
  container images or arguments are ever read into the document; every string that is
  kept is passed through :func:`scrub`, which blanks anything shaped like
  ``NAME=value`` / ``TOKEN: value`` or a well-known credential prefix.
"""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable

KIND_NAMES = ("hardware", "software", "services")
SCHEMA_VERSION = 1
_MAX_STR = 200
REDACTED = "[redacted]"

#: ``KEY=value`` / ``KEY: value`` where KEY looks like a credential name, or any
#: ``UPPER_CASE=value`` assignment (an environment line), or a well-known token prefix.
_SECRETISH = re.compile(
    r"(?i)(token|secret|passw(or)?d|api[_-]?key|private[_-]?key|credential|bearer|auth)"
    r"[A-Za-z0-9_]*\s*[=:]"
    r"|\b[A-Z][A-Z0-9_]{2,}=\S"
    r"|\b(sk-|ghp_|ghs_|gho_|github_pat_|AKIA|xox[bp]-|pk_live_|sk_live_)")


def scrub(value: Any) -> Any:
    """Recursively blank secret-shaped strings and clip long ones."""
    if isinstance(value, str):
        if _SECRETISH.search(value):
            return REDACTED
        return value[:_MAX_STR]
    if isinstance(value, dict):
        return {str(k): scrub(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [scrub(v) for v in value]
    return value


class Ctx:
    """Where a collector gets the outside world from -- tests substitute every part."""

    def __init__(self, *, run: Callable[..., Any] | None = None,
                 which: Callable[[str], str | None] | None = None,
                 winreg: Any = None, system: str | None = None,
                 psutil: Any = None, read_text: Callable[[str], str] | None = None) -> None:
        self._run = run or subprocess.run
        self.which = which or shutil.which
        self.winreg = winreg
        self.system = system or platform.system()
        self.psutil = psutil
        self._read_text = read_text
        self.unavailable: list[dict] = []

    def missing(self, source: str, reason: str) -> None:
        self.unavailable.append({"source": source, "reason": str(reason)[:_MAX_STR]})

    def tool(self, argv: list[str], source: str, timeout: int = 30) -> str | None:
        """stdout of ``argv``, or None (and an ``unavailable`` row) on any failure."""
        if not self.which(argv[0]):
            self.missing(source, f"{argv[0]} not found")
            return None
        # files sync runs under pythonw on Windows: a console child would flash a window.
        nowin = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        kw = {"creationflags": nowin} if os.name == "nt" else {}
        try:
            proc = self._run(argv, capture_output=True, text=True, encoding="utf-8",
                             errors="replace", timeout=timeout, check=False, **kw)
        except (OSError, subprocess.SubprocessError, ValueError) as exc:
            self.missing(source, f"{argv[0]}: {type(exc).__name__}: {exc}")
            return None
        if proc.returncode != 0:
            err = (proc.stderr or "").strip().splitlines()
            self.missing(source, f"{argv[0]} exit {proc.returncode}"
                         + (f": {err[-1]}" if err else ""))
            return None
        return proc.stdout or ""

    def read(self, path: str) -> str | None:
        try:
            if self._read_text is not None:
                return self._read_text(path)
            return Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None


def _guarded(ctx: Ctx, source: str, fn: Callable[[], Any], default: Any) -> Any:
    """A collector section that raises is a recorded gap, never a failed publish."""
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001 - every section degrades independently
        ctx.missing(source, f"{type(exc).__name__}: {exc}")
        return default


def _psutil() -> Any:
    try:
        import psutil  # type: ignore[import-not-found]  # noqa: PLC0415
    except ImportError:
        return None
    return psutil


def _winreg() -> Any:
    try:
        import winreg  # type: ignore[import-not-found]  # noqa: PLC0415
    except ImportError:
        return None
    return winreg


def default_ctx() -> Ctx:
    return Ctx(winreg=_winreg(), psutil=_psutil())


# ---------------------------------------------------------------------------
# parsers -- pure functions over tool output (the tests feed fixtures here)
# ---------------------------------------------------------------------------

def parse_nvidia_smi(text: str) -> list[dict]:
    """``nvidia-smi --query-gpu=name,memory.total,driver_version
    --format=csv,noheader,nounits`` -> [{name, vram_mb, driver}]."""
    gpus = []
    for line in text.splitlines():
        cells = [c.strip() for c in line.split(",")]
        if not cells or not cells[0]:
            continue
        try:
            vram = int(float(cells[1])) if len(cells) > 1 and cells[1] else None
        except ValueError:
            vram = None
        gpus.append({"name": cells[0], "vram_mb": vram,
                     "driver": cells[2] if len(cells) > 2 else None})
    return gpus


def parse_dpkg_query(text: str) -> list[dict]:
    r"""``dpkg-query -W -f='${Package}\t${Version}\t${db:Status-Abbrev}\n'`` -> the
    installed (``ii``) packages."""
    out = []
    for line in text.splitlines():
        cells = line.split("\t")
        if len(cells) < 2 or not cells[0].strip():
            continue
        status = cells[2].strip() if len(cells) > 2 else "ii"
        if status and not status.startswith("ii"):
            continue
        out.append({"source": "dpkg", "name": cells[0].strip(), "version": cells[1].strip()})
    return out


def parse_rpm(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        cells = line.split("\t")
        if len(cells) >= 2 and cells[0].strip():
            out.append({"source": "rpm", "name": cells[0].strip(), "version": cells[1].strip()})
    return out


def parse_system_profiler_apps(text: str) -> list[dict]:
    data = json.loads(text or "{}")
    out = []
    for app in data.get("SPApplicationsDataType") or []:
        name = app.get("_name")
        if name:
            out.append({"source": "macos-app", "name": name,
                        "version": app.get("version") or ""})
    return out


def parse_systemctl(text: str) -> list[dict]:
    """``systemctl list-units --type=service --all --no-legend --no-pager --plain`` ->
    [{name, load, active, sub}]. The DESCRIPTION column is dropped on purpose."""
    out = []
    for line in text.splitlines():
        cells = line.split()
        if len(cells) < 4 or not cells[0].endswith(".service"):
            continue
        out.append({"source": "systemd", "name": cells[0], "load": cells[1],
                    "state": cells[2], "sub": cells[3]})
    return out


def parse_sc_query(text: str) -> list[dict]:
    """``sc query type= service state= all`` -> [{name, state}] (name + state only)."""
    out: list[dict] = []
    cur: dict | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if line.upper().startswith("SERVICE_NAME:"):
            cur = {"source": "windows", "name": line.split(":", 1)[1].strip(), "state": ""}
            out.append(cur)
        elif cur is not None and line.upper().startswith("STATE") and ":" in line:
            parts = line.split(":", 1)[1].split()
            cur["state"] = parts[-1].lower() if parts else ""
    return out


def parse_container_ps(text: str, engine: str) -> list[dict]:
    """``<engine> ps -a --format '{{.Names}}\\t{{.State}}'`` -> [{name, state}]."""
    out = []
    for line in text.splitlines():
        cells = line.split("\t")
        if cells and cells[0].strip():
            out.append({"source": engine, "name": cells[0].strip(),
                        "state": cells[1].strip() if len(cells) > 1 else ""})
    return out


def read_uninstall_keys(winreg: Any) -> list[dict]:
    """Installed programs from the three Uninstall hives: DisplayName / DisplayVersion /
    Publisher only (UninstallString and friends are command lines -- never read)."""
    hives = (
        ("HKEY_LOCAL_MACHINE", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        ("HKEY_LOCAL_MACHINE",
         r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        ("HKEY_CURRENT_USER", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    )
    seen: set[tuple[str, str]] = set()
    out = []
    for hive_name, path in hives:
        try:
            root = winreg.OpenKey(getattr(winreg, hive_name), path)
        except OSError:
            continue
        try:
            i = 0
            while True:
                try:
                    sub = winreg.EnumKey(root, i)
                except OSError:
                    break
                i += 1
                try:
                    k = winreg.OpenKey(root, sub)
                except OSError:
                    continue
                try:
                    vals = {}
                    for fld in ("DisplayName", "DisplayVersion", "Publisher"):
                        try:
                            vals[fld] = str(winreg.QueryValueEx(k, fld)[0] or "").strip()
                        except OSError:
                            vals[fld] = ""
                finally:
                    winreg.CloseKey(k)
                name = vals["DisplayName"]
                if not name or (name, vals["DisplayVersion"]) in seen:
                    continue
                seen.add((name, vals["DisplayVersion"]))
                out.append({"source": "windows", "name": name,
                            "version": vals["DisplayVersion"],
                            "publisher": vals["Publisher"]})
        finally:
            winreg.CloseKey(root)
    return out


# ---------------------------------------------------------------------------
# hardware
# ---------------------------------------------------------------------------

def _cpu(ctx: Ctx) -> dict:
    model = ""
    if ctx.system == "Windows" and ctx.winreg is not None:
        try:
            k = ctx.winreg.OpenKey(ctx.winreg.HKEY_LOCAL_MACHINE,
                                   r"HARDWARE\DESCRIPTION\System\CentralProcessor\0")
            try:
                model = str(ctx.winreg.QueryValueEx(k, "ProcessorNameString")[0]).strip()
            finally:
                ctx.winreg.CloseKey(k)
        except OSError:
            model = ""
    elif ctx.system == "Linux":
        for line in (ctx.read("/proc/cpuinfo") or "").splitlines():
            if line.lower().startswith(("model name", "hardware")) and ":" in line:
                model = line.split(":", 1)[1].strip()
                break
    elif ctx.system == "Darwin":
        model = (ctx.tool(["sysctl", "-n", "machdep.cpu.brand_string"], "cpu") or "").strip()
    physical = None
    if ctx.psutil is not None:
        try:
            physical = ctx.psutil.cpu_count(logical=False)
        except Exception:  # noqa: BLE001 - optional detail
            physical = None
    return {"model": model or platform.processor() or "", "logical_cores": os.cpu_count(),
            "physical_cores": physical, "arch": platform.machine()}


def _ram_bytes(ctx: Ctx) -> int | None:
    if ctx.psutil is not None:
        return int(ctx.psutil.virtual_memory().total)
    if ctx.system == "Linux":
        for line in (ctx.read("/proc/meminfo") or "").splitlines():
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) * 1024
    if ctx.system == "Windows":
        import ctypes  # noqa: PLC0415

        class _MS(ctypes.Structure):
            _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                        ("ullTotalPhys", ctypes.c_ulonglong),
                        ("ullAvailPhys", ctypes.c_ulonglong),
                        ("ullTotalPageFile", ctypes.c_ulonglong),
                        ("ullAvailPageFile", ctypes.c_ulonglong),
                        ("ullTotalVirtual", ctypes.c_ulonglong),
                        ("ullAvailVirtual", ctypes.c_ulonglong),
                        ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
        ms = _MS()
        ms.dwLength = ctypes.sizeof(_MS)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(ms)):  # type: ignore[attr-defined]
            return int(ms.ullTotalPhys)
    if ctx.system == "Darwin":
        got = ctx.tool(["sysctl", "-n", "hw.memsize"], "ram")
        return int(got.strip()) if got and got.strip().isdigit() else None
    ctx.missing("ram", f"no RAM probe for {ctx.system} without psutil")
    return None


_PSEUDO_FS = {"proc", "sysfs", "devtmpfs", "devpts", "tmpfs", "cgroup", "cgroup2", "overlay",
              "squashfs", "securityfs", "pstore", "debugfs", "tracefs", "mqueue", "hugetlbfs",
              "fusectl", "configfs", "bpf", "autofs", "binfmt_misc", "nsfs", "ramfs", "rpc_pipefs",
              "efivarfs", "fuse.portal"}


def _disks(ctx: Ctx) -> list[dict]:
    mounts: list[tuple[str, str, str]] = []          # (device, mountpoint, fstype)
    if ctx.psutil is not None:
        for p in ctx.psutil.disk_partitions(all=False):
            mounts.append((p.device, p.mountpoint, p.fstype))
    elif ctx.system == "Linux":
        for line in (ctx.read("/proc/mounts") or "").splitlines():
            cells = line.split()
            if len(cells) >= 3 and cells[2] not in _PSEUDO_FS:
                mounts.append((cells[0], cells[1].replace("\\040", " "), cells[2]))
    elif ctx.system == "Windows":
        for letter in "CDEFGHIJKLMNOPQRSTUVWXYZ":
            root = f"{letter}:\\"
            if os.path.exists(root):
                mounts.append((f"{letter}:", root, _win_fs(root)))
    else:
        mounts.append(("/", "/", ""))
    out, seen = [], set()
    for dev, mnt, fs in mounts:
        if mnt in seen:
            continue
        seen.add(mnt)
        try:
            u = shutil.disk_usage(mnt)
        except OSError as exc:
            ctx.missing(f"disk:{mnt}", f"{type(exc).__name__}: {exc}")
            continue
        out.append({"device": dev, "mount": mnt, "fs": fs, "total_bytes": int(u.total),
                    "free_bytes": int(u.free)})
    return out


def _win_fs(root: str) -> str:
    try:
        import ctypes  # noqa: PLC0415
        buf = ctypes.create_unicode_buffer(64)
        ok = ctypes.windll.kernel32.GetVolumeInformationW(  # type: ignore[attr-defined]
            ctypes.c_wchar_p(root), None, 0, None, None, None, buf, 64)
        return buf.value if ok else ""
    except Exception:  # noqa: BLE001 - the fs name is a nicety
        return ""


def collect_hardware(ctx: Ctx | None = None) -> dict:
    ctx = ctx or default_ctx()
    gpus: list[dict] = []
    smi = ctx.tool(["nvidia-smi", "--query-gpu=name,memory.total,driver_version",
                    "--format=csv,noheader,nounits"], "gpu:nvidia-smi")
    if smi is not None:
        gpus = _guarded(ctx, "gpu:nvidia-smi", lambda: parse_nvidia_smi(smi), [])
    doc = {
        "hostname": _guarded(ctx, "hostname", socket.gethostname, ""),
        "os": {"system": platform.system(), "release": platform.release(),
               "version": platform.version(), "machine": platform.machine(),
               "platform": platform.platform()},
        "cpu": _guarded(ctx, "cpu", lambda: _cpu(ctx), {}),
        "ram_bytes": _guarded(ctx, "ram", lambda: _ram_bytes(ctx), None),
        "gpus": gpus,
        "disks": _guarded(ctx, "disks", lambda: _disks(ctx), []),
    }
    doc["rows"] = 1 + len(doc["gpus"]) + len(doc["disks"])
    return doc


# ---------------------------------------------------------------------------
# software
# ---------------------------------------------------------------------------

def _pip_packages() -> list[dict]:
    from importlib import metadata  # noqa: PLC0415
    seen, out = set(), []
    for d in metadata.distributions():
        name = (d.metadata["Name"] or "").strip() if d.metadata else ""
        if name and name.lower() not in seen:
            seen.add(name.lower())
            out.append({"source": "pip", "name": name, "version": d.version or ""})
    return sorted(out, key=lambda r: r["name"].lower())


def collect_software(ctx: Ctx | None = None) -> dict:
    ctx = ctx or default_ctx()
    pkgs: list[dict] = []
    if ctx.system == "Windows":
        if ctx.winreg is None:
            ctx.missing("windows-uninstall", "winreg not importable")
        else:
            pkgs += _guarded(ctx, "windows-uninstall",
                             lambda: read_uninstall_keys(ctx.winreg), [])
    elif ctx.system == "Linux":
        txt = ctx.tool(["dpkg-query", "-W",
                        "-f=${Package}\t${Version}\t${db:Status-Abbrev}\n"], "dpkg", 120)
        if txt is not None:
            pkgs += _guarded(ctx, "dpkg", lambda: parse_dpkg_query(txt), [])
        elif ctx.which("rpm"):
            rtxt = ctx.tool(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"],
                            "rpm", 120)
            if rtxt is not None:
                pkgs += _guarded(ctx, "rpm", lambda: parse_rpm(rtxt), [])
    elif ctx.system == "Darwin":
        jtxt = ctx.tool(["system_profiler", "SPApplicationsDataType", "-json"],
                        "macos-apps", 120)
        if jtxt is not None:
            pkgs += _guarded(ctx, "macos-apps", lambda: parse_system_profiler_apps(jtxt), [])
    else:
        ctx.missing("os-packages", f"no package source for {ctx.system}")
    pip = _guarded(ctx, "pip", _pip_packages, [])
    return {"python": {"version": platform.python_version(), "implementation":
                       platform.python_implementation(),
                       "executable_name": Path(sys.executable).name},
            "packages": pkgs, "pip": pip, "rows": len(pkgs) + len(pip)}


# ---------------------------------------------------------------------------
# services
# ---------------------------------------------------------------------------

def _windows_services(ctx: Ctx) -> list[dict]:
    if ctx.psutil is not None and hasattr(ctx.psutil, "win_service_iter"):
        out = []
        for s in ctx.psutil.win_service_iter():
            try:
                out.append({"source": "windows", "name": s.name(), "state": s.status()})
            except Exception:  # noqa: BLE001 - a vanished service is not a gap
                continue
        return out
    txt = ctx.tool(["sc", "query", "type=", "service", "state=", "all"], "windows-services")
    return parse_sc_query(txt) if txt is not None else []


def collect_services(ctx: Ctx | None = None) -> dict:
    ctx = ctx or default_ctx()
    svcs: list[dict] = []
    if ctx.system == "Windows":
        svcs += _guarded(ctx, "windows-services", lambda: _windows_services(ctx), [])
    elif ctx.which("systemctl"):
        txt = ctx.tool(["systemctl", "list-units", "--type=service", "--all", "--no-legend",
                        "--no-pager", "--plain"], "systemd")
        if txt is not None:
            svcs += _guarded(ctx, "systemd", lambda: parse_systemctl(txt), [])
    else:
        ctx.missing("systemd", "systemctl not found")
    containers: list[dict] = []
    for engine in ("podman", "docker"):
        txt = ctx.tool([engine, "ps", "-a", "--format", "{{.Names}}\t{{.State}}"],
                       engine, 20)
        if txt is not None:
            containers += _guarded(ctx, engine, lambda t=txt, e=engine:
                                   parse_container_ps(t, e), [])
    return {"services": svcs, "containers": containers,
            "rows": len(svcs) + len(containers)}


COLLECTORS: dict[str, Callable[[Ctx | None], dict]] = {
    "hardware": collect_hardware, "software": collect_software, "services": collect_services,
}


def collect(kind: str, ctx: Ctx | None = None) -> dict:
    """The whole scrubbed document for ``kind``. Never raises for a host problem."""
    ctx = ctx or default_ctx()
    body = _guarded(ctx, kind, lambda: COLLECTORS[kind](ctx), {"rows": 0})
    rows = int(body.pop("rows", 0) or 0)
    doc = {"format": "awstorage-host-inventory/1", "kind": kind,
           "collected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           **body, "unavailable": ctx.unavailable}
    doc = scrub(doc)
    doc["rows"] = rows
    return doc


# ---------------------------------------------------------------------------
# the inventory Kind glue
# ---------------------------------------------------------------------------

def make_export(kind: str, ctx_factory: Callable[[], Ctx] | None = None
                ) -> Callable[[Path, str, Path], dict]:
    def export(src: Path, node: str, out: Path) -> dict:  # noqa: ARG001 - src is files-only
        doc = collect(kind, (ctx_factory or default_ctx)())
        doc["node"] = node
        Path(out).write_text(json.dumps(doc, indent=1, sort_keys=True), encoding="utf-8")
        return {"rows": doc["rows"], "scanned_at": doc["collected_at"],
                "unavailable": len(doc["unavailable"])}
    return export


def kind_cache_dir(cache_dir: Path, kind: str) -> Path:
    return Path(cache_dir) / "kinds" / kind


def make_merge(kind: str) -> Callable[[Path, str, Path], None]:
    def merge(artifact: Path, node: str, cache_dir: Path) -> None:
        doc = json.loads(Path(artifact).read_text(encoding="utf-8"))
        if doc.get("kind") != kind:
            raise ValueError(f"artifact is kind {doc.get('kind')!r}, not {kind!r}")
        d = kind_cache_dir(cache_dir, kind)
        d.mkdir(parents=True, exist_ok=True)
        tmp = d / f".{node}.json.tmp"
        tmp.write_text(json.dumps(doc, indent=1, sort_keys=True), encoding="utf-8")
        os.replace(tmp, d / f"{node}.json")
    return merge


def cached_doc(cache_dir: Path, kind: str, node: str) -> dict | None:
    try:
        return json.loads((kind_cache_dir(cache_dir, kind) / f"{node}.json")
                          .read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _gib(n: Any) -> str:
    return f"{n / (1 << 30):.1f} GiB" if isinstance(n, (int, float)) else "?"


def render(doc: dict) -> str:
    """A short human view of one cached document."""
    kind = doc.get("kind")
    lines = [f"{doc.get('node')} {kind} (collected {doc.get('collected_at')},"
             f" {doc.get('rows')} rows)"]
    if kind == "hardware":
        cpu, os_ = doc.get("cpu") or {}, doc.get("os") or {}
        lines.append(f"  host   {doc.get('hostname')}  {os_.get('system')} {os_.get('release')}"
                     f" ({os_.get('machine')})")
        lines.append(f"  cpu    {cpu.get('model')}  {cpu.get('physical_cores')}p/"
                     f"{cpu.get('logical_cores')}l cores")
        lines.append(f"  ram    {_gib(doc.get('ram_bytes'))}")
        for g in doc.get("gpus") or []:
            lines.append(f"  gpu    {g.get('name')}  {g.get('vram_mb')} MiB")
        for d in doc.get("disks") or []:
            lines.append(f"  disk   {d.get('mount'):<12} {d.get('fs') or '?':<6}"
                         f" {_gib(d.get('total_bytes'))} total, {_gib(d.get('free_bytes'))} free")
    elif kind == "software":
        pk, pip = doc.get("packages") or [], doc.get("pip") or []
        lines.append(f"  os packages {len(pk)}, pip packages {len(pip)}"
                     f" (python {(doc.get('python') or {}).get('version')})")
        for p in pk[:15]:
            lines.append(f"  {p.get('source'):<8} {p.get('name')} {p.get('version')}")
        if len(pk) > 15:
            lines.append(f"  ... {len(pk) - 15} more (--json for all)")
    elif kind == "services":
        sv, ct = doc.get("services") or [], doc.get("containers") or []
        running = sum(1 for s in sv if str(s.get("state")).lower() in ("active", "running"))
        lines.append(f"  services {len(sv)} ({running} running), containers {len(ct)}")
        for c in ct[:20]:
            lines.append(f"  {c.get('source'):<8} {c.get('name')}  {c.get('state')}")
    for u in doc.get("unavailable") or []:
        lines.append(f"  unavailable: {u.get('source')} -- {u.get('reason')}")
    return "\n".join(lines)
