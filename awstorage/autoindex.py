"""autoindex.py -- keep an enrolled device's file index current with no per-device setup.

Two verbs, both stdlib-only:

* ``awstorage files schedule`` -- run once, at enrolment (``adk pair`` / ``adk enroll``
  call it). Picks an index directory (off the system drive when that drive is low),
  writes ``~/.aither/awstorage-autoindex.json`` and registers ONE recurring job that
  runs ``files sync``: an awrise wake where ``awrise`` is installed, else the platform's
  own scheduler (Windows Task Scheduler, a systemd user timer, launchd, cron).
* ``awstorage files sync`` -- one pass: ``files scan --all-volumes`` then ``files push``,
  as the node id the device REGISTERED with (``identity.whoami``), and a receipt
  ``last_run.json`` written on EVERY path. A failed scan or push exits non-zero with the
  failing step and its stderr tail in the receipt: never a silent success. awrise records
  the verdict; the platform sees the node go stale in ``storage_files_nodes``.

The index can be GBs (millions of rows), and SQLite spills sort journals to the OS temp
dir -- a 7.3 GB journal once filled C: -- so a pass points TMP/TEMP/SQLITE_TMPDIR at
``<index_dir>/tmp``, beside the index, exactly like ``dev/tools/storage_index_node.sh``.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable

JOB_NAME = "aither-file-index"
WIN_TASK = "AitherFileIndex"
DEFAULT_EVERY_HOURS = 6
DEFAULT_BUDGET_S = 5400
#: A system drive with less free space than this does not get the index.
LOW_SYSTEM_FREE_BYTES = 30 * 1024 ** 3
#: An alternative volume must have at least this much free to be worth moving to.
MIN_ALT_FREE_BYTES = 50 * 1024 ** 3
#: The host inventory kinds a pass publishes on a SLOWER cadence than files: at most
#: once per KINDS_EVERY_S each (``$AWSTORAGE_INVENTORY_KINDS_EVERY_S``), tracked in
#: ``<index_dir>/inventory_kinds.json`` -- a failed kind publish is retried next pass.
HOST_KINDS = ("hardware", "software", "services")
KINDS_EVERY_ENV = "AWSTORAGE_INVENTORY_KINDS_EVERY_S"
DEFAULT_KINDS_EVERY_S = 24 * 3600
KINDS_STATE = "inventory_kinds.json"


def config_path() -> Path:
    return Path.home() / ".aither" / "awstorage-autoindex.json"


def default_index_dir() -> Path:
    return Path.home() / ".aither" / "awstorage"


def _home_mount() -> str:
    home = Path.home().resolve()
    return home.anchor or "/"


def pick_index_dir(volumes: list[dict] | None = None, *,
                   free_of: Callable[[str], int] | None = None) -> tuple[Path, str]:
    """(index_dir, why). The home drive unless it is low on space and another LOCAL
    fixed volume has real room; then ``<that volume>/AitherOS-Data/awstorage``."""
    from .identity import list_volumes  # noqa: PLC0415

    def _free(mount: str) -> int:
        try:
            return int(shutil.disk_usage(mount).free)
        except OSError:
            return 0

    free_of = free_of or _free
    home_mount = _home_mount()
    home_free = free_of(home_mount)
    if home_free >= LOW_SYSTEM_FREE_BYTES:
        return default_index_dir(), f"home drive {home_mount} has {home_free >> 30} GiB free"
    vols = volumes if volumes is not None else list_volumes()
    best = None
    for v in vols:
        mount = str(v.get("mount") or "")
        if not mount or v.get("kind", "fixed") != "fixed" or mount.rstrip("/\\").lower() == \
                home_mount.rstrip("/\\").lower():
            continue
        free = int(v.get("free_bytes") or 0)
        if free >= MIN_ALT_FREE_BYTES and (best is None or free > best[1]):
            best = (mount, free)
    if best is None:
        return default_index_dir(), (f"home drive {home_mount} is low ({home_free >> 30} GiB"
                                     " free) and no other local volume has room; kept it")
    return (Path(best[0]) / "AitherOS-Data" / "awstorage",
            f"home drive {home_mount} is low ({home_free >> 30} GiB free); "
            f"{best[0]} has {best[1] >> 30} GiB")


def load_config(path: Path | None = None) -> dict:
    """The enrolment config. A config written before 0.9.0 has no ``inventory_publish``;
    it exists only on an enrolled node, so the signed inventory defaults ON there."""
    try:
        d = json.loads((path or config_path()).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(d, dict):
        return {}
    d.setdefault("inventory_publish", True)
    return d


# ---------------------------------------------------------------------------
# files sync -- one pass
# ---------------------------------------------------------------------------

def _tail(path: Path, n: int = 600) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")[-n:].strip()
    except OSError:
        return ""


def run_pass(cfg: dict | None = None, *, run: Callable[..., Any] | None = None,
             python: str | None = None) -> dict:
    """Scan then push; the receipt (also written to ``<index_dir>/last_run.json``)."""
    from .identity import whoami  # noqa: PLC0415

    cfg = dict(cfg if cfg is not None else load_config())
    run = run or subprocess.run
    py = python or sys.executable
    index_dir = Path(cfg.get("index_dir") or default_index_dir())
    tmp = index_dir / "tmp"
    receipt: dict = {"started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                     "node": "", "index_dir": str(index_dir), "scan_exit": None,
                     "push_exit": None, "exit_code": 2, "failed_step": None, "error": ""}
    try:
        tmp.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        receipt.update(failed_step="index_dir", error=f"cannot create {tmp}: {exc}")
        return _finish(receipt, index_dir)
    node = str(cfg.get("node") or "") or whoami()
    receipt["node"] = node
    env = {**os.environ, "TMP": str(tmp), "TEMP": str(tmp), "TMPDIR": str(tmp),
           "SQLITE_TMPDIR": str(tmp), "AWSTORAGE_NODE": node}
    catalog = str(index_dir / "catalog.db")
    publish = bool(cfg.get("inventory_publish"))
    receipt["publish_exit"] = None if publish else "disabled"
    steps = (
        ("scan", [py, "-m", "awstorage", "files", "scan", "--all-volumes", "--hash", "auto",
                  "--budget", str(int(cfg.get("budget_s") or DEFAULT_BUDGET_S)), "--quiet",
                  "--catalog", catalog, "--node", node, "--json"]),
        ("push", [py, "-m", "awstorage", "files", "push", "--catalog", catalog, "--node", node,
                  "--json"] + (["--api", str(cfg["api"])] if cfg.get("api") else [])),
    ) + ((
        # The signed GitHub inventory (inventory.py): its own transport, so it runs even
        # when the Genesis push failed -- and its failure lands in this receipt too.
        ("publish", [py, "-m", "awstorage", "inventory", "publish", "--catalog", catalog,
                     "--node", node, "--json"]
         + (["--repo", str(cfg["inventory_repo"])] if cfg.get("inventory_repo") else [])),
    ) if publish else ())
    for name, argv in steps:
        out_f, err_f = index_dir / f"{name}.json", index_dir / f"{name}.err"
        try:
            with open(out_f, "wb") as so, open(err_f, "wb") as se:
                rc = int(run(argv, stdout=so, stderr=se, env=env).returncode)
        except OSError as exc:
            rc = 2
            receipt["error"] = f"{name} did not start: {exc}"
        receipt[f"{name}_exit"] = rc
        if rc != 0 and receipt["failed_step"] is None:
            receipt["failed_step"] = name
            receipt["error"] = receipt["error"] or _tail(err_f) or _tail(out_f) or f"exit {rc}"
            receipt["exit_code"] = rc
        if rc != 0 and (name == "scan" or not publish):
            return _finish(receipt, index_dir)
        if name == "publish" and rc == 0:
            try:
                pub = json.loads(out_f.read_text(encoding="utf-8"))
                receipt["published"] = {k: pub.get(k) for k in ("release", "rows", "repo")}
            except (OSError, ValueError) as exc:
                receipt["published"] = {"unreadable": f"{out_f}: {exc}"[:200]}
    if publish and cfg.get("inventory_kinds", True):
        receipt["kinds"] = _publish_kinds(cfg, index_dir, catalog, node, py, run, env)
    if receipt["failed_step"] is None:
        receipt["exit_code"] = 0
    return _finish(receipt, index_dir)


def kinds_every_s() -> int:
    try:
        return max(0, int(os.environ.get(KINDS_EVERY_ENV) or DEFAULT_KINDS_EVERY_S))
    except ValueError:
        return DEFAULT_KINDS_EVERY_S


def kinds_due(index_dir: Path, now: float | None = None) -> list[str]:
    """The host kinds whose last SUCCESSFUL publish is older than the cadence."""
    now = time.time() if now is None else now
    try:
        state = json.loads((index_dir / KINDS_STATE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        state = {}
    every = kinds_every_s()
    out = []
    for k in HOST_KINDS:
        last = state.get(k) if isinstance(state, dict) else None
        if not isinstance(last, (int, float)) or now - float(last) >= every:
            out.append(k)
    return out


def _publish_kinds(cfg: dict, index_dir: Path, catalog: str, node: str, py: str,
                   run: Callable[..., Any], env: dict) -> dict:
    """hardware / software / services, each when due. Never fails the files pass: each
    outcome is in the receipt and only a success moves that kind's timestamp."""
    out: dict = {}
    due = kinds_due(index_dir)
    try:
        state = json.loads((index_dir / KINDS_STATE).read_text(encoding="utf-8"))
        state = state if isinstance(state, dict) else {}
    except (OSError, ValueError):
        state = {}
    for k in HOST_KINDS:
        if k not in due:
            out[k] = {"skipped": "not due", "last": state.get(k)}
            continue
        argv = ([py, "-m", "awstorage", "inventory", "publish", "--kind", k, "--catalog",
                 catalog, "--node", node, "--json"]
                + (["--repo", str(cfg["inventory_repo"])] if cfg.get("inventory_repo") else []))
        out_f, err_f = index_dir / f"publish-{k}.json", index_dir / f"publish-{k}.err"
        try:
            with open(out_f, "wb") as so, open(err_f, "wb") as se:
                rc = int(run(argv, stdout=so, stderr=se, env=env).returncode)
        except OSError as exc:
            out[k] = {"exit": 2, "error": f"did not start: {exc}"[:300]}
            continue
        if rc != 0:
            out[k] = {"exit": rc, "error": _tail(err_f) or _tail(out_f) or f"exit {rc}"}
            continue
        try:
            pub = json.loads(out_f.read_text(encoding="utf-8"))
            out[k] = {"exit": 0, "release": pub.get("release"), "rows": pub.get("rows"),
                      "pruned": (pub.get("retention") or {}).get("pruned")}
        except (OSError, ValueError) as exc:
            out[k] = {"exit": 0, "unreadable": f"{out_f}: {exc}"[:200]}
        state[k] = time.time()
    try:
        (index_dir / KINDS_STATE).write_text(json.dumps(state) + "\n", encoding="utf-8")
    except OSError as exc:
        out["state_error"] = str(exc)[:200]
    return out


def _finish(receipt: dict, index_dir: Path) -> dict:
    receipt["finished"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    try:
        index_dir.mkdir(parents=True, exist_ok=True)
        (index_dir / "last_run.json").write_text(json.dumps(receipt) + "\n", encoding="utf-8")
    except OSError as exc:
        receipt["receipt_error"] = str(exc)
    return receipt


# ---------------------------------------------------------------------------
# files schedule -- install the recurring job once
# ---------------------------------------------------------------------------

def sync_argv(python: str | None = None) -> list[str]:
    py = python or sys.executable
    if python is None and os.name == "nt":  # no console window flashing every N hours
        w = Path(py).with_name("pythonw.exe")
        py = str(w) if w.is_file() else py
    return [py, "-m", "awstorage", "files", "sync"]


def _quote(argv: list[str]) -> str:
    if os.name == "nt":
        return subprocess.list2cmdline(argv)
    import shlex  # noqa: PLC0415
    return " ".join(shlex.quote(a) for a in argv)


def _platform() -> str:
    if sys.platform.startswith("win"):
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return "linux"


def _ok(r: Any) -> bool:
    return getattr(r, "returncode", 1) == 0


def _err(r: Any) -> str:
    return (str(getattr(r, "stderr", "") or getattr(r, "stdout", "") or "")).strip()[:300]


def _install_awrise(run, argv: list[str], every_hours: int) -> dict:
    run(["awrise", "remove", "--name", JOB_NAME], capture_output=True, text=True)
    r = run(["awrise", "add", "--name", JOB_NAME, "--every", f"{every_hours}h",
             "--run", _quote(argv), "--timeout", str(DEFAULT_BUDGET_S + 1800)],
            capture_output=True, text=True)
    return {"scheduler": "awrise", "ok": _ok(r), "detail": "" if _ok(r) else _err(r)}


def _install_windows(run, argv: list[str], every_hours: int) -> dict:
    r = run(["schtasks", "/create", "/f", "/tn", WIN_TASK, "/sc", "HOURLY", "/mo",
             str(every_hours), "/tr", _quote(argv)], capture_output=True, text=True)
    return {"scheduler": "windows-task", "ok": _ok(r), "detail": "" if _ok(r) else _err(r)}


def systemd_units(argv: list[str], every_hours: int) -> tuple[str, str]:
    service = ("[Unit]\nDescription=AitherOS file index (awstorage files sync)\n"
               "After=network-online.target\n\n[Service]\nType=oneshot\nNice=15\n"
               "IOSchedulingClass=idle\n"
               f"ExecStart={_quote(argv)}\n")
    timer = ("[Unit]\nDescription=AitherOS file index, every "
             f"{every_hours}h\n\n[Timer]\nOnBootSec=15min\nOnUnitActiveSec={every_hours}h\n"
             "Persistent=true\n\n[Install]\nWantedBy=timers.target\n")
    return service, timer


def _install_systemd_user(run, argv: list[str], every_hours: int) -> dict:
    unit_dir = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / \
        "systemd" / "user"
    service, timer = systemd_units(argv, every_hours)
    try:
        unit_dir.mkdir(parents=True, exist_ok=True)
        (unit_dir / f"{JOB_NAME}.service").write_text(service, encoding="utf-8")
        (unit_dir / f"{JOB_NAME}.timer").write_text(timer, encoding="utf-8")
    except OSError as exc:
        return {"scheduler": "systemd-user", "ok": False, "detail": str(exc)[:300]}
    for cmd in (["systemctl", "--user", "daemon-reload"],
                ["systemctl", "--user", "enable", "--now", f"{JOB_NAME}.timer"]):
        r = run(cmd, capture_output=True, text=True)
        if not _ok(r):
            return {"scheduler": "systemd-user", "ok": False, "detail": _err(r)}
    run(["loginctl", "enable-linger"], capture_output=True, text=True)  # headless boxes
    return {"scheduler": "systemd-user", "ok": True, "detail": ""}


def _install_cron(run, argv: list[str], every_hours: int) -> dict:
    tag = f"# {JOB_NAME}"
    cur = run(["crontab", "-l"], capture_output=True, text=True)
    lines = [ln for ln in (cur.stdout or "").splitlines() if _ok(cur) and tag not in ln]
    log = Path.home() / ".aither" / "logs" / "file-index.log"
    lines.append(f"17 */{every_hours} * * * {_quote(argv)} >>{log} 2>&1 {tag}")
    r = run(["crontab", "-"], input="\n".join(lines) + "\n", capture_output=True, text=True)
    return {"scheduler": "cron", "ok": _ok(r), "detail": "" if _ok(r) else _err(r)}


def launchd_plist(argv: list[str], every_hours: int) -> str:
    from xml.sax.saxutils import escape  # noqa: PLC0415

    args = "".join(f"<string>{escape(a)}</string>" for a in argv)
    log = escape(str(Path.home() / ".aither" / "logs" / "file-index.log"))
    return ('<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD '
            'PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
            '<plist version="1.0"><dict>'
            f"<key>Label</key><string>com.aitherium.{JOB_NAME}</string>"
            f"<key>ProgramArguments</key><array>{args}</array>"
            f"<key>StartInterval</key><integer>{every_hours * 3600}</integer>"
            "<key>RunAtLoad</key><true/><key>LowPriorityIO</key><true/>"
            f"<key>StandardOutPath</key><string>{log}</string>"
            f"<key>StandardErrorPath</key><string>{log}</string>"
            "</dict></plist>\n")


def _install_launchd(run, argv: list[str], every_hours: int) -> dict:
    agents = Path.home() / "Library" / "LaunchAgents"
    plist = agents / f"com.aitherium.{JOB_NAME}.plist"
    try:
        agents.mkdir(parents=True, exist_ok=True)
        plist.write_text(launchd_plist(argv, every_hours), encoding="utf-8")
    except OSError as exc:
        return {"scheduler": "launchd", "ok": False, "detail": str(exc)[:300]}
    run(["launchctl", "unload", str(plist)], capture_output=True, text=True)
    r = run(["launchctl", "load", "-w", str(plist)], capture_output=True, text=True)
    return {"scheduler": "launchd", "ok": _ok(r), "detail": "" if _ok(r) else _err(r)}


def schedule(*, every_hours: int = DEFAULT_EVERY_HOURS, index_dir: str | None = None,
             api: str | None = None, run: Callable[..., Any] | None = None,
             which: Callable[[str], str | None] | None = None,
             platform: str | None = None, python: str | None = None,
             cfg_path: Path | None = None) -> dict:
    """Write the config and register the recurring ``files sync``. Never raises: the
    outcome (``ok`` False with ``detail`` naming the scheduler's own error) is returned
    for the caller -- enrolment prints it."""
    from .identity import whoami, whoami_source  # noqa: PLC0415

    run = run or subprocess.run
    which = which or shutil.which
    plat = platform or _platform()
    every_hours = max(1, min(int(every_hours), 24))
    if index_dir:
        idx, why = Path(index_dir), "given"
    else:
        idx, why = pick_index_dir()
    node, src = whoami(), whoami_source()
    out: dict = {"node": node, "node_source": src, "index_dir": str(idx),
                 "index_dir_reason": why, "every_hours": every_hours}
    if src == "hostname":
        out.update(ok=False, scheduler=None,
                   detail="this device is not enrolled (no node_auth.json / node-token):"
                          " its index would push under a hostname no registry knows."
                          " Enrol first: adk pair <code>, or adk enroll")
        return out
    cfg = {"index_dir": str(idx), "every_hours": every_hours, "node": node,
           "budget_s": DEFAULT_BUDGET_S, "inventory_publish": True,
           **({"api": api} if api else {})}
    # The node's OWN awseal key signs its inventory (inventory.py). Made here, at
    # enrolment, when missing -- local only; nodes/<node>.pub is committed by the first
    # publish. No awseal installed = the publish step reports that in its receipt.
    try:
        from .inventory import ensure_key  # noqa: PLC0415
        kp, made = ensure_key()
        out["inventory_key"] = {"path": str(kp), "created": made}
    except Exception as exc:  # noqa: BLE001 -- enrolment reports, never raises
        out["inventory_key"] = {"error": f"{type(exc).__name__}: {exc}"[:200]}
    path = cfg_path or config_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(cfg, indent=1) + "\n", encoding="utf-8")
        idx.mkdir(parents=True, exist_ok=True)
        (Path.home() / ".aither" / "logs").mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        out.update(ok=False, scheduler=None, detail=f"config not written: {exc}"[:300])
        return out
    argv = sync_argv(python)
    try:
        if which("awrise"):
            res = _install_awrise(run, argv, every_hours)
        elif plat == "windows":
            res = _install_windows(run, argv, every_hours)
        elif plat == "macos":
            res = _install_launchd(run, argv, every_hours)
        elif which("systemctl") and _ok(run(["systemctl", "--user", "show-environment"],
                                             capture_output=True, text=True)):
            res = _install_systemd_user(run, argv, every_hours)
            if not res["ok"] and which("crontab"):
                res = {**_install_cron(run, argv, every_hours),
                       "systemd_detail": res["detail"]}
        elif which("crontab"):
            res = _install_cron(run, argv, every_hours)
        else:
            res = {"scheduler": None, "ok": False,
                   "detail": "no awrise, no user systemd, no crontab on this machine"}
    except Exception as exc:  # noqa: BLE001 -- report the scheduler failure, never raise
        res = {"scheduler": None, "ok": False, "detail": f"{type(exc).__name__}: {exc}"[:300]}
    out.update(res)
    out["command"] = _quote(argv)
    return out
