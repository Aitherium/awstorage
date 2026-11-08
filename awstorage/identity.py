"""Node identity and the volumes a node can see.

`whoami()` is the ONE place a node id comes from, in this order:

1. ``AWSTORAGE_NODE`` (a scheduler or a test pins it);
2. ``~/.aither/node-id`` (host setup; the platform host writes ``local``);
3. the id this device REGISTERED with: ``~/.aither/node_auth.json`` ``node_id``
   (``adk pair`` / ``adk enroll`` -- the install door), else ``AITHER_NODE_ID`` in the
   ``node-token`` file ``bootstrap/join.sh`` writes (``/etc/aitheros`` or the per-user
   ``~/.config/aitheros``);
4. the hostname -- only when the device never enrolled.

Step 3 exists because nothing wrote ``node-id`` at enroll: every enrolled laptop
indexed itself under its HOSTNAME, a name no registry knows, and Genesis refused the
push ("not in your scope"). The registered id is the one the node's credential names.

Every CLI verb uses it; nothing else calls ``socket.gethostname()`` for a node id.

`list_volumes()` is the stdlib volume probe that travels in a file-index push
(and backs ``files scan --all-volumes``): mount, fs, total and free bytes.
"""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import socket
from pathlib import Path

NODE_ID_FILE = Path.home() / ".aither" / "node-id"
_NODE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


def credential_files(node_id_file: Path | None = None) -> list[Path]:
    """Where an enrolled device keeps its registration, in lookup order. Relative to the
    ``node-id`` file's directory (``~/.aither``), plus join.sh's ``node-token`` locations
    when that directory is the default one."""
    base = (node_id_file or NODE_ID_FILE).parent
    out = [base / "node_auth.json"]
    if node_id_file is None:
        xdg = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
        out += [Path("/etc/aitheros/node-token"), xdg / "aitheros" / "node-token"]
    return out


def read_registration(path: Path) -> dict:
    """{"node_id", "token", "tenant_id"} from one credential file ({} when absent or
    unreadable). node_auth.json is JSON; join.sh's node-token is KEY=VALUE lines."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return {}
    if path.name.endswith(".json"):
        try:
            d = json.loads(text)
        except ValueError:
            return {}
        if not isinstance(d, dict):
            return {}
        return {"node_id": str(d.get("node_id") or "").strip(),
                "token": str(d.get("bearer_token") or "").strip(),
                "tenant_id": str(d.get("tenant_id") or "").strip()}
    kv = {}
    for line in text.splitlines():
        k, sep, v = line.partition("=")
        if sep:
            kv[k.strip()] = v.strip()
    return {"node_id": kv.get("AITHER_NODE_ID", ""), "token": kv.get("AITHER_NODE_TOKEN", ""),
            "tenant_id": ""}


def registered_node(node_id_file: Path | None = None) -> tuple[str, str]:
    """(node_id, source file) of the first enrolled registration found, ("", "") if none."""
    for f in credential_files(node_id_file):
        nid = read_registration(f).get("node_id", "")
        if nid and _NODE_RE.match(nid):
            return nid, str(f)
    return "", ""


def whoami(node_id_file: Path | None = None) -> str:
    """The node id this process speaks for (see module docstring for the order)."""
    env = (os.environ.get("AWSTORAGE_NODE") or "").strip()
    if env:
        return env
    f = node_id_file or NODE_ID_FILE
    try:
        text = f.read_text(encoding="utf-8").strip()
    except OSError:
        text = ""
    if text and _NODE_RE.match(text):
        return text
    nid, _src = registered_node(node_id_file)
    return nid or socket.gethostname()


def whoami_source(node_id_file: Path | None = None) -> str:
    if (os.environ.get("AWSTORAGE_NODE") or "").strip():
        return "env:AWSTORAGE_NODE"
    f = node_id_file or NODE_ID_FILE
    try:
        if _NODE_RE.match(f.read_text(encoding="utf-8").strip()):
            return f"file:{f}"
    except OSError:
        pass
    _nid, src = registered_node(node_id_file)
    return f"registration:{src}" if src else "hostname"


_PSEUDO_FS = frozenset({
    "proc", "sysfs", "devtmpfs", "devpts", "tmpfs", "cgroup", "cgroup2", "securityfs",
    "pstore", "debugfs", "tracefs", "configfs", "fusectl", "mqueue", "hugetlbfs", "bpf",
    "autofs", "binfmt_misc", "overlay", "squashfs", "nsfs", "ramfs", "rpc_pipefs",
    "efivarfs", "selinuxfs", "devfs", "nullfs",
})
_NETWORK_FS = frozenset({"nfs", "nfs4", "cifs", "smb3", "9p", "drvfs", "fuse.sshfs"})


def _usage(mount: str) -> tuple[int, int] | None:
    try:
        u = shutil.disk_usage(mount)
    except OSError:
        return None
    return int(u.total), int(u.free)


def _windows_volumes() -> list[dict]:
    import ctypes  # noqa: PLC0415
    import string  # noqa: PLC0415

    k32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    mask = k32.GetLogicalDrives()
    out = []
    for i, letter in enumerate(string.ascii_uppercase):
        if not mask & (1 << i):
            continue
        root = letter + ":" + os.sep
        dtype = k32.GetDriveTypeW(root)  # 2 removable 3 fixed 4 remote 5 cdrom 6 ram
        if dtype not in (2, 3, 4, 6):
            continue
        fs_buf = ctypes.create_unicode_buffer(64)
        if not k32.GetVolumeInformationW(root, None, 0, None, None, None, fs_buf, 64):
            continue
        u = _usage(root)
        if u is None:
            continue
        out.append({"mount": f"{letter}:/", "fs": fs_buf.value, "total_bytes": u[0],
                    "free_bytes": u[1],
                    "kind": {2: "removable", 3: "fixed", 4: "network", 6: "ramdisk"}[dtype]})
    return out


def _posix_volumes(mounts_text: str | None = None) -> list[dict]:
    if mounts_text is None:
        try:
            mounts_text = Path("/proc/mounts").read_text(encoding="utf-8")
        except OSError:
            return []
    out, seen = [], set()
    for ln in mounts_text.splitlines():
        parts = ln.split()
        if len(parts) < 3:
            continue
        dev, mnt, fs = parts[0], parts[1].replace(r"\040", " "), parts[2]
        if fs in _PSEUDO_FS or mnt.startswith(("/proc", "/sys", "/dev", "/run")):
            continue
        if dev in seen:
            continue
        u = _usage(mnt)
        if u is None or u[0] == 0:
            continue
        seen.add(dev)
        out.append({"mount": mnt, "fs": fs, "total_bytes": u[0], "free_bytes": u[1],
                    "kind": "network" if fs in _NETWORK_FS else "fixed"})
    return out


def list_volumes() -> list[dict]:
    """Every mounted volume; never raises (a probe failure is an empty list)."""
    try:
        return _windows_volumes() if platform.system() == "Windows" else _posix_volumes()
    except Exception:  # noqa: BLE001
        return []
