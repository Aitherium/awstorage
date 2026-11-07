"""NTFS USN change journal: the bytes in, typed records out.

`files.index_root` uses this to make a repeat scan of an NTFS root read only what
changed since the last one instead of walking every file. Two halves:

* **Pure parsing** (`parse_journal_data`, `parse_read_buffer`) -- struct over fixed
  layouts (USN_JOURNAL_DATA_V0/V1/V2, USN_RECORD_V2/V3), testable on any OS.
* **Windows I/O** (`Volume`) -- ctypes `DeviceIoControl` on a handle to the volume's
  root directory:
  FSCTL_QUERY_USN_JOURNAL, FSCTL_READ_USN_JOURNAL (falling back to
  FSCTL_READ_UNPRIVILEGED_USN_JOURNAL when the privileged read is refused), and
  `OpenFileById` + `GetFinalPathNameByHandleW` to turn a directory's file reference
  number back into a path.

Every failure is a `UsnError` carrying a short machine reason (``access_denied``,
``not_ntfs``, ``journal_wrapped`` ...). The caller turns ANY `UsnError` -- or any other
exception -- into a full walk; nothing here decides to skip a change.

Stdlib only.
"""

from __future__ import annotations

import os
import struct
import sys
from dataclasses import dataclass
from typing import Iterator

# -- reasons (winioctl.h) ------------------------------------------------------------
REASON_DATA_OVERWRITE = 0x00000001
REASON_DATA_EXTEND = 0x00000002
REASON_DATA_TRUNCATION = 0x00000004
REASON_FILE_CREATE = 0x00000100
REASON_FILE_DELETE = 0x00000200
REASON_RENAME_OLD_NAME = 0x00001000
REASON_RENAME_NEW_NAME = 0x00002000
REASON_BASIC_INFO_CHANGE = 0x00008000
REASON_HARD_LINK_CHANGE = 0x00010000
REASON_REPARSE_POINT_CHANGE = 0x00100000
REASON_CLOSE = 0x80000000

#: A directory record with any of these moves, removes or re-points a whole subtree.
DIR_STRUCTURAL = (REASON_FILE_CREATE | REASON_FILE_DELETE | REASON_RENAME_OLD_NAME
                  | REASON_RENAME_NEW_NAME | REASON_REPARSE_POINT_CHANGE)
#: Where the record's (parent, name) is the location the object LEFT.
LEAVING = REASON_FILE_DELETE | REASON_RENAME_OLD_NAME

FILE_ATTRIBUTE_DIRECTORY = 0x10
FILE_ATTRIBUTE_REPARSE_POINT = 0x400

FSCTL_QUERY_USN_JOURNAL = 0x000900F4
FSCTL_READ_USN_JOURNAL = 0x000900BB
FSCTL_READ_UNPRIVILEGED_USN_JOURNAL = 0x000903AB

ERROR_ACCESS_DENIED = 5
ERROR_INVALID_FUNCTION = 1
ERROR_INVALID_PARAMETER = 87
ERROR_JOURNAL_DELETE_IN_PROGRESS = 1178
ERROR_JOURNAL_NOT_ACTIVE = 1179
ERROR_JOURNAL_ENTRY_DELETED = 1181

_JOURNAL_V0 = struct.Struct("<QqqqqQQ")       # 56 bytes
_READ_V1 = struct.Struct("<qIIQQQHH")         # READ_USN_JOURNAL_DATA_V1, 44 bytes
_HDR = struct.Struct("<IHH")                  # RecordLength, MajorVersion, MinorVersion
_V2 = struct.Struct("<IHHQQqqIIIIHH")         # USN_RECORD_V2 header, 60 bytes
_V3 = struct.Struct("<IHH16s16sqqIIIIHH")     # USN_RECORD_V3 header, 76 bytes
READ_BUFFER_BYTES = 1 << 20
_BS = chr(92)
_LONG_PREFIX = _BS * 2 + "?" + _BS            # \\?\
_UNC_PREFIX = _LONG_PREFIX + "UNC" + _BS      # \\?\UNC\


class UsnError(Exception):
    """The journal cannot be used for this read; `reason` is a short machine word."""

    def __init__(self, reason: str, detail: str = "", winerror: int | None = None) -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.winerror = winerror


@dataclass(frozen=True)
class JournalInfo:
    journal_id: int
    first_usn: int
    next_usn: int
    lowest_valid_usn: int
    max_usn: int


@dataclass(frozen=True)
class UsnRecord:
    frn: int
    parent_frn: int
    usn: int
    reason: int
    attributes: int
    name: str

    @property
    def is_dir(self) -> bool:
        return bool(self.attributes & FILE_ATTRIBUTE_DIRECTORY)


def parse_journal_data(buf: bytes) -> JournalInfo:
    """USN_JOURNAL_DATA_V0/V1/V2 -> JournalInfo (only the V0 prefix is read)."""
    if len(buf) < _JOURNAL_V0.size:
        raise UsnError("bad_journal_data", f"{len(buf)} bytes < {_JOURNAL_V0.size}")
    jid, first, nxt, lowest, mx, _size, _delta = _JOURNAL_V0.unpack_from(buf, 0)
    return JournalInfo(jid, first, nxt, lowest, mx)


def _fid128(raw: bytes) -> int:
    return int.from_bytes(raw, "little")


def parse_records(buf: bytes, offset: int = 0) -> Iterator[UsnRecord]:
    """Every USN_RECORD_V2/V3 in `buf[offset:]`. A record whose length or name span
    does not fit, or a major version other than 2/3, raises -- never a silent skip."""
    n = len(buf)
    pos = offset
    while pos < n:
        if n - pos < _HDR.size:
            raise UsnError("bad_record", f"truncated header at {pos}")
        length, major, _minor = _HDR.unpack_from(buf, pos)
        if length == 0:
            break  # zero padding at the end of a buffer
        if length < _HDR.size or pos + length > n or length % 8:
            raise UsnError("bad_record", f"record length {length} at {pos}")
        if major == 2:
            if length < _V2.size:
                raise UsnError("bad_record", f"v2 record of {length} bytes at {pos}")
            (_l, _ma, _mi, frn, pfrn, usn, _ts, reason, _src, _sec, attrs, nlen,
             noff) = _V2.unpack_from(buf, pos)
        elif major == 3:
            if length < _V3.size:
                raise UsnError("bad_record", f"v3 record of {length} bytes at {pos}")
            (_l, _ma, _mi, frn_b, pfrn_b, usn, _ts, reason, _src, _sec, attrs, nlen,
             noff) = _V3.unpack_from(buf, pos)
            frn, pfrn = _fid128(frn_b), _fid128(pfrn_b)
        else:
            raise UsnError("bad_record", f"unsupported major version {major} at {pos}")
        if nlen % 2 or noff + nlen > length:
            raise UsnError("bad_record", f"name span {noff}+{nlen} > {length} at {pos}")
        name = buf[pos + noff:pos + noff + nlen].decode("utf-16-le", "surrogatepass")
        yield UsnRecord(frn, pfrn, usn, reason, attrs, name)
        pos += length


def parse_read_buffer(buf: bytes) -> tuple[int, list[UsnRecord]]:
    """FSCTL_READ_USN_JOURNAL output: (next USN to ask for, records)."""
    if len(buf) < 8:
        raise UsnError("bad_record", f"read buffer of {len(buf)} bytes")
    (nxt,) = struct.unpack_from("<q", buf, 0)
    return nxt, list(parse_records(buf, 8))


def pack_read_request(start_usn: int, journal_id: int) -> bytes:
    """READ_USN_JOURNAL_DATA_V1: every reason, no waiting, records v2..v3."""
    return _READ_V1.pack(start_usn, 0xFFFFFFFF, 0, 0, 0, journal_id, 2, 3)


# ---------------------------------------------------------------------------
# Windows I/O
# ---------------------------------------------------------------------------

def supported() -> bool:
    return sys.platform == "win32"


class Volume:
    """An open NTFS volume: query/read the journal, resolve directory ids to paths.

    `root` is any path on the volume. Raises UsnError on every refusal."""

    def __init__(self, root: str) -> None:
        if not supported():
            raise UsnError("not_windows", sys.platform)
        import ctypes
        from ctypes import wintypes as w

        self._ct = ctypes
        k = ctypes.WinDLL("kernel32", use_last_error=True)
        self._k = k
        k.CreateFileW.restype = w.HANDLE
        k.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, ctypes.c_void_p, w.DWORD,
                                  w.DWORD, w.HANDLE]
        k.DeviceIoControl.restype = w.BOOL
        k.DeviceIoControl.argtypes = [w.HANDLE, w.DWORD, ctypes.c_void_p, w.DWORD,
                                      ctypes.c_void_p, w.DWORD, ctypes.POINTER(w.DWORD),
                                      ctypes.c_void_p]
        k.CloseHandle.argtypes = [w.HANDLE]
        k.OpenFileById.restype = w.HANDLE
        k.OpenFileById.argtypes = [w.HANDLE, ctypes.c_void_p, w.DWORD, w.DWORD,
                                   ctypes.c_void_p, w.DWORD]
        k.GetFinalPathNameByHandleW.restype = w.DWORD
        k.GetFinalPathNameByHandleW.argtypes = [w.HANDLE, w.LPWSTR, w.DWORD, w.DWORD]
        k.GetVolumePathNameW.argtypes = [w.LPCWSTR, w.LPWSTR, w.DWORD]
        k.GetVolumeNameForVolumeMountPointW.argtypes = [w.LPCWSTR, w.LPWSTR, w.DWORD]
        k.GetVolumeInformationW.argtypes = [w.LPCWSTR, w.LPWSTR, w.DWORD,
                                            ctypes.POINTER(w.DWORD), ctypes.POINTER(w.DWORD),
                                            ctypes.POINTER(w.DWORD), w.LPWSTR, w.DWORD]
        self._invalid = w.HANDLE(-1).value
        buf = ctypes.create_unicode_buffer(1024)
        if not k.GetVolumePathNameW(os.path.abspath(root), buf, 1024):
            self._fail("no_volume", "GetVolumePathNameW")
        self.mount = buf.value                       # e.g. "C:\\"
        fs = ctypes.create_unicode_buffer(64)
        if not k.GetVolumeInformationW(self.mount, None, 0, None, None, None, fs, 64):
            self._fail("no_volume", "GetVolumeInformationW")
        self.fs = fs.value
        if self.fs.upper() != "NTFS":
            raise UsnError("not_ntfs", self.fs)
        guid = ctypes.create_unicode_buffer(128)
        if not k.GetVolumeNameForVolumeMountPointW(self.mount, guid, 128):
            self._fail("no_volume", "GetVolumeNameForVolumeMountPointW")
        self.volume_name = guid.value.rstrip("\\")   # \\?\Volume{...}
        share = 0x1 | 0x2 | 0x4
        # Measured 2026-11-07 (Windows 11 26300, un-elevated): CreateFileW on the volume
        # device needs admin for any access that FSCTL_QUERY_USN_JOURNAL accepts, but a
        # 0-access BACKUP_SEMANTICS handle on the volume's ROOT DIRECTORY answers the
        # query and FSCTL_READ_UNPRIVILEGED_USN_JOURNAL. It is also the OpenFileById hint.
        self._h = self._open(self.mount, 0, share, 0x02000000)
        self.privileged_read: bool | None = None

    # -- plumbing ----------------------------------------------------------------
    def _fail(self, reason: str, what: str, err: int | None = None) -> None:
        err = self._ct.get_last_error() if err is None else err
        if err == ERROR_ACCESS_DENIED:
            reason = "access_denied"
        raise UsnError(reason, f"{what} failed (winerror {err})", err)

    def _open(self, path: str, access: int, share: int, flags: int) -> int:
        h = self._k.CreateFileW(path, access, share, None, 3, flags, None)
        if h is None or h == self._invalid:
            self._fail("open_failed", f"CreateFileW({path})")
        return h

    def _ioctl(self, code: int, inbuf: bytes | None, out_size: int) -> tuple[bytes, int]:
        ct = self._ct
        from ctypes import wintypes as w
        out = ct.create_string_buffer(out_size)
        got = w.DWORD(0)
        inb = ct.create_string_buffer(inbuf, len(inbuf)) if inbuf else None
        ok = self._k.DeviceIoControl(self._h, code, inb, len(inbuf) if inbuf else 0, out,
                                     out_size, ct.byref(got), None)
        if not ok:
            return b"", ct.get_last_error()
        return out.raw[:got.value], 0

    def close(self) -> None:
        h = getattr(self, "_h", None)
        if h:
            self._k.CloseHandle(h)
        self._h = None

    def __enter__(self) -> "Volume":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- journal -----------------------------------------------------------------
    def query(self) -> JournalInfo:
        raw, err = self._ioctl(FSCTL_QUERY_USN_JOURNAL, None, 80)
        if err:
            reason = {ERROR_ACCESS_DENIED: "access_denied",
                      ERROR_JOURNAL_NOT_ACTIVE: "journal_not_active",
                      ERROR_JOURNAL_DELETE_IN_PROGRESS: "journal_not_active",
                      ERROR_INVALID_FUNCTION: "not_ntfs"}.get(err, "query_failed")
            raise UsnError(reason, f"FSCTL_QUERY_USN_JOURNAL (winerror {err})", err)
        return parse_journal_data(raw)

    def read(self, start_usn: int, journal_id: int) -> tuple[int, list[UsnRecord]]:
        """One buffer of records from `start_usn`: (next usn, records)."""
        req = pack_read_request(start_usn, journal_id)
        codes = ([FSCTL_READ_USN_JOURNAL, FSCTL_READ_UNPRIVILEGED_USN_JOURNAL]
                 if self.privileged_read is not False else
                 [FSCTL_READ_UNPRIVILEGED_USN_JOURNAL])
        err = 0
        for code in codes:
            raw, err = self._ioctl(code, req, READ_BUFFER_BYTES)
            if not err:
                self.privileged_read = code == FSCTL_READ_USN_JOURNAL
                return parse_read_buffer(raw)
            if err not in (ERROR_ACCESS_DENIED, ERROR_INVALID_FUNCTION,
                           ERROR_INVALID_PARAMETER):
                break
        reason = {ERROR_ACCESS_DENIED: "access_denied",
                  ERROR_JOURNAL_ENTRY_DELETED: "journal_wrapped",
                  ERROR_JOURNAL_NOT_ACTIVE: "journal_not_active",
                  ERROR_JOURNAL_DELETE_IN_PROGRESS: "journal_not_active"}.get(err,
                                                                              "read_failed")
        raise UsnError(reason, f"FSCTL_READ_USN_JOURNAL (winerror {err})", err)

    def read_until(self, start_usn: int, end_usn: int, journal_id: int
                   ) -> Iterator[UsnRecord]:
        """Every record with start_usn <= usn < end_usn."""
        usn = start_usn
        while usn < end_usn:
            nxt, recs = self.read(usn, journal_id)
            for r in recs:
                if r.usn >= end_usn:
                    return
                yield r
            if nxt <= usn or not recs:
                return
            usn = nxt

    def resolve(self, frn: int) -> tuple[str | None, int]:
        """(current DOS path, 0) of the object with this file reference number, or
        (None, winerror) when it no longer exists or cannot be opened. Raises nothing."""
        ct = self._ct
        desc = ct.create_string_buffer(24)
        if frn >= 1 << 64:
            struct.pack_into("<Ii16s", desc, 0, 24, 2, frn.to_bytes(16, "little"))
        else:
            struct.pack_into("<IiQQ", desc, 0, 24, 0, frn, 0)
        # OPEN_REPARSE_POINT: a junction / symlink resolves to ITSELF, not its target
        # (measured: dangling links otherwise read as "gone" with no delete record).
        h = self._k.OpenFileById(self._h, desc, 0, 0x1 | 0x2 | 0x4, None, 0x02200000)
        if h is None or h == self._invalid:
            return None, ct.get_last_error()
        try:
            buf = ct.create_unicode_buffer(32768)
            n = self._k.GetFinalPathNameByHandleW(h, buf, 32768, 0)
            if not n or n >= 32768:
                return None, ct.get_last_error() or ERROR_INVALID_PARAMETER
            p = buf.value
        finally:
            self._k.CloseHandle(h)
        if p.startswith(_UNC_PREFIX):
            return None, ERROR_INVALID_PARAMETER
        if p.startswith(_LONG_PREFIX):
            p = p[len(_LONG_PREFIX):]
        return p.replace(_BS, "/"), 0

    def path_of(self, frn: int) -> str | None:
        return self.resolve(frn)[0]
