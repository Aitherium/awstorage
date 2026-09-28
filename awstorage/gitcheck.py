"""Is this path's git work tree clean AND pushed?  The question before removing one.

A work tree is safe to remove only when nothing in it exists ONLY there:

* no uncommitted or untracked change (``git status --porcelain``), and
* no commit that no remote holds: ``git rev-list @{u}..`` when a branch tracks an
  upstream, and ``git rev-list HEAD --not --remotes`` always (a detached agent
  worktree has no upstream, and a branch that was never pushed has none either).
  For a MAIN clone (``.git`` is a directory) every local branch is checked, not
  just HEAD -- removing the clone loses all of them; a linked worktree (``.git`` is
  a file) shares its refs with the main clone, so only its HEAD is at stake.

Every git call has a timeout, runs with ``GIT_OPTIONAL_LOCKS=0`` (a status must
not take the index lock from a live session) and never bypasses ``safe.directory``.
Anything git cannot answer -- missing binary, timeout, a repo owned by someone
else, an empty repo -- is ``judged: False``, and every caller REFUSES on it: "could
not tell" never reads as "clean".

Stdlib only (subprocess); speaks to no sibling.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from ._fs import walk_no_follow

GIT_TIMEOUT_S = 20.0
#: Nested-repo scan bounds: repos deeper than this, or past this many dirs, are not
#: looked for -- the scan says so (`complete: False`) and the caller treats that as
#: "could not prove there is none".
NESTED_MAX_DEPTH = 3
NESTED_MAX_DIRS = 20000
NESTED_MAX_REPOS = 20


def _norm(p: str | os.PathLike) -> str:
    return str(p).replace("\\", "/")


def find_work_tree(path: str | os.PathLike) -> tuple[str, str] | None:
    """(work tree root, 'dir'|'file') of the git tree `path` lives in, or None.

    Walks from the path itself (or its parent, for a file) up to the FILESYSTEM root:
    a `.git` directory is a main clone, a `.git` FILE a linked worktree/submodule.
    """
    p = Path(os.path.abspath(str(path)))
    node = p if (p.is_dir() and not os.path.islink(p)) else p.parent
    while True:
        g = node / ".git"
        if os.path.lexists(g):
            return _norm(node), ("dir" if g.is_dir() and not os.path.islink(g) else "file")
        parent = node.parent
        if parent == node:
            return None
        node = parent


def _git(repo: str, *args: str, timeout: float) -> tuple[int, str, str]:
    env = dict(os.environ)
    env["GIT_OPTIONAL_LOCKS"] = "0"
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["LC_ALL"] = "C"
    r = subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True,
                       timeout=timeout, env=env, check=False, encoding="utf-8",
                       errors="replace")
    return r.returncode, r.stdout, r.stderr


def repo_state(repo: str, kind: str = "dir", *, timeout: float = GIT_TIMEOUT_S) -> dict:
    """Judge one work tree root. Keys: repo, kind, judged, clean, dirty, unpushed, why."""
    out: dict[str, Any] = {"repo": _norm(repo), "kind": kind, "judged": False,
                           "clean": False, "dirty": None, "unpushed": None, "why": ""}
    if shutil.which("git") is None:
        out["why"] = "could not judge: git is not on PATH"
        return out
    try:
        rc, so, se = _git(repo, "status", "--porcelain", "--untracked-files=normal",
                          timeout=timeout)
        if rc != 0:
            out["why"] = f"could not judge: git status exit {rc}: {se.strip()[:200]}"
            return out
        dirty = [ln for ln in so.splitlines() if ln.strip()]
        out["dirty"] = len(dirty)
        rc, so, se = _git(repo, "rev-parse", "--verify", "--quiet", "HEAD", timeout=timeout)
        if rc != 0:
            out["why"] = "could not judge: the repo has no HEAD commit"
            return out
        ahead = 0
        rc, so, _se = _git(repo, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}",
                           timeout=timeout)
        if rc == 0 and so.strip():
            rc, so, se = _git(repo, "rev-list", "--count", "@{u}..HEAD", timeout=timeout)
            if rc != 0:
                out["why"] = f"could not judge: git rev-list @{{u}}.. exit {rc}"
                return out
            ahead = int(so.strip() or 0)
        # Commits no remote-tracking ref holds. A main clone loses every local branch
        # when removed; a linked worktree only its HEAD (its refs live in the clone).
        scope = ["HEAD", "--branches"] if kind == "dir" else ["HEAD"]
        rc, so, se = _git(repo, "rev-list", "--count", *scope, "--not", "--remotes",
                          timeout=timeout)
        if rc != 0:
            out["why"] = f"could not judge: git rev-list --not --remotes exit {rc}"
            return out
        unpushed = max(ahead, int(so.strip() or 0))
        out["unpushed"] = unpushed
    except subprocess.TimeoutExpired:
        out["why"] = f"could not judge: git timed out after {timeout:g}s"
        return out
    except (OSError, ValueError) as exc:
        out["why"] = f"could not judge: {type(exc).__name__}: {exc}"
        return out
    out["judged"] = True
    if dirty:
        out["why"] = f"{len(dirty)} uncommitted/untracked change(s), first {dirty[0].strip()!r}"
    elif unpushed:
        out["why"] = f"{unpushed} commit(s) no remote holds"
    else:
        out["clean"] = True
        out["why"] = "clean and pushed"
    return out


def git_state(path: str | os.PathLike, *, timeout: float = GIT_TIMEOUT_S) -> dict:
    """The state of the work tree `path` lives in (walk up for `.git`).

    Not inside any work tree: ``{"repo": None, "judged": True, "clean": True}`` --
    callers that REQUIRE a repo (the agent-worktrees rule) check ``repo`` themselves.
    """
    wt = find_work_tree(path)
    if wt is None:
        return {"repo": None, "kind": None, "judged": True, "clean": True, "dirty": 0,
                "unpushed": 0, "why": "not inside a git work tree"}
    return repo_state(wt[0], wt[1], timeout=timeout)


def nested_repos(path: str | os.PathLike, *, max_depth: int = NESTED_MAX_DEPTH,
                 max_dirs: int = NESTED_MAX_DIRS) -> dict:
    """Work trees BELOW `path` (bounded walk, links never followed).

    Returns {"repos": [(root, kind)], "complete": bool}. `complete` is False when the
    dir budget ran out -- then a repo may exist that was not seen.
    """
    base = os.path.abspath(str(path))
    base_depth = base.rstrip("\\/").count(os.sep)
    repos: list[tuple[str, str]] = []
    seen_dirs = 0
    complete = True
    for d, dirs, files, links in walk_no_follow(base):
        seen_dirs += 1
        if seen_dirs > max_dirs:
            complete = False
            break
        depth = os.path.abspath(d).rstrip("\\/").count(os.sep) - base_depth
        names = {e.name for e in dirs} | {e.name for e in files} | {e.name for e in links}
        dirs[:] = [e for e in dirs if e.name != ".git"]  # never walk a repo's objects
        if depth >= max_depth:
            dirs[:] = []  # walk_no_follow honours pruning of its dirs list
        if depth == 0:
            continue  # the path itself is judged by git_state (walk-up)
        if ".git" in names:
            g = os.path.join(d, ".git")
            repos.append((_norm(d), "dir" if os.path.isdir(g) and not os.path.islink(g)
                          else "file"))
    return {"repos": repos, "complete": complete}


__all__ = ["GIT_TIMEOUT_S", "find_work_tree", "git_state", "nested_repos", "repo_state"]
