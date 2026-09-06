"""Classify trees: what is this, and can it be recreated?

Two classifiers share one contract. `HeuristicClassifier` is offline and
deterministic: path-segment and extension rules, each carrying the REASON it
fired. `LLMClassifier` wraps any `complete(prompt) -> str` callable (the
platform wires its own model router) and asks for JSON; anything it cannot
parse falls back to the heuristic verdict -- and every verdict records its
`source`, so a model-made call and a rule-made call are never confused.

A verdict is a dict merged into the tree:

    {"cls": "package-cache", "refetchable": true, "confidence": 0.9,
     "reason": "segment 'node_modules'", "source": "heuristic"}

Classes are a closed vocabulary (CLASSES) because a policy keys on them; a
model may only pick from the list, never invent one.
"""

from __future__ import annotations

import json
import re
from typing import Callable, Iterable, Protocol

CLASSES = (
    "package-cache",   # pip/npm/cargo/hf caches: re-fetchable from a registry or hub
    "build-temp",      # build outputs, buildah/tmp dirs, node .next/dist: re-buildable
    "model-weights",   # gguf/safetensors/bin weights: re-fetchable if a mirror exists
    "container-store", # image layers / engine storage: prune via the engine, not rm
    "dataset",         # training/eval data: usually NOT re-fetchable
    "backup",          # snapshots, archives, *.bak: keep, but may be redundant
    "repo",            # git working trees: re-clonable, but may hold uncommitted work
    "logs",            # journals, *.log: rotate, do not delete blindly
    "service-state",   # databases, volumes, WAL, vault: NEVER auto-delete
    "media",           # video/images/audio outputs
    "vm-disk",         # vhdx/qcow2/img: the disk is the thing, not the file
    "unknown",
)

_SEG_RULES: list[tuple[re.Pattern, str, bool, float]] = [
    # (segment regex, class, refetchable, confidence)
    (re.compile(r"^(\.cache|caches?|__pycache__|\.npm|\.yarn|\.pnpm-store|pip|npm-cache)$", re.I),
     "package-cache", True, 0.9),
    (re.compile(r"^node_modules$", re.I), "package-cache", True, 0.95),
    (re.compile(r"^(huggingface|hf|hub|hf-cache|\.hf)$", re.I), "model-weights", True, 0.7),
    (re.compile(r"^(build|dist|out|target|\.next|\.turbo|\.parcel-cache|obj|bin)$", re.I),
     "build-temp", True, 0.75),
    (re.compile(r"^(buildah\d+|tmp|temp|\.tmp|staging)$", re.I), "build-temp", True, 0.8),
    (re.compile(r"^(overlay|overlay-images|overlay-layers|containers|docker|podman)$", re.I),
     "container-store", True, 0.85),
    (re.compile(r"^(models?|weights|checkpoints|ggufs?|loras?)$", re.I),
     "model-weights", True, 0.6),
    (re.compile(r"^(datasets?|corpus|corpora|training-data|train|eval)$", re.I),
     "dataset", False, 0.7),
    (re.compile(r"^(backups?|snapshots?|archive|archives|\.snaps)$", re.I), "backup", False, 0.8),
    (re.compile(r"^(\.git|repos?|worktrees?|src)$", re.I), "repo", True, 0.6),
    (re.compile(r"^(logs?|journal|\.log)$", re.I), "logs", True, 0.8),
    (re.compile(r"^(volumes?|postgres(-data)?|pgdata|wal|redis|qdrant|secrets|vault|\.lockbox)$",
                re.I), "service-state", False, 0.9),
    (re.compile(r"^(media|videos?|images?|renders?|audio|music|clips)$", re.I),
     "media", False, 0.6),
    (re.compile(r"^(wsl|vhd|vhdx|vms?|virtual machines)$", re.I), "vm-disk", False, 0.8),
]

_EXT_RULES: list[tuple[re.Pattern, str, bool, float]] = [
    (re.compile(r"\.(gguf|safetensors|ckpt|pth|pt|onnx|bin)$", re.I), "model-weights", True, 0.7),
    (re.compile(r"\.(vhdx?|qcow2|img|iso|vmdk)$", re.I), "vm-disk", False, 0.8),
    (re.compile(r"\.(log|jsonl\.gz|journal)$", re.I), "logs", True, 0.7),
    (re.compile(r"\.(bak|tar\.gz|tgz|zip|7z|snap)$", re.I), "backup", False, 0.6),
    (re.compile(r"\.(mp4|mkv|mov|webm|png|jpe?g|exr|wav|flac|mp3)$", re.I), "media", False, 0.6),
    (re.compile(r"\.(db|sqlite3?|wal|pg_wal|rdb|aof)$", re.I), "service-state", False, 0.9),
]


class Classifier(Protocol):
    def classify(self, items: list[dict]) -> list[dict]: ...


def classify_tree(path: str, top_files: Iterable[str] = ()) -> dict:
    """Heuristic verdict for one tree from its path segments and sampled files."""
    segs = [s for s in path.replace("\\", "/").split("/") if s]
    best: dict | None = None
    # Only the tree's OWN name and its parent's are evidence; anything higher is
    # context, not identity. (Walking every ancestor labelled a whole temp volume
    # "build-temp" because one far-up segment was `Temp` -- measured on the first
    # real scan, and it would have pre-approved deleting the volume root.)
    for i, seg in enumerate(list(reversed(segs))[:2]):
        for rx, cls, refetch, conf in _SEG_RULES:
            if rx.search(seg):
                c = round(conf * (1.0 if i == 0 else 0.85), 2)
                cand = {"cls": cls, "refetchable": refetch, "confidence": c,
                        "reason": f"segment '{seg}'", "source": "heuristic"}
                if best is None or cand["confidence"] > best["confidence"]:
                    best = cand
        if best is not None and i >= 1:
            break
    if best is None:
        counts: dict[str, int] = {}
        why: dict[str, str] = {}
        for f in top_files:
            for rx, cls, refetch, conf in _EXT_RULES:
                if rx.search(f):
                    counts[cls] = counts.get(cls, 0) + 1
                    why.setdefault(cls, f"file '{f.rsplit('/', 1)[-1]}'")
                    break
        if counts:
            cls = max(counts, key=counts.get)
            refetch = next(r for _, c, r, _ in _EXT_RULES if c == cls)
            best = {"cls": cls, "refetchable": refetch,
                    "confidence": round(min(0.85, 0.4 + 0.1 * counts[cls]), 2),
                    "reason": why[cls], "source": "heuristic"}
    return best or {"cls": "unknown", "refetchable": False, "confidence": 0.0,
                    "reason": "no rule matched", "source": "heuristic"}


class HeuristicClassifier:
    def classify(self, items: list[dict]) -> list[dict]:
        out = []
        for it in items:
            files = it.get("sample_files") or []
            out.append({**it, **classify_tree(it["path"], files)})
        return out


_PROMPT = """You label directory trees for a storage inventory. For EACH item, pick exactly
one class from this list: {classes}. Say whether the tree is RE-FETCHABLE (can be
recreated from a registry, a hub, a build, or a mirror without loss) and give a one-line
reason. Answer with a JSON array, one object per item, same order, keys: path, cls,
refetchable (true/false), confidence (0..1), reason. No prose.

ITEMS:
{items}
"""


class LLMClassifier:
    """Model-backed classification with a heuristic floor.

    `complete` is any callable taking a prompt string and returning the model's
    text. The platform passes its router; a stranger can pass a local llama.cpp
    call. Items the model skips, mislabels (class not in CLASSES), or answers
    unparseably keep the heuristic verdict and are counted in `fallbacks` --
    a model that returns nothing must never read as "everything is unknown".
    """

    def __init__(self, complete: Callable[[str], str], batch: int = 25) -> None:
        self._complete = complete
        self._batch = max(1, int(batch))
        self.fallbacks = 0
        self.batches = 0

    def classify(self, items: list[dict]) -> list[dict]:
        base = HeuristicClassifier().classify(items)
        out: list[dict] = []
        for i in range(0, len(base), self._batch):
            chunk = base[i:i + self._batch]
            out.extend(self._classify_chunk(chunk))
        return out

    def _classify_chunk(self, chunk: list[dict]) -> list[dict]:
        self.batches += 1
        lines = []
        for it in chunk:
            files = ", ".join((it.get("sample_files") or [])[:5])
            lines.append(
                f"- path={it['path']} bytes={it.get('bytes', 0)} files={it.get('files', 0)}"
                f" sample_files=[{files}] heuristic={it['cls']}"
            )
        prompt = _PROMPT.format(classes=", ".join(CLASSES), items="\n".join(lines))
        try:
            text = self._complete(prompt) or ""
        except Exception as exc:  # noqa: BLE001 -- the model is optional; the floor is not
            self.fallbacks += len(chunk)
            return [{**it, "llm_error": type(exc).__name__} for it in chunk]
        parsed = _extract_json_array(text)
        by_path = {str(p.get("path", "")): p for p in parsed if isinstance(p, dict)}
        result = []
        for it in chunk:
            v = by_path.get(it["path"])
            if not v or v.get("cls") not in CLASSES or not isinstance(v.get("refetchable"), bool):
                self.fallbacks += 1
                result.append(it)
                continue
            try:
                conf = max(0.0, min(1.0, float(v.get("confidence", 0.5))))
            except (TypeError, ValueError):
                conf = 0.5
            result.append({**it, "cls": v["cls"], "refetchable": v["refetchable"],
                           "confidence": round(conf, 2),
                           "reason": str(v.get("reason", ""))[:200] or "model verdict",
                           "source": "llm", "heuristic_cls": it["cls"]})
        return result


def _extract_json_array(text: str) -> list:
    start = text.find("[")
    end = text.rfind("]")
    if start < 0 or end <= start:
        return []
    try:
        data = json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        return []
    return data if isinstance(data, list) else []


def classify_snapshot(snapshot: dict, classifier: Classifier | None = None) -> dict:
    """Attach a verdict to every tree in the snapshot (in place; returns it)."""
    clf = classifier or HeuristicClassifier()
    samples: dict[str, list[str]] = {}
    for f in snapshot.get("top_files", []):
        p = f["path"]
        for t in snapshot["trees"]:
            if p.startswith(t["path"].rstrip("/") + "/"):
                samples.setdefault(t["path"], []).append(p)
    items = [{**t, "sample_files": samples.get(t["path"], [])[:8]} for t in snapshot["trees"]]
    verdicts = clf.classify(items)
    heuristic_pass = not isinstance(clf, LLMClassifier)
    for t, v in zip(snapshot["trees"], verdicts):
        if heuristic_pass and t.get("source") == "llm":
            # A stored model verdict outranks a re-run of the rules; only a new
            # model pass may replace it.
            continue
        for k in ("cls", "refetchable", "confidence", "reason", "source", "heuristic_cls"):
            if k in v:
                t[k] = v[k]
    snapshot["classified"] = True
    if isinstance(clf, LLMClassifier):
        snapshot["classifier"] = {"kind": "llm", "fallbacks": clf.fallbacks, "batches": clf.batches}
    else:
        snapshot["classifier"] = {"kind": "heuristic"}
    return snapshot
