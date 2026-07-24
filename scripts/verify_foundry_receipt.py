"""Validate that Foundry created a fresh environment-specific casting receipt."""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


class FoundryReceiptError(ValueError):
    """Raised when Foundry deployment evidence is absent, stale, or malformed."""


@dataclass(frozen=True, slots=True)
class ReceiptIdentity:
    exists: bool
    size: int = 0
    modified_ns: int = 0
    sha256: str = ""


def receipt_identity(path: Path) -> ReceiptIdentity:
    if not path.exists():
        return ReceiptIdentity(exists=False)
    if path.is_symlink() or not path.is_file():
        raise FoundryReceiptError("Foundry deployment receipt is not a regular file")
    stat = path.stat()
    content = path.read_bytes()
    return ReceiptIdentity(
        exists=True,
        size=stat.st_size,
        modified_ns=stat.st_mtime_ns,
        sha256=hashlib.sha256(content).hexdigest(),
    )


def validate_replaced_receipt(
    receipt: Path,
    *,
    before: ReceiptIdentity,
    source_lock: Path,
) -> ReceiptIdentity:
    after = receipt_identity(receipt)
    if not after.exists:
        raise FoundryReceiptError("Foundry did not create casting.yaml.lock")
    if before.exists and after == before:
        raise FoundryReceiptError(
            "Foundry did not replace the pre-existing casting.yaml.lock"
        )
    content = receipt.read_bytes()
    if source_lock.exists() and content == source_lock.read_bytes():
        raise FoundryReceiptError(
            "The source-content lock cannot serve as a Foundry deployment receipt"
        )
    _validate_foundry_yaml(content)
    return after


def _validate_foundry_yaml(content: bytes) -> None:
    if not content or len(content) > 5 * 1024 * 1024:
        raise FoundryReceiptError("Foundry deployment receipt has an invalid size")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FoundryReceiptError("Foundry deployment receipt is not UTF-8 YAML") from exc
    try:
        possible_source_lock = json.loads(text)
    except json.JSONDecodeError:
        possible_source_lock = None
    if isinstance(possible_source_lock, dict) and {
        "lock_version",
        "source",
        "sha256",
        "size",
    }.issubset(possible_source_lock):
        raise FoundryReceiptError(
            "Source-content JSON is not a Foundry deployment receipt"
        )

    top_level: dict[str, str] = {}
    sections: set[str] = set()
    for line in text.splitlines():
        if not line or line[0].isspace() or line.lstrip().startswith("#"):
            continue
        key, separator, value = line.partition(":")
        if not separator:
            raise FoundryReceiptError("Foundry deployment receipt is malformed YAML")
        key = key.strip()
        value = value.strip()
        if key in top_level or key in sections:
            raise FoundryReceiptError(
                f"Foundry deployment receipt duplicates top-level key {key}"
            )
        if value:
            top_level[key] = value.strip("'\"")
        else:
            sections.add(key)

    if top_level.get("apiVersion") != "v1alpha1":
        raise FoundryReceiptError(
            "Foundry deployment receipt has an unsupported apiVersion"
        )
    if top_level.get("kind") not in {"Installation", "CollectionAgent"}:
        raise FoundryReceiptError("Foundry deployment receipt has an invalid kind")
    if not {"metadata", "spec"}.issubset(sections):
        raise FoundryReceiptError(
            "Foundry deployment receipt lacks metadata or resolved spec"
        )


def _identity_from_json(value: str) -> ReceiptIdentity:
    try:
        payload: Any = json.loads(value)
        return ReceiptIdentity(
            exists=payload["exists"],
            size=payload.get("size", 0),
            modified_ns=payload.get("modified_ns", 0),
            sha256=payload.get("sha256", ""),
        )
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise FoundryReceiptError("Invalid pre-deployment receipt identity") from exc


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    snapshot = subparsers.add_parser("snapshot")
    snapshot.add_argument("--receipt", type=Path, required=True)
    validate = subparsers.add_parser("validate")
    validate.add_argument("--receipt", type=Path, required=True)
    validate.add_argument("--source-lock", type=Path, required=True)
    validate.add_argument("--before", required=True)
    args = parser.parse_args()

    try:
        if args.command == "snapshot":
            print(json.dumps(asdict(receipt_identity(args.receipt)), sort_keys=True))
        else:
            validate_replaced_receipt(
                args.receipt,
                before=_identity_from_json(args.before),
                source_lock=args.source_lock,
            )
    except FoundryReceiptError as exc:
        parser.exit(1, f"{exc}\n")


if __name__ == "__main__":
    main()
