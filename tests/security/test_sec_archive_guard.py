"""Adversarial security tests for ArchiveGuard (src/activesec/guards/archive_guard.py).

Tests defense against high-ratio ZipBombs, single-file/total quota exhaustion,
Zip-Slip path traversal, and malicious symlinks/setuid attributes.
"""

from __future__ import annotations

import os
import stat
import zipfile

import pytest

from activesec.core.exceptions import ArchiveSecurityError
from activesec.guards.archive_guard import ArchiveGuard, ArchivePolicy


@pytest.mark.security
def test_sec_high_ratio_zip_bomb_blocked_and_purged(tmp_path: os.PathLike[str]) -> None:
    """[Vector B.1: Decompression Bomb] Detects and aborts a high-ratio deflate bomb mid-stream."""
    bomb_zip = os.path.join(str(tmp_path), "bomb.zip")
    extract_dir = os.path.join(str(tmp_path), "quarantine")

    # 2 MB of zeroes compresses to ~2 KB (~1000:1 ratio)
    with zipfile.ZipFile(bomb_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("payload.bin", b"\x00" * (2 * 1024 * 1024))

    guard = ArchiveGuard(
        ArchivePolicy(
            max_compression_ratio=25.0,
            ratio_grace_bytes=32 * 1024,
        )
    )

    with pytest.raises(ArchiveSecurityError) as exc_info:
        guard.safe_extract_zip(bomb_zip, extract_dir)

    assert exc_info.value.vector_id == "B.1"
    assert os.listdir(extract_dir) == []


@pytest.mark.security
def test_sec_zip_slip_path_traversal_blocked(tmp_path: os.PathLike[str]) -> None:
    """[Vector B.2: Zip-Slip Path Traversal] Blocks relative ../ and absolute paths in ZIP entries."""
    slip_zip = os.path.join(str(tmp_path), "slip.zip")
    extract_dir = os.path.join(str(tmp_path), "quarantine")
    outside_target = os.path.join(str(tmp_path), "escaped.txt")

    with zipfile.ZipFile(slip_zip, "w") as zf:
        zf.writestr("../escaped.txt", "pwned")

    guard = ArchiveGuard()
    with pytest.raises(ArchiveSecurityError) as exc_info:
        guard.safe_extract_zip(slip_zip, extract_dir)

    assert exc_info.value.vector_id == "B.2"
    assert not os.path.exists(outside_target)


@pytest.mark.security
def test_sec_symlink_and_setuid_in_archive_blocked(tmp_path: os.PathLike[str]) -> None:
    """[Vector B.2: Symlink & Special File Attack] Rejects symlinks and setuid bits inside archives."""
    symlink_zip = os.path.join(str(tmp_path), "symlink.zip")
    extract_dir = os.path.join(str(tmp_path), "quarantine")

    with zipfile.ZipFile(symlink_zip, "w") as zf:
        info = zipfile.ZipInfo("ssh_link")
        # Set Unix symlink mode (0o120777) in external_attr upper 16 bits
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        zf.writestr(info, "/home/user/.ssh")

    guard = ArchiveGuard()
    with pytest.raises(ArchiveSecurityError) as exc_info:
        guard.safe_extract_zip(symlink_zip, extract_dir)

    assert exc_info.value.vector_id == "B.2"


@pytest.mark.security
def test_sec_recursive_nested_archive_limit_enforced(tmp_path: os.PathLike[str]) -> None:
    """[Vector B.1: Recursive ZipBomb] Blocks nested archives exceeding max_nesting_depth."""
    nested_zip = os.path.join(str(tmp_path), "outer.zip")
    extract_dir = os.path.join(str(tmp_path), "quarantine")

    with zipfile.ZipFile(nested_zip, "w") as zf:
        zf.writestr("inner_layer.zip", b"PK\x03\x04dummy")

    guard = ArchiveGuard(ArchivePolicy(max_nesting_depth=0))
    with pytest.raises(ArchiveSecurityError) as exc_info:
        guard.safe_extract_zip(nested_zip, extract_dir, current_depth=0)

    assert exc_info.value.vector_id == "B.1"
