"""Ring-0 ArchiveGuard: Streaming defense against ZipBombs, TarBombs, and Zip-Slip traversal.

Never trusts archive header metadata alone. Enforces real-time streaming decompression
counters, compression ratio caps, canonical path confinement, and special-file rejection.
"""

from __future__ import annotations

import os
import secrets
import shutil
import stat
import zipfile
from dataclasses import dataclass
from typing import List, Tuple

from activesec.core.component import ComponentSecurityAssessment, SecureComponent
from activesec.core.exceptions import ArchiveSecurityError


@dataclass(frozen=True, slots=True)
class ArchivePolicy:
    """Immutable quota policy for safe archive inspection and extraction."""

    max_total_uncompressed_bytes: int = 100 * 1024 * 1024  # 100 MB default
    max_single_file_bytes: int = 50 * 1024 * 1024          # 50 MB default
    max_compression_ratio: float = 100.0                   # Max 100:1 expansion ratio
    ratio_grace_bytes: int = 64 * 1024                     # Enforce ratio once stream > 64 KB
    max_file_count: int = 2_000
    max_nesting_depth: int = 2
    chunk_size: int = 65_536                               # 64 KB streaming chunks


class ArchiveGuard(SecureComponent):
    """Ring-0 gateway for safe, quota-enforced archive extraction."""

    NESTED_ARCHIVE_EXTENSIONS = (".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z")

    def __init__(self, policy: ArchivePolicy | None = None) -> None:
        self._policy: ArchivePolicy = policy if policy is not None else ArchivePolicy()

    @property
    def policy(self) -> ArchivePolicy:
        return self._policy

    @classmethod
    def security_assessment(cls) -> ComponentSecurityAssessment:
        return ComponentSecurityAssessment(
            component_id="archive_guard",
            title="Ring-0 Archive Decompression Bomb & Path Traversal Guard",
            ring_level=0,
            source_path="src/activesec/guards/archive_guard.py",
            security_test_path="tests/security/test_sec_archive_guard.py",
            threat_vectors=("B.1", "B.2"),
            summary=(
                "Protects the harness against flat and recursive decompression bombs (ZipBombs), "
                "spoofed ZIP headers, Zip-Slip relative path traversal, and malicious symlinks/device nodes."
            ),
            enforced_invariants=(
                "Never invokes zipfile.extractall() or tarfile.extractall().",
                "Streams decompression into an isolated atomic staging directory (.staging_<random>) using O_NOFOLLOW file descriptors while counting actual uncompressed bytes against max_single_file_bytes, max_total_uncompressed_bytes, and max_compression_ratio.",
                "Rejects symlinks, FIFOs, character/block devices, and setuid/setgid bits via Unix external attributes and post-extraction lstat/realpath verification.",
                "Verifies canonical path containment against TOCTOU symlink swaps before atomically moving verified files into target_dir.",
            ),
            residual_risks=(
                "CPU time spent decompressing up to the configured quota before threshold termination (bounded by SandboxGuard wall-clock timeout).",
            ),
        )

    def safe_extract_zip(
        self,
        zip_path: str,
        target_dir: str,
        *,
        current_depth: int = 0,
    ) -> List[str]:
        """Safely extract a ZIP archive into target_dir while enforcing all Ring-0 quotas."""
        if current_depth > self._policy.max_nesting_depth:
            raise ArchiveSecurityError(
                f"Archive nesting depth {current_depth} exceeds max_nesting_depth ({self._policy.max_nesting_depth}).",
                vector_id="B.1",
                component_id="archive_guard",
            )

        if not os.path.isfile(zip_path):
            raise ArchiveSecurityError(
                f"Archive file does not exist: {zip_path}",
                vector_id="B.1",
                component_id="archive_guard",
            )

        if os.path.islink(target_dir):
            raise ArchiveSecurityError(
                f"Extraction target_dir '{target_dir}' is a symbolic link (TOCTOU defense).",
                vector_id="B.2",
                component_id="archive_guard",
            )

        real_target = os.path.realpath(target_dir)
        os.makedirs(real_target, mode=0o700, exist_ok=True)
        staging_dir = os.path.join(real_target, f".staging_{secrets.token_hex(8)}")
        os.makedirs(staging_dir, mode=0o700, exist_ok=True)

        archive_file_size = max(1, os.path.getsize(zip_path))
        total_written = 0
        staged_pairs: List[Tuple[str, str]] = []
        extracted_files: List[str] = []

        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                infos = zf.infolist()
                if len(infos) > self._policy.max_file_count:
                    raise ArchiveSecurityError(
                        f"Archive entry count ({len(infos)}) exceeds max_file_count ({self._policy.max_file_count}).",
                        vector_id="B.1",
                        component_id="archive_guard",
                    )

                for info in infos:
                    self._validate_member_attributes(info)
                    staged_path = self._resolve_safe_destination(staging_dir, info.filename)
                    final_dest_path = self._resolve_safe_destination(real_target, info.filename)

                    if info.is_dir():
                        os.makedirs(staged_path, mode=0o700, exist_ok=True)
                        os.makedirs(final_dest_path, mode=0o700, exist_ok=True)
                        continue

                    if any(info.filename.lower().endswith(ext) for ext in self.NESTED_ARCHIVE_EXTENSIONS):
                        if current_depth + 1 > self._policy.max_nesting_depth:
                            raise ArchiveSecurityError(
                                f"Nested archive '{info.filename}' exceeds max_nesting_depth ({self._policy.max_nesting_depth}).",
                                vector_id="B.1",
                                component_id="archive_guard",
                            )

                    os.makedirs(os.path.dirname(staged_path), mode=0o700, exist_ok=True)
                    file_written = 0
                    compressed_size = max(1, info.compress_size)

                    open_flags = (
                        os.O_WRONLY
                        | os.O_CREAT
                        | os.O_TRUNC
                        | getattr(os, "O_NOFOLLOW", 0)
                    )
                    try:
                        fd = os.open(staged_path, open_flags, 0o600)
                    except OSError as exc:
                        raise ArchiveSecurityError(
                            f"Failed to open staging descriptor with O_NOFOLLOW for '{info.filename}': {exc}",
                            vector_id="B.2",
                            component_id="archive_guard",
                        ) from exc

                    with zf.open(info, "r") as src, os.fdopen(fd, "wb") as dst:
                        while True:
                            chunk = src.read(self._policy.chunk_size)
                            if not chunk:
                                break
                            file_written += len(chunk)
                            total_written += len(chunk)

                            if file_written > self._policy.max_single_file_bytes:
                                raise ArchiveSecurityError(
                                    f"Entry '{info.filename}' exceeded single-file quota ({self._policy.max_single_file_bytes} bytes).",
                                    vector_id="B.1",
                                    component_id="archive_guard",
                                )
                            if total_written > self._policy.max_total_uncompressed_bytes:
                                raise ArchiveSecurityError(
                                    f"Archive exceeded total uncompressed quota ({self._policy.max_total_uncompressed_bytes} bytes).",
                                    vector_id="B.1",
                                    component_id="archive_guard",
                                )

                            if file_written >= self._policy.ratio_grace_bytes:
                                member_ratio = file_written / compressed_size
                                if member_ratio > self._policy.max_compression_ratio:
                                    raise ArchiveSecurityError(
                                        f"Decompression bomb detected in '{info.filename}': ratio {member_ratio:.1f}:1 exceeds {self._policy.max_compression_ratio}:1.",
                                        vector_id="B.1",
                                        component_id="archive_guard",
                                    )

                            if total_written >= self._policy.ratio_grace_bytes:
                                overall_ratio = total_written / archive_file_size
                                if overall_ratio > self._policy.max_compression_ratio:
                                    raise ArchiveSecurityError(
                                        f"Overlapping decompression bomb detected: archive ratio {overall_ratio:.1f}:1 exceeds {self._policy.max_compression_ratio}:1.",
                                        vector_id="B.1",
                                        component_id="archive_guard",
                                    )

                            dst.write(chunk)

                    self._verify_no_symlink_or_escape(staged_path, staging_dir)
                    os.chmod(staged_path, 0o600)
                    staged_pairs.append((staged_path, final_dest_path))

                # Atomic promotion from staging_dir to real_target after all members pass quotas & realpath checks
                for staged_path, final_dest_path in staged_pairs:
                    self._verify_no_symlink_or_escape(staged_path, staging_dir)
                    dest_parent = os.path.dirname(final_dest_path)
                    os.makedirs(dest_parent, mode=0o700, exist_ok=True)
                    if os.path.islink(dest_parent) or os.path.islink(final_dest_path):
                        raise ArchiveSecurityError(
                            f"TOCTOU symlink race detected at destination '{final_dest_path}'.",
                            vector_id="B.2",
                            component_id="archive_guard",
                        )
                    os.replace(staged_path, final_dest_path)
                    self._verify_no_symlink_or_escape(final_dest_path, real_target)
                    os.chmod(final_dest_path, 0o600)
                    extracted_files.append(final_dest_path)

        except ArchiveSecurityError:
            shutil.rmtree(staging_dir, ignore_errors=True)
            self._purge_directory_contents(real_target)
            raise
        except zipfile.BadZipFile as exc:
            shutil.rmtree(staging_dir, ignore_errors=True)
            self._purge_directory_contents(real_target)
            raise ArchiveSecurityError(
                f"Corrupted or malformed ZIP archive: {exc}",
                vector_id="B.1",
                component_id="archive_guard",
            ) from exc
        finally:
            shutil.rmtree(staging_dir, ignore_errors=True)

        return extracted_files

    @staticmethod
    def _verify_no_symlink_or_escape(file_path: str, root_dir: str) -> None:
        """Verify via lstat and realpath that `file_path` is a regular file strictly inside `root_dir`."""
        if os.path.islink(file_path):
            raise ArchiveSecurityError(
                f"Post-extraction symlink race detected on '{file_path}'.",
                vector_id="B.2",
                component_id="archive_guard",
            )
        st = os.lstat(file_path)
        if not stat.S_ISREG(st.st_mode):
            raise ArchiveSecurityError(
                f"Extracted entry '{file_path}' is not a regular file.",
                vector_id="B.2",
                component_id="archive_guard",
            )
        real_file = os.path.realpath(file_path)
        real_root = os.path.realpath(root_dir)
        if not (real_file == real_root or real_file.startswith(real_root + os.sep)):
            raise ArchiveSecurityError(
                f"Post-extraction canonical path '{real_file}' escaped root '{real_root}'.",
                vector_id="B.2",
                component_id="archive_guard",
            )

    @staticmethod
    def _validate_member_attributes(info: zipfile.ZipInfo) -> None:
        if "\x00" in info.filename:
            raise ArchiveSecurityError(
                "Null-byte injection detected in archive filename.",
                vector_id="B.2",
                component_id="archive_guard",
            )

        unix_mode = info.external_attr >> 16
        if unix_mode:
            if (
                stat.S_ISLNK(unix_mode)
                or stat.S_ISCHR(unix_mode)
                or stat.S_ISBLK(unix_mode)
                or stat.S_ISFIFO(unix_mode)
                or stat.S_ISSOCK(unix_mode)
            ):
                raise ArchiveSecurityError(
                    f"Forbidden symlink or special device file in archive: '{info.filename}'.",
                    vector_id="B.2",
                    component_id="archive_guard",
                )
            if unix_mode & (stat.S_ISUID | stat.S_ISGID):
                raise ArchiveSecurityError(
                    f"Forbidden setuid/setgid bit on archive entry: '{info.filename}'.",
                    vector_id="B.2",
                    component_id="archive_guard",
                )

    @staticmethod
    def _resolve_safe_destination(real_target: str, member_name: str) -> str:
        norm_name = os.path.normpath(member_name)
        if os.path.isabs(member_name) or norm_name.startswith(".."):
            raise ArchiveSecurityError(
                f"Zip-Slip path traversal rejected: '{member_name}'.",
                vector_id="B.2",
                component_id="archive_guard",
            )
        candidate = os.path.realpath(os.path.join(real_target, member_name))
        if not (candidate == real_target or candidate.startswith(real_target + os.sep)):
            raise ArchiveSecurityError(
                f"Canonical path traversal outside target root rejected: '{member_name}'.",
                vector_id="B.2",
                component_id="archive_guard",
            )
        return candidate

    @staticmethod
    def _purge_directory_contents(real_target: str) -> None:
        if not os.path.isdir(real_target):
            return
        for entry in os.listdir(real_target):
            entry_path = os.path.join(real_target, entry)
            if os.path.isdir(entry_path) and not os.path.islink(entry_path):
                shutil.rmtree(entry_path, ignore_errors=True)
            else:
                try:
                    os.unlink(entry_path)
                except OSError:
                    pass
