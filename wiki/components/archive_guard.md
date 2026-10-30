# Component Security Assessment: `archive_guard`

> **Auto-Generated & Verified by `tools/wiki_sync.py`** — Do not edit manual status badges directly; update the `ComponentSecurityAssessment` contract in [`src/activesec/guards/archive_guard.py`](../../src/activesec/guards/archive_guard.py) or the security test suite in [`tests/security/test_sec_archive_guard.py`](../../tests/security/test_sec_archive_guard.py).

---

## 1. Security Posture Metadata

| Attribute | Value |
| :--- | :--- |
| **Component ID** | `archive_guard` |
| **Title** | Ring-0 Archive Decompression Bomb & Path Traversal Guard |
| **Privilege Ring** | **Ring 0** |
| **Mitigated Threat Vectors** | `B.1`, `B.2` |
| **Source File** | [`src/activesec/guards/archive_guard.py`](../../src/activesec/guards/archive_guard.py) (`sha256:31fe4b95ec58`) |
| **Dedicated Security Test Suite** | [`tests/security/test_sec_archive_guard.py`](../../tests/security/test_sec_archive_guard.py) |
| **AST Static Safety Audit** | **CLEAN (Zero Forbidden Primitives)** |
| **Adversarial Security Verification** | **VERIFIED (PASS)** (4 test vectors) |

---

## 2. Architectural Summary

Protects the harness against flat and recursive decompression bombs (ZipBombs), spoofed ZIP headers, Zip-Slip relative path traversal, and malicious symlinks/device nodes.

---

## 3. Enforced Deterministic Security Invariants

- Never invokes zipfile.extractall() or tarfile.extractall().
- Streams decompression in 64 KB chunks while counting actual uncompressed bytes against max_single_file_bytes, max_total_uncompressed_bytes, and max_compression_ratio.
- Rejects symlinks, FIFOs, character/block devices, and setuid/setgid bits via Unix external attributes.
- Resolves canonical target paths via os.path.realpath() and cleans up the target directory on any violation.

---

## 4. Dedicated Component Security Tests (`tests/security/test_sec_archive_guard.py`)

| Test Function | Verified Adversarial Vector & Invariant | Status |
| :--- | :--- | :--- |
| `test_sec_high_ratio_zip_bomb_blocked_and_purged` | [Vector B.1: Decompression Bomb] Detects and aborts a high-ratio deflate bomb mid-stream. | **PASS** |
| `test_sec_zip_slip_path_traversal_blocked` | [Vector B.2: Zip-Slip Path Traversal] Blocks relative ../ and absolute paths in ZIP entries. | **PASS** |
| `test_sec_symlink_and_setuid_in_archive_blocked` | [Vector B.2: Symlink & Special File Attack] Rejects symlinks and setuid bits inside archives. | **PASS** |
| `test_sec_recursive_nested_archive_limit_enforced` | [Vector B.1: Recursive ZipBomb] Blocks nested archives exceeding max_nesting_depth. | **PASS** |

---

## 5. Known Residual Risks & Defense-in-Depth Pairing

- CPU time spent decompressing up to the configured quota before threshold termination (bounded by SandboxGuard wall-clock timeout).
