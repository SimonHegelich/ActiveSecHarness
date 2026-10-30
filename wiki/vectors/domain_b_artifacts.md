# Threat Vector Synthesis – Domain B: Files, Archives & Decompression Bombs

- **Taxonomy Reference:** [`docs/01_threat_taxonomy.md#domain-b`](../../docs/01_threat_taxonomy.md)
- **Primary Mitigating Components:**
  - [`archive_guard`](../components/archive_guard.md) (Real-time streaming ZipBomb ratio/size quota enforcement, canonical path Zip-Slip & symlink rejection)
  - [`deobfuscator`](../components/deobfuscator.md) (Trojan Source Unicode bidirectional control character detection)

## Core Threat Model
Archive headers (`uncompressed_size`) are attacker-controlled and trivially forged. Furthermore, relative paths (`../../`) and embedded symlinks can overwrite sensitive files outside the target directory.

## Enforced Invariants
1. `extractall()` is strictly banned across the entire repository.
2. All archives are extracted in fixed 64 KB chunks while monitoring real-time byte output and compression ratios.
3. Canonical path resolution (`os.path.realpath`) verifies containment inside the target directory prior to opening any file descriptor.
