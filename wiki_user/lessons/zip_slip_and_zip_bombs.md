# Security Academy Lesson: Archive Safety: Zip-Slip Path Traversal & Decompression Bombs (ZipBombs)

- **Topic ID:** `zip_slip_and_zip_bombs`
- **Related Threat Taxonomy Vectors:** `B.1`, `B.2`
- **Your Current Academy Level:** **Level 1: Security Foundations (Plain-Language & Everyday Analogies)**

---

## 1. Everyday Analogy (Why Does This Matter?)

Imagine receiving a small moving box labeled 'Office Supplies'. When you open it,  two things can go wrong: 1) An item inside has an address label saying 'Put this directly into the home safe in the bedroom' (Zip-Slip), or 2) The box contains a compressed inflatable raft that instantly expands to fill your entire house until the walls burst (ZipBomb).

---

## 2. What Is the Security Problem in Plain Language?

Standard archive helpers like Python's `zipfile.extractall()` trust the filenames and sizes stored inside the ZIP file. However, an attacker controls those filenames and headers! A filename like `../../.bashrc` can escape the destination folder and overwrite startup scripts (Zip-Slip), and a 40 KB file of compressed zeroes can expand into gigabytes of data that freeze your computer (ZipBomb).

### How Attackers & Social Engineers Use This Against You
Attackers often share 'helpful test fixtures', 'dataset.zip', or 'starter templates' in GitHub issues or forums and ask you (or your AI coding assistant) to unpack them. Even small local AI models frequently write `zf.extractall()` because it is the shortest code snippet in their training data.

---

## 3. Your Personal Practice Checklist

- [x] Never accept `zf.extractall()` or `tar.extractall()` in generated code.
- [x] Always check that `os.path.realpath()` is used to lock files inside the target folder.
- [x] Verify that archive extraction reads in bounded chunks with a maximum byte and ratio limit.

---

> *Tip: Complete 3 security cases in ActiveSecHarness to unlock **Level 2: Secure Engineering Patterns** on this page!*

---

## Hands-On Cases from Your Workspace

_No live cases recorded for this topic yet._
