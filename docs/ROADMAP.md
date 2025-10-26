# UndownUnlock Master Plan – “Near Level 0” Stealth Roadmap

This document tracks the end‑to‑end plan for making SecurityHooked/UndownUnlock as stealthy as possible without going kernel‑mode. Each phase lists high‑level objectives and concrete TODOs.

---

## Phase 1 – Stealth & Fingerprint Reduction

**Goals:** Make the injected DLL indistinguishable from the target process by removing obvious fingerprints.

### TODOs
1. **Strip exports and banners**
   - Remove unused DLL exports.
   - Ensure no debug banners/MessageBox calls remain in `dllmain`.
2. **Dynamic API resolution**
   - Replace `GetProcAddress`/static imports with hashed imports via custom resolver.
   - Encrypt hash table with per‑build key.
3. **Memory hygiene**
   - After applying hooks/patches, restore original page protections and clear decoded signatures.
   - Add `SecureZeroMemory` on signature buffers after resolving.
4. **Auto‑hibernation**
   - Detect idle periods (no swap chain activity/focus change) and temporarily unhook to reduce exposure.

---

## Phase 2 – Vendor Intelligence

**Goals:** Know exactly what each exam client is doing so we patch only what we must.

### TODOs
1. **Signature telemetry (optional)**
   - Log hashed module/version + signature offsets to encrypted file for later analysis.
2. **Integrity spoofing**
   - Identify and patch CRC/self‑check routines (e.g., `NtQuerySystemInformation` hooking).
3. **Behavior toggles per vendor**
   - Move hook selection into vendor profiles (LockDown vs ProProctor vs ETS/Prometric).
4. **Baseline snapshots**
   - Collect PDB/IDA notes per vendor to accelerate future updates.

---

## Phase 3 – Injection Hardening

**Goals:** Avoid obvious CreateRemoteThread patterns and reduce on‑disk footprint.

### TODOs
1. **Reflective loader**
   - Build small EXE stub that loads DLL from memory (no DLL written to disk).
2. **ETW suppression**
   - Patch `EtwEventWrite`, `NtTraceControl`, `EventWrite` in target to no‑op or fake success.
3. **Thread hiding**
   - Inject via APC/fiber or thread hijacking rather than `CreateRemoteThread`.
4. **Config obfuscation**
   - Move `config.json` into encrypted resource blob decrypted at runtime.

---

## Phase 4 – Monitoring & Update Loop

**Goals:** Know when vendors patch binaries and react quickly.

### TODOs
1. **Beacon/reporting (opt‑in)**
   - Encrypted telemetry summarizing vendor version and success/failure of hooks.
2. **Auto‑update script**
   - CLI (`securityhooked.exe update`) downloads latest release, verifies hash, injects.
3. **Release cadence**
   - Document tag/publish process with checklist (signatures revalidated, telemetry cleared, etc.).

---

## Phase 5 – Testing & Fail‑safes

**Goals:** Ensure we don’t crash exams and we leave minimal traces if anything goes wrong.

### TODOs
1. **Sandbox regression**
   - Spin up mock processes per vendor using real binaries to run smoke hooks in CI.
2. **Fail‑safe mode**
   - If signature resolution fails or anti‑tamper trips, auto‑unhook and unload.
3. **Cleaner**
   - Add an “emergency cleanup” command to remove artifacts, registry keys, and recent files.

---

## How to use this roadmap
1. Pick a phase → create GitHub issues for each TODO bullet.
2. Reference this document in commit messages/PR descriptions to track coverage.
3. Update the “Status” column (add a table later) as tasks get merged.
