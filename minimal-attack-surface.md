# Minimal Attack Surface Check Implementation Plan

## Overview
This plan outlines the implementation of the "Minimal Attack Surface" passive check to fulfill the CRA Annex I §1.3.e requirement. The check will fail a device if it exposes UPnP (TCP 5000 / UDP 1900), SMBv1 (TCP 445/139), or mDNS/Bonjour alongside > 5 other arbitrary ports, indicating an excessively large attack surface.

## Project Type
BACKEND

## Success Criteria
- The `CRAScanner` in `scan_logic.py` includes a `check_minimal_attack_surface(self, device)` method.
- The check returns a standard compliance result dictionary (`{"passed": bool, "details": str}`).
- The check is executed during the compliance phase in `scan_subnet`.
- The `CRAScanner` tests pass and correctly identify minimal vs. excessive attack surfaces.

## Tech Stack
- Python 3.11+
- Nmap port scanning data structure

## File Structure
- `cra_auditor/scan_logic.py` (Core logic modification)
- `cra_auditor/tests/test_scan_logic.py` (Test addition)

## Task Breakdown

### 1. Implement `check_minimal_attack_surface`
- **Agent:** `backend-specialist`
- **Skill:** `python-patterns`
- **Priority:** P0
- **INPUT:** `cra_auditor/scan_logic.py`
- **OUTPUT:** New method `check_minimal_attack_surface` added to `CRAScanner` class.
- **VERIFY:** Method accepts a `device` dictionary, extracts `openPorts`, identifies UPnP/SMB/mDNS ports, and returns a pass/fail dictionary.

### 2. Integrate Check into `scan_subnet`
- **Agent:** `backend-specialist`
- **Skill:** `python-patterns`
- **Priority:** P0
- **Dependencies:** Task 1
- **INPUT:** `cra_auditor/scan_logic.py` (`scan_subnet` method)
- **OUTPUT:** Execute `check_minimal_attack_surface`, evaluate its result in the overall `status` determination, and include it in the `checks` dictionary output.
- **VERIFY:** The final JSON output contains `minimalAttackSurface` in the `checks` dictionary.

### 3. Add Unit Tests for the New Check
- **Agent:** `test-engineer`
- **Skill:** `testing-patterns`
- **Priority:** P1
- **Dependencies:** Task 1, 2
- **INPUT:** `cra_auditor/tests/test_scan_logic.py`
- **OUTPUT:** New test methods for `check_minimal_attack_surface` covering pass and fail scenarios.
- **VERIFY:** `pytest cra_auditor/tests/test_scan_logic.py` passes successfully.

## Phase X: Verification
- [ ] Run `python .agent/skills/lint-and-validate/scripts/lint_runner.py .`
- [ ] Run `pytest cra_auditor/tests/test_scan_logic.py`
- [ ] Manual test: Run `npm run dev` and `python server.py`, execute a mock scan via UI, and verify the new check appears in the backend API response.
