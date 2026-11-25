# Aegis Enterprise AI — Technical Architecture & Security Packet

## Core Security Invariants

1. **Non-Human Identity Delegation (RFC 8693):** Agents never impersonate humans. Every agent request carries `sub` (verified human principal), `act.sub` (SPIFFE ID of the acting agent), `jti` (revocable UUID), `clearance` (`min(human.clearance, agent.max_clearance)`), and `exp - iat <= 300`.
2. **Database-Kernel Isolation (PostgreSQL `FORCE ROW LEVEL SECURITY`):** Retrieval connections execute `SET LOCAL ROLE aegis_app_runtime` (`NOBYPASSRLS`) and bind identity strictly via parameterized `set_config(..., is_local := true)` calls sourced from verified JWT claims.
3. **Defense-in-Depth Dual RLS Policies:**
   - `aegis_rebac_positive_grant` (`AS PERMISSIVE`): Requires an explicit `viewer`/`editor`/`owner` tuple in `rebac_tuples` for the user or one of their verified IdP groups.
   - `aegis_mandatory_zero_trust_guard` (`AS RESTRICTIVE`): Enforces hard `tenant_id` match, hierarchical Mandatory Access Control (`clearance_required <= current_clearance`), and explicit Investment Banking Information Barrier (`ethical_wall_deny`) exclusions.
4. **Cryptographic & Kernel-Immutable Audit Trail:** Every token exchange, denial, revocation, and retrieval appends a `SHA256(prev_hash || canonical_json)` record to `audit_ledger`, guarded by PostgreSQL `BEFORE UPDATE OR DELETE OR TRUNCATE` triggers (`SQLSTATE 55000`).
