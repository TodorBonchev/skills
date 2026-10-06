# rust-auditor benchmarks

A scoring set of **public** Solana security codebases and audit reports with **documented** bugs,
so a future rust-auditor run can be measured: point the skill at the scope, and check the report
against the known findings below. Only bugs the source itself documents are listed — nothing here is
invented. "Expected" means "the source says this bug is here", not "the skill is guaranteed to find
it"; a run is scored by recall against these and by false positives outside them.

Each entry pins the **commit / version** it was recorded at. Re-pin before scoring, because the
upstream repos move. Loss figures and severities are the source's own. Educational repos label
severity by bug class (the vulnerable module is deliberately exploitable); audit reports use the
auditor's severity.

Corpus clones used to build this file live under `/workspace/solana-sec-corpus/` (not committed).

---

## 1. Ubuntu-Technologies/solana-security-template — `@cb48608`

Anchor (+ one Pinocchio) vulnerable-vs-secure modules, each with LiteSVM tests; AMM adds Trident
fuzzing. Scope for each row = `programs/<module>/src/vulnerable.rs` (+ `state.rs`, `lib.rs`); the
matching `secure.rs` is the negative control (a run should **not** flag it). Documented bug per
module:

| Module (scope) | Documented bug | Class | Severity |
| --- | --- | --- | --- |
| `signer-authorization` | privileged action with no signer check | B1 | High |
| `owner-check` | account trusted with no owner check | B2 | High |
| `account-type-mismatch` | type cosplay — no discriminator distinguishes layouts | B3 | High |
| `insecure-init` | re-init / first-caller claims config | B4 | High |
| `remaining-accounts` | `ctx.remaining_accounts` used unvalidated | B5-adjacent | High |
| `duplicate-accounts` | two mutable accounts, no `key() !=` constraint | B6 | High |
| `pda-security` | non-canonical / predictable PDA derivation | B7 | High |
| `account-close` | manual lamports-to-zero close, revival possible | B8 | High |
| `arithmetic-overflow` | unchecked arithmetic wraps (overflow-checks off) | B10 | High |
| `account-reloading` | stale account read after CPI (no `reload()`) | B11 | Medium |
| `account-griefing` | predictable `init` PDA pre-funded to DoS the victim | B13 | Medium |
| `authority-transfer` | single-step authority handover, no propose/accept | B14 | High |
| `multisig-payer` | PDA used as `init` payer — always fails (correctness, not a vuln) | — | Informational |
| `amm/buggy-amm` | weak PDA seeds + unchecked overflow + **ignored `min_out` (no slippage)** | B7+B10+B16 | High |

## 2. Abdullateef1x/solana-security-patterns — `@4646ebe`

Five patterns, **each in Anchor and Pinocchio** (scope = `programs/<pattern>/{anchor,pinocchio}/src/vulnerable.rs`).
Note: the repo warns these may not `anchor build` (dependency/IDL drift) — they score the account-map
+ agent review, not the `--poc` build path.

| Pattern | Documented bug | Class | Severity |
| --- | --- | --- | --- |
| `missing-signer-check` | no `is_signer` / no `Signer` | B1 | High |
| `missing-has-one` | account link not enforced (`has_one` missing) | B1/B7 | High |
| `unsafe-arithmetic` | unchecked add/sub on balances | B10 | High |
| `insecure-pda` | PDA accepted without re-derivation / seeds | B7 | High |
| `cpi-authority-misuse` | user-controlled account passed as CPI transfer authority | B5 | High |

## 3. Xzavior34/solana-security-secrets — `@a1963e7`

Educational site + one Anchor program (`anchor/programs/security_secrets/src/lib.rs`) demonstrating
five classes: signer authorization (B1), type cosplay (B3), PDA verification (B7), owner check (B2),
integer overflow (B10). Scope = that `lib.rs`. Severity: High by class. Contributes the CEI
mental model and the Anchor-vs-Pinocchio comparison, not new bug classes.

## 4. HalbornSecurity/CTFs — HalbornCTF_Rust_Solana — `@684f1af`

A **native** (non-Anchor) Solana program: `HalbornCTF_Rust_Solana/ctf_game/ctf/src/{processor,instructions,state,lib}.rs`.
A good native/manual-validation target. **Expected bugs: not published** — it is a CTF requiring a
PoC, so no itemized findings are listed here (not fabricated). Use it to check the account-map and
the native/Pinocchio review do not crash and produce sane leads on hand-rolled account handling.

## 5. Adevar Labs audit reports (external repos; findings documented in the report)

Scope = the audited repo at the commit the report pins; known findings = the report's finding IDs,
severities and file locations. Summarize, do not copy. From `AdevarLabs/audit-reports @d51d21e`:

- **GLAM** — `reports/2025-11-07_GLAM_audit_report.pdf` (audited `glamsystems/glam @bafcfeab…`).
  Documented: 2 High, 2 Medium, 10 Low. Generalizable, locatable findings:
  E06 vault can transfer SOL to any allowed address; **E07 Kamino/Drift deposit/withdraw skip the
  markets allow-list**; **E20 destination account not validated on `ext_drift/.../withdraw.rs`
  (deposit checks it, withdraw doesn't)**; L04 timelock bypass; L10/E14 fee crystallization ordering;
  M01 admin can't burn/force-transfer from non-ATA.
- **Indentura Private Credit Vault** — `reports/2026-02-17_Indentura_Private_Credit_Vault_audit_report.pdf`.
  Documented: 2 High, 2 Medium, 5 Low. **H01/H02 silent u64 overflow in admin/user withdrawal math
  → fund loss**; M01 missing slippage protection in `ACTION_WITHDRAW`; M02 deposit DoS; L04 missing
  `state_vault` check allows reinitialization; L05 broken clock check.
- **M0 MExtensions** — `reports/2025-07-02_M0_MExtensions_audit_report.pdf`.
  Documented: 1 Critical, 3 Medium, 2 Low. **#1 (Critical) missing admin access control on `ext_swap`
  whitelist ops**; #2 retroactive fee application; #3 imprecise multiplier → insolvency; #4 swap
  doesn't forbid same-token swap; #5 `m_ext` init front-running; #6 misaligned Anchor constraint on
  the swap source token account.

## 6. anza-xyz/security-audits — core-component reports — `@4d5d71e`

Scope = the component at the audited version; these are **negative/robustness controls** (core code,
mostly clean):

- **Neodyme P-Token (Pinocchio)** — `spl/NeodymePTokenPinocchioAudit-2025-06-12.pdf`: **0 findings**
  (clean). Use as a false-positive control for a Pinocchio token program, and mine its "Select
  Common Vulnerabilities" list (freeze-authority checks, rent-exemption assertion, account-creation
  DoS, CPI recursion, redeployment cross-instance confusion, log truncation).
- **Certora P-Token formal verification** — `spl/CertoraPTokenFV-2026-05-11.pdf`.
- Zellic/Neodyme stake-program and Token-2022 reports are present for Token-2022 extension review
  context (B12).

## 7. 0xMacro/awesome-solana-security — competitive-audit targets — `@24f792c`

Linked First Flights with documented results (itemized findings on the linked report pages; only the
verified aggregate counts are recorded here, not fabricated specifics):

- **RustFund** First Flight — codehawks.cyfrin.io/c/2025-03-rustfund (170 nSLOC): **4 High, 3 Medium,
  4 Low** (verified on the results page).
- **SSSwap** First Flight — codehawks.cyfrin.io/c/2025-05-ssswap: **5 High, 4 Medium** (per the
  awesome list).

These are good future additions to the scorable set once their code is checked out at the contest
commit and the per-finding list is pulled from the published report.
