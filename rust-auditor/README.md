# Rust Auditor

A security agent for Solana programs written in Rust - findings in minutes, not weeks.

Covers Anchor, native `solana-program` and Pinocchio programs. It runs the same engine as the
[solidity-auditor](../solidity-auditor/) - 12 parallel attacker agents, dedup, a four-gate
judge, loop mode and a findings memory - with every agent rewritten for the Solana account
model. Before the agents run, a **pre-scan account map** walks every instruction (accounts and
their signer/owner/PDA constraints, cross-program calls, state writes) and auto-highlights review
leads, and each agent carries a catalogue of **real Solana exploit patterns** - Wormhole, Cashio,
Mango, Nirvana and more - mapped to the bug class it hunts, plus **lessons distilled from recent
public audit reports** (GLAM, Indentura, M0, Neodyme's P-Token checklist) and deeper **native /
Pinocchio manual-validation** coverage for programs that don't use Anchor. The agents cover: missing signer and owner checks, account type confusion, PDA seed collisions and
non-canonical bumps, arbitrary CPI, stale accounts after CPI, closed-account revival,
Token-2022 extensions, oracle staleness and integer overflow in release builds.

Built for:

- **Solana devs** who want a security check before every commit
- **Security researchers** looking for fast wins before a manual review
- **Just about anyone** who wants an extra pair of eyes.

Not a substitute for a formal audit - but the check you should never skip.

## Usage

```
Install https://github.com/pashov/skills/ and run rust auditor on the codebase
```

```
run rust auditor on *specified files*
```

```
update skill to latest version
```

More than one run per scan is loop mode. Each run is a full audit, and every run after the first is
told what the earlier ones found, so it hunts new ground instead of the same bugs. You get one
report at the end, not one per run.

```
run rust auditor in loop mode
```

## Verify the real bugs (`--poc`)

Pass `--poc` and, after judging, the skill tries to **prove** each High/Critical finding by writing
and running a regression test in a scratch copy of your project. A bug that reproduces ships with a
failing test you can keep (`PoC: CONFIRMED`); a finding that can't be reproduced drops to a lead
(`PoC: NOT REPRODUCED`), so false positives fall out of the findings list. If the build toolchain
isn't installed it says so rather than guessing (`PoC: UNVERIFIED`). It writes only under
`.rust-auditor/runs/{stamp}/poc/` and **never touches your source or tests**. A plain scan runs no
builds and is unaffected.

```
run rust auditor with --poc
```

## What it scans

By default, the `.rs` files of every on-chain program crate - a crate whose `[dependencies]`
name `anchor-lang`, `solana-program`, `pinocchio` or a related framework crate - plus Rust
deploy and admin scripts under `scripts/`, `deploy/`, `admin/` and `src/bin/`. It skips
`target/`, `.anchor/`, `node_modules/`, `test-ledger/`, `migrations/`, tests, benches, fuzz
harnesses and off-chain client crates. Name any file on the command line to scan it anyway,
including TypeScript deploy scripts.

Every agent also sees a **Build context** header: which framework each crate uses, the exact
framework versions, and whether release builds have `overflow-checks` on (Cargo's release
default is off, so integer overflow wraps in the deployed program). The setting is resolved
**per workspace**: a nested or `exclude`d workspace is reported with its own value.

## The 12 agents

| # | Agent | Focus |
| - | ----- | ----- |
| 1 | math-precision | Wrapping arithmetic without `overflow-checks`, `as` truncation, rounding direction, decimals, share inflation |
| 2 | access-control | Missing signers, init front-running, PDA authorities that sign for anyone, signer forwarding through CPI |
| 3 | economic-security | Pyth / Switchboard staleness and spoofing, Token-2022 extensions, flash loans, address squatting, compute exhaustion |
| 4 | execution-trace | Stale accounts after CPI, write-back clobbering, duplicate accounts, instruction composition and introspection |
| 5 | invariant | Conservation laws, donation, closed-account revival and re-creation, rent and `realloc` |
| 6 | periphery | Validation helpers, layouts and deserialisation, `unsafe`, feature-flagged checks, hardcoded IDs |
| 7 | first-principles | Assumptions with no name - identity, ordering, freshness, existence |
| 8 | asymmetry | Paired instructions, Accounts-struct constraint diffs, Token vs Token-2022 and SOL vs SPL branches |
| 9 | account-validation | Every account of every instruction against eleven questions, every CPI, `remaining_accounts`, instruction data |
| 10 | numerical-gap | Seams between precision, invariants and edges |
| 11 | trust-gap | Seams between access, economics and asymmetry |
| 12 | flow-gap | Seams between execution, external programs and program intent |

## Tips

- **Target hot programs.** Rather than scanning an entire repo, point the tool at the instruction files you're actively changing - plus `state.rs` and the `lib.rs` that dispatches them. Smaller scope means denser context for each agent and higher-signal findings.
- **Use loop mode.** LLM output is non-deterministic — each pass can surface different vulnerabilities. Three passes is a good default: the later ones know what the earlier ones found, and you still get a single report.
- **Read the report file.** Long scans print a short summary in the terminal; every finding and its fix is in `full-report.md`.
- **Benchmarks.** `rust-auditor/evals/` lists public codebases and audit reports with documented bugs (and an `evals.json` in the repo's eval convention), so runs can be scored for recall and false positives over time. Strip comments from the in-scope files of a benchmark copy first — template comments name the bugs: `python3 rust-auditor/evals/strip-comments.py --in-place --list scope.txt` (see `evals/benchmarks.md` §0).
- **Ignore `.rust-auditor/` in git.** Every scan writes its run files there, and `--memory` keeps a findings ledger there.

## Changelog

**1.3**
- **Correctness lane.** An instruction that fails for every caller, an always-true or never-true
  constraint, a byte offset that misreads the struct layout, or a two-leg route with no
  `from != to` is now a finding (confidence 75, with a fix, title `Correctness: …`) instead of a
  lead — `judging.md` Gate 4, mirrored in `dedup-and-assembly.md`, `report-formatting.md`,
  `shared-rules.md` and both agent prompts.
- **Admin rules.** A stubbed privileged instruction (`msg!` / `Ok(())`) behind a real access
  defect is judged by the impact its name states. An honest admin call that is irreversible
  (single-step authority transfer, unbounded bricking setter) or retroactive (fee / index / mint
  change with no settle) clears gate 3 without an unprivileged amplifier.
- **Layout check.** Agents lay hand-coded offsets against the `#[repr(C)]` / packed layout;
  `account-map.py` raises `offset-mismatch`, and `key-compared-no-signer` for a key compared with
  stored data and no `is_signer`.
- **Rounding.** `f64` rounding past 2^53 and float-to-int saturation in the math-precision and
  numerical-gap agents and in judging's safe-pattern caveat; new pattern **B17** same-asset round
  trip (self-swap) for the asymmetry, flow-gap, economic and account-validation agents.
- **Per-workspace overflow checks.** The Build context walks each crate up to its own workspace
  root (honouring `exclude`) and prints every root when they differ.
- **Account-map noise.** Constant-seed singletons fold to one `singleton-init` (or
  `singleton-write`) lead, constant / parent-scoped CPI signer seeds to one `global-signer` lead
  per program; foreign (`seeds::program`) and parent-keyed child PDAs raise nothing;
  `stale-after-cpi` skips `lamports()` reads and System-program-only CPIs; signer-seed
  expansion now follows `let seeds = &[ctx.accounts…]`, `Signer::from(&seeds)` and
  `signer = &[&seeds[..]]` (Pinocchio caller-chosen bumps are caught). M0: 41 → 22 leads.
- **Benchmarks.** Three template rows corrected (account-close and account-reloading not
  present, arithmetic-overflow panics), found-by-skill additions re-confirmed in code, M0 pinned
  to the pre-fix commit `25e29e1`, leakage hygiene, and `evals/strip-comments.py`.

**1.2** — audit lessons (Part C), bug classes B13–B16, native/Pinocchio depth, `check-deferred`
lead, benchmarks. **1.1** — `--poc` verification, account map, exploit-pattern catalogue.
**1.0** — the solidity-auditor engine ported to Rust/Solana with 12 agents.
