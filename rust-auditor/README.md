# Rust Auditor

A security agent for Solana programs written in Rust - findings in minutes, not weeks.

Covers Anchor, native `solana-program` and Pinocchio programs. It runs the same engine as the
[solidity-auditor](../solidity-auditor/) - 12 parallel attacker agents, dedup, a four-gate judge,
loop mode and a findings memory - with every agent rewritten for the Solana account model.

Two things are specific to Solana:

- **Account map.** Before the agents run, a script maps every instruction - its accounts and their
  signer / owner / PDA constraints, its cross-program calls and the state it writes - and highlights
  review leads such as an authority written with no signer check or a CPI to a program ID that is
  not pinned. On native and Pinocchio code it follows checks made in helpers and in typed account
  constructors, so they do not raise false leads.
- **Exploit patterns.** Every agent carries a catalogue of real Solana incidents (Wormhole, Cashio,
  Crema, Mango, Loopscale and more), published bug classes and lessons from public audit reports,
  each with its source, mapped to the agent that hunts it.

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
harnesses and off-chain client crates (RPC crates under `[dev-dependencies]` or a host-only
`cfg(not(target_os = "solana"))` table do not make a program a client). Name any file on the command line to scan it anyway,
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
| 8 | asymmetry | Paired instructions, Accounts-struct constraint diffs, Token vs Token-2022 and SOL vs SPL branches, settings fields a setter never writes |
| 9 | account-validation | Every account of every instruction against eleven questions, every CPI, `remaining_accounts`, instruction data |
| 10 | numerical-gap | Seams between precision, invariants and edges, including a fee base that changes on a capped fill |
| 11 | trust-gap | Seams between access, economics and asymmetry |
| 12 | flow-gap | Seams between execution, external programs and program intent |

## Tips

- **Target hot programs.** Rather than scanning an entire repo, point the tool at the instruction files you're actively changing - plus `state.rs` and the `lib.rs` that dispatches them. Smaller scope means denser context for each agent and higher-signal findings.
- **Use loop mode.** LLM output is non-deterministic — each pass can surface different vulnerabilities. Three passes is a good default: the later ones know what the earlier ones found, and you still get a single report.
- **Read the report file.** Long scans print a short summary in the terminal; every finding and its fix is in `full-report.md`.
- **Benchmarks.** `evals/` lists public Solana codebases and audit reports with documented bugs, so a run can be scored for recall and false positives. Strip comments from a benchmark copy first - educational repos name the bug in a comment (`evals/benchmarks.md`, section 0).
- **Ignore `.rust-auditor/` in git.** Every scan writes its run files there, and `--memory` keeps a findings ledger there.

## Changelog

**1.6** - A correctness or economic candidate is not dropped as "by design" or as self-harm unless
the source states that intent. Otherwise it is a lead that names the assumption. An outsider who
makes a privileged or one-shot instruction fail clears Gate 3 (privileged-op griefing). New bug
class B26: an account another program creates, which an outsider can create first. A fee base must
match the amount actually applied on every branch, and a phased formula is evaluated at each
boundary from both sides. A `lamports()` check against a tracked reserve subtracts the rent-exempt
minimum. A settings setter is diffed field by field against init and against later reads. The
catalogue is 48 entries.

**1.5** - Dedup compares fixes before it merges two bug-class labels: different fixes stay two
items. New bug classes B23-B25: a mint closed and re-created after an allow-time extension check, a
user's signer forwarded to a program the user did not choose (now an access gap in judging), and a
shorter variable-length rewrite that leaves a stale tail. Missing defences with no path today go out
as `hardening-` leads that are never promoted; paired hooks and callbacks are checked for equal
context; an honest-admin hazard users can recover from is scored as bounded. The account map follows
native and Pinocchio idioms: signer and owner checks in helpers, typed account structs validated in
their constructor, program names from `Cargo.toml`, and generic handler names qualified by module.

**1.4** - Solana facts in the agents checked against Anchor, SPL Token, Pinocchio and System-program
source (account close, write-back, `init_if_needed`, bumps, rent, discriminator overrides,
Token-2022 extensions, instruction introspection, return data). New bug classes B18-B22: exit paths
that depend on an account another party controls, `close =` to an unconstrained destination, System
transfers out of a data-carrying PDA, token custody that leaves a `close_authority` behind, and
variable-length seeds that run together. New account-map leads (`foreign-dependency`,
`close-to-unchecked`), raw writes through borrowed account data counted as state changes, signer
leads that must each end in a finding or a stated rejection, and a worked-example rule for float
rounding direction. PoC demotion now survives a multi-pass report, and discovery no longer drops a
program that lists RPC crates in a host-only target table. Version stamps and tuning notes removed
from the agent files; pattern ownership is consistent between the catalogue and the agents.

**1.3** - Correctness lane, honest-admin and stubbed-instruction rules, per-workspace overflow
checks, hand-offset layout check, same-asset round trip (B17). **1.2** - Lessons from public audit
reports (Part C), B13-B16, native and Pinocchio depth. **1.1** - `--poc` verification, account map,
exploit-pattern catalogue. **1.0** - the solidity-auditor engine ported to Rust and Solana.
