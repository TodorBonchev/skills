# Proof-of-concept verification — the `--poc` flag

**Off by default.** A plain scan never reaches this file. `--poc` turns on an **opt-in** step
that runs after judging (Turn 4) and before the report (Turn 5): for each **High/Critical**
finding, the skill tries to write one regression test that demonstrates whether the reported bug
is real, runs it, and labels the finding by the result. A confirmed bug ships with a failing test
the developer keeps as a regression test after they fix it; a bug that cannot be reproduced is
dropped to a lead or rejected, cutting false positives.

> **This step never touches the user's source or tests.** It writes only under
> `.rust-auditor/runs/{stamp}/poc/`, and when a build needs the program it copies the repo to a
> scratch workspace **outside** the repo and builds there. The READ-ONLY rule in
> `agent-prompts.md` still binds the 12 agents; this verification step is the orchestrator's, it
> runs after the agents are done, and it is the one place a build is allowed — in scratch, never
> in the audited tree. A later editor must not let it build in the repo or edit the developer's
> files.

## When it runs, and on what

- Only when `--poc` was passed. Without the flag, skip this file entirely.
- Only on findings the gate scored **High or Critical** (confidence ≥ 90; treat ≥ 90 as the
  High/Critical band this skill judges). Mediums, lows and leads are not verified — a PoC budget
  spent on a low is a budget not spent on a critical.
- One PoC per finding, in gate-sorted order (highest confidence first), until the **budget**
  below is spent. Findings not reached stay `UNVERIFIED`.

## Labels — written into judging, the report and assemble.sh

Every High/Critical finding under `--poc` carries exactly one label:

- **CONFIRMED** — a test built and ran that demonstrates the bug (the attack transaction
  succeeds, or the invariant breaks, exactly as the finding claims). Keep the finding; attach the
  test path. Confidence is unchanged — a confirmed bug is not more than 100.
- **NOT REPRODUCED** — a faithful test built and ran, and the bug did **not** occur (the attack
  was rejected, the guard held). This is strong evidence of a false positive: **demote the
  finding to a lead** and say why in one line (what the test did and what blocked it). Do not
  silently drop it — a NOT REPRODUCED lead tells the developer the skill checked and the path
  held.
- **UNVERIFIED** — no faithful test could be built or run inside the budget (toolchain missing,
  the harness could not model the state, the build failed for reasons unrelated to the bug, or the
  budget ran out). **Keep the finding at its gated confidence** — UNVERIFIED is "not checked", not
  "disproven". Say in one line why it could not be verified.

These three labels are the only verification outcomes. They are written in the run-file finding
block (see `dedup-and-assembly.md`), surfaced on the report meta line by `assemble.sh`, and must
never be invented by the model at report time — the label comes from the PoC run.

## Harness choice

Pick the lightest harness that can model the bug:

1. **LiteSVM** (preferred, Anchor and native). In-process SVM, no validator, fast (seconds).
   Load the built `.so` with `svm.add_program_from_file(program_id, path)`, set up accounts with
   `svm.set_account` / `svm.airdrop`, send the attack transaction, assert on balances/data. Best
   for multi-instruction attacks and for "anyone can call this" signer bugs.
2. **Mollusk** (single-instruction, native / Pinocchio). Minimal harness that invokes one
   instruction against a set of accounts and checks the result. Use it when the bug is one
   instruction and LiteSVM's transaction machinery is more than you need.
3. **solana-program-test / `anchor test`** (fallback). Heavier (BanksClient, or a full
   `anchor test` with a local validator). Use only when LiteSVM/Mollusk cannot model the state —
   e.g. a bug that needs real sysvar/clock behaviour or a CPI to a program you can only get from
   the cluster. Slower; respect the budget.

Prefer LiteSVM unless there is a concrete reason it cannot express the attack. Quote the reason in
the UNVERIFIED/CONFIRMED note when you fall back.

## Building the program

The PoC needs the compiled program as an `.so`:

- **Anchor:** `anchor build` (writes `target/deploy/<prog>.so` and the IDL), or `cargo build-sbf`
  when Anchor's CLI is absent.
- **Native / Pinocchio:** `cargo build-sbf --manifest-path <crate>/Cargo.toml`.

**Build in a scratch copy, never in the repo.** Copy the repo to a temp dir
(`mktemp -d`), excluding `target/`, `.git/` and `node_modules/`, build there, and point the
harness at the scratch `.so`. The harness Cargo project (the test itself) lives under
`.rust-auditor/runs/{stamp}/poc/<finding-id>/` with its own `[workspace]` line so it never joins
the audited repo's workspace; it reads the `.so` path from an env var
(`POC_PROGRAM_SO=/scratch/.../<prog>.so`). Keeping the test crate under the runs directory means
the developer can read and reuse it; keeping the *build* in scratch means the audited tree is
never written.

## Time and attempt budget

PoC is expensive; cap it so a `--poc` scan cannot run away:

- **≤ 2 build attempts per finding**, and **≤ ~5 min wall-clock per finding** (build + run). An
  SBF build from a cold cache can take minutes; a warm rebuild and a LiteSVM run are seconds.
- **≤ ~20 min total** across all findings in one scan. When the total budget is spent, every
  remaining High/Critical finding is `UNVERIFIED` with "PoC budget exhausted".
- One harness build of the program is shared across findings in the same program — build the
  `.so` once, reuse it for every finding in that crate.
- If the first harness choice fails to build for a reason unrelated to the bug (a dependency, a
  version mismatch), try the next lighter harness once, then stop and mark `UNVERIFIED`.

## Toolchain detection — report, never install silently

Before any build, probe the toolchain and **do not install anything without saying so**:

```bash
command -v cargo-build-sbf || ls "$HOME/.local/share/solana/install/active_release/bin/cargo-build-sbf"
command -v anchor
command -v rustup   # cargo-build-sbf shells out to rustup; without it the SBF build fails
```

- If `cargo-build-sbf` (the Solana/Agave toolchain) is **absent**, mark every High/Critical
  finding `UNVERIFIED` with "no Solana build toolchain (cargo-build-sbf) found — install the
  Agave/Solana CLI to enable --poc", and **do not** attempt a silent install. Print the one-line
  install hint; let the developer decide.
- If `anchor` is absent but `cargo-build-sbf` is present, fall back to `cargo build-sbf` for
  Anchor programs (you lose the IDL, but LiteSVM only needs the `.so` and the instruction
  discriminator, which is `sha256("global:<ix>")[..8]`).
- If `rustup` is absent, `cargo-build-sbf` fails with "Failed to execute rustup"; put
  `~/.cargo/bin` on `PATH` or report `UNVERIFIED` with that reason.
- **Missing crates** (`litesvm`, `mollusk-svm`, `solana-*`) are ordinary `cargo` dependencies of
  the *test crate under the runs dir*, not global installs — `cargo` fetches them on first build.
  That is not a "silent install" of a toolchain; it is the test's own `Cargo.toml`. A sandbox with
  no network makes even that fail — then mark `UNVERIFIED` with "no network to fetch test
  dependencies".

## Anchor discriminators without the IDL

A LiteSVM test calls an instruction by raw bytes. The 8-byte discriminator is
`sha256("global:<snake_case_ix_name>")[..8]`; an account discriminator is
`sha256("account:<StructName>")[..8]`. Compute them in the test with `sha2` so the PoC does not
need the IDL.

## What a PoC must and must not claim

- A CONFIRMED PoC must demonstrate the **finding's own claim** — the attacker's transaction
  succeeds and the harm occurs (funds move, an account is taken over, an invariant breaks). A test
  that merely "runs the instruction" proves nothing; assert the harmful end state.
- A PoC that needs a precondition the finding did not establish (a specific unlikely account
  state) and cannot reach it is `UNVERIFIED`, not CONFIRMED.
- Never weaken the gate with a PoC: a CONFIRMED label does not raise confidence above the gate's
  number, and a NOT REPRODUCED demotes rather than deletes. The gate decided severity; the PoC
  decides reproducibility.

## This box

A one-shot end-to-end check of this flow was run on this box against a sealevel-attacks
closing-accounts example (the `insecure` close with no signer and a manual lamports-to-zero
"close"). The example was modernized to a current Anchor version because the original repo pins
Anchor 0.20.1, whose old `getrandom` does not build on the current SBF toolchain — a real
toolchain-drift case a reviewer will hit, and the reason the PoC step builds a scratch copy and
reports build failures as `UNVERIFIED` rather than pretending. The LiteSVM test built the program
with `cargo build-sbf`, loaded the `.so`, funded a victim `Data` account owned by the program,
and sent the `close` instruction signed only by an unrelated attacker key: the attacker drained
the victim's lamports and the transaction succeeded — **CONFIRMED**. See the run notes in the
task report.
