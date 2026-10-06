# Finding Validation

Every finding passes four sequential gates. Fail any gate → **rejected** or **demoted** to lead. Later gates are not evaluated for failed findings.

You are not defending the code. The job of these gates is to verify the attacker's claimed exploit actually fires end-to-end — anything that interrupts the attack between the attacker's transaction and the harm means the agent's claim does not execute, and only then does it fail to qualify as a finding.

## Gate 1 — Attack execution

Trace the agent's claimed attack path from the attacker's transaction to the harm. Read every guard that sits on that path: Anchor account types (`Account<'info, T>`, `Signer`, `Program<'info, T>`, `Interface`, `InterfaceAccount`, `Sysvar`), Anchor constraints (`has_one`, `address`, `owner`, `seeds` + `bump`, `constraint = …`, `token::mint`, `token::authority`, `associated_token::*`), `require!` / `require_keys_eq!` and explicit checks in the handler, and native checks (`is_signer`, `owner == program_id`, key comparisons). Then the runtime rules nothing in the program can turn off: an account the program does not own cannot be written or debited by it, a signer must really sign, a PDA can only be signed for by its own program, and a failed instruction rolls back the whole transaction. Confirm that none of these interrupts the attack before the exploit step fires.
- A specific guard / constraint / runtime rule on the attack path interrupts the claimed exploit step before harm occurs (quote the exact line or rule and trace it) → **REJECTED** (or **DEMOTE** if a related code smell remains)
- The supposed interruption is speculative ("the client always passes the right account", "the frontend derives the PDA", "the admin would set X", "nobody would build that transaction") → **clears**, continue. **The client is not a guard.** Any account list and any instruction data can be sent by anyone.

## Gate 2 — Reachability

Prove the vulnerable state exists in a live deployment.

- Structurally impossible (enforced invariant or runtime rule prevents it) → **REJECTED**
- Requires privileged actions outside normal operation → **DEMOTE**
- Achievable through normal usage, through instructions composed in one transaction, or through common mint behaviors (Token-2022 transfer fees and hooks, freeze authority, a closed and re-created account at the same address) → **clears**, continue

## Gate 3 — Trigger

Prove an unprivileged actor executes the attack.

- Only trusted roles can trigger (admin, upgrade authority, a whitelisted keeper) → **DEMOTE**
- Unprivileged actor triggers profitably → **clears**, continue

**Admin-action findings — reject unless an unprivileged amplifier is named.** This applies ONLY to actions performed by the admin, the config authority or the upgrade authority, NOT to unprivileged attacker actions. If the harm requires the admin acting maliciously or against documented intent, **REJECT** — do not even emit as a LEAD (stricter than the DEMOTE above). The finding clears only when the body names a concrete unprivileged amplifier:

- **race** — the admin sets X mid-flow; an unprivileged user exploits the window, for example in the same slot, before the update reaches every account that caches X.
- **retroactive sweep** — an admin update rewrites a pending value already credited.
- **asymmetric formula** — admin output chains into a formula an unprivileged actor profits from.
- **access gap** — a missing `Signer`, a missing owner or `has_one` check, a tautological check (`constraint = config.admin == config.admin`), an `initialize` anyone can call first, or an upgrade-authority check that reads a spoofable account (the access mechanism itself is the bug).

No amplifier named → **REJECTED**. Amplifier named → judge it on that unprivileged path.

## Gate 4 — Impact

Prove material harm to an identifiable victim.

- Self-harm only (the caller passes their own wrong account and loses their own tokens) → **REJECTED**
- Dust-level, no compounding (a few lamports, one base unit of a token) → **DEMOTE**
- Material loss to an identifiable victim — tokens or lamports taken from a vault or another user, an account taken over, a mint inflated, an instruction that fails for every caller so funds stay locked → **CONFIRMED**

## Confidence

Start at **100**, deduct: partial attack path **-20**, bounded non-compounding impact **-15**, requires specific (but achievable) state **-10**. Confidence ≥ 75 gets description + fix. Below 75 gets description only.

**The threshold is 75, and it is set here.** `report-formatting.md` reads it from this line and states it nowhere else. It is 75 and not 80 because the three lead-promotion rules below all land a promoted lead at exactly 75: at a threshold of 80 every cross-program echo, every multi-agent convergence and every completed partial path would be promoted to a finding and then printed with no **Fix** block. Moving this number means moving those three, or the promotions stop being worth making.

**Integer overflow depends on the Build context.** Read `Release overflow checks` at the top of `source.md`. When it is **not set** or **OFF**, `+`, `-` and `*` on integers wrap silently in the deployed program and an overflow finding is scored like any other value bug. When it is **on**, the same overflow panics and the transaction fails, so the impact is that the instruction fails for that input — score it as a denial of service, not as a wrong value, unless the panic blocks other users' funds. `as` casts truncate and `wrapping_*` wraps **in every build**, whatever the setting.

## Safe patterns (do not flag)

- `checked_add` / `checked_sub` / `checked_mul` / `checked_div` with the `None` case returned as an error (but verify a `.unwrap()` on it is not a panic an attacker can reach to block other users)
- Plain arithmetic when the Build context says release overflow checks are **on** (it panics, it does not wrap) — but `as` casts and `wrapping_*` still wrap
- `u64::try_from(x)?`, `x.try_into()?` (checked narrowing)
- Anchor `Account<'info, T>` for owner + discriminator, `Signer<'info>` for the signature, `Program<'info, T>` for the program ID, `Sysvar<'info, T>` for the sysvar address, `InterfaceAccount` / `Interface` for an owner or program in the allowed set — for exactly what each one checks and nothing more (an `Account<TokenAccount>` proves it is a token account, not **which** token account)
- `seeds` + `bump` constraints that use the canonical bump (`bump` in an `init`, or a stored `bump = state.bump` that was written from `ctx.bumps` / `find_program_address`)
- `init` (not `init_if_needed`) for accounts that must be created once
- Anchor `close = target` in a framework version that also zeroes the data and reassigns the account (verify the version in the Build context before you call a close safe)
- `transfer_checked` with the mint and its decimals; `get_price_no_older_than` with a bounded age and a checked feed ID
- `load_instruction_at_checked` / `Sysvar<'info, Instructions>` for instruction introspection
- Two-step authority transfer (propose, then accept by the new authority's signature)
- Consistent protocol-favoring rounding unless compounding or zero-rounding

## Lead promotion

Before finalizing leads, promote where warranted:

- **Cross-program echo.** Same root cause confirmed as FINDING in one instruction or program → promote in every instruction and program where the identical pattern appears (the same unchecked account type taken by another instruction, the same seeds used by another PDA).
- **Multi-agent convergence.** 2+ agents flagged same area, lead was demoted (not rejected) → promote to FINDING at confidence 75.
- **Partial-path completion.** Only weakness is incomplete trace but path is reachable and unguarded → promote to FINDING at confidence 75, **description only — a deliberate exception to the threshold**. 75 clears the line, so this finding would otherwise carry a **Fix** block; it does not, because the trace it would fix was never completed. The other two promotions above take their **Fix** block normally.

## Leads

High-signal trails for manual investigation. No confidence score, no fix — title, code smells, and what remains unverified.

## Do Not Report

Clippy lints, compiler warnings, compute-unit micro-optimisations, naming, doc comments. Admin privileges by design. Missing `emit!` events or `msg!` logs. Centralisation without an exploit path — "the upgrade authority can replace the program" is not a finding unless the upgrade authority itself is unprotected. EVM-only classes the Solana runtime prevents: cross-program reentrancy (the runtime rejects A → B → A; only direct self-recursion is allowed). Implausible preconditions (but Token-2022 mints with transfer fees, transfer hooks, a permanent delegate or a freeze authority, mints with unusual decimals, and accounts closed and re-created at the same address ARE plausible for programs that accept any mint or any account).
