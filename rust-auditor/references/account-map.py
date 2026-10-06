#!/usr/bin/env python3
"""rust-auditor account-map pre-scan.

Reads the in-scope .rs files and writes a Markdown account map: one entry per
instruction handler (accounts, signer/mut/owner/type, PDA seeds and bump source,
init/close, constraints, CPIs, state written, gating) plus an auto-highlighted
"Review leads" section. The map is a list of LEADS for the hacking agents, never a
list of findings.

Python 3.8+ standard library only. No network, no writes except --out.

  python3 account-map.py --out .rust-auditor/runs/STAMP/account-map.md FILE...

Anchor (#[derive(Accounts)] + #[program]) is parsed structurally. Native
solana-program and Pinocchio handlers are parsed heuristically; any cell the
script cannot settle is written as `?`, and the handler is listed under
"Needs completion" so a model can finish it from the source.
"""
import os
import re
import sys

# --------------------------------------------------------------------------
# Lexing helpers
# --------------------------------------------------------------------------

def mask(text):
    """Blank comments and string/char literal contents (same length, newlines
    kept) so brace matching and regexes never see code inside them."""
    out = list(text)
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            for k in range(i, j):
                out[k] = " "
            i = j
        elif text.startswith("/*", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if text.startswith("/*", j):
                    depth += 1; j += 2
                elif text.startswith("*/", j):
                    depth -= 1; j += 2
                else:
                    j += 1
            for k in range(i, j):
                if out[k] != "\n":
                    out[k] = " "
            i = j
        elif c == "r" and re.match(r'r#*"', text[i:i + 10]) and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_")):
            m = re.match(r'r(#*)"', text[i:])
            hashes = m.group(1)
            end = text.find('"' + hashes, i + len(m.group(0)))
            end = n if end < 0 else end
            for k in range(i + len(m.group(0)), end):
                if out[k] != "\n":
                    out[k] = " "
            i = end + 1 + len(hashes)
        elif c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            for k in range(i + 1, min(j, n)):
                if out[k] != "\n":
                    out[k] = " "
            i = j + 1
        elif c == "'":
            # char literal vs lifetime: 'a' or '\n' is a literal, 'info is a lifetime
            m = re.match(r"'(\\.|[^\\'])'", text[i:i + 6])
            if m:
                for k in range(i + 1, i + len(m.group(0)) - 1):
                    out[k] = " "
                i += len(m.group(0))
            else:
                i += 1
        else:
            i += 1
    return "".join(out)


PAIRS = {"(": ")", "[": "]", "{": "}"}


def match_close(s, open_idx):
    """Index of the bracket closing s[open_idx] (on masked text)."""
    o = s[open_idx]
    c = PAIRS[o]
    depth = 0
    for k in range(open_idx, len(s)):
        if s[k] == o:
            depth += 1
        elif s[k] == c:
            depth -= 1
            if depth == 0:
                return k
    return len(s) - 1


def split_top(s, sep=",", angle=False):
    """Split on sep at bracket depth 0. angle=True also counts <> (types)."""
    parts, depth, cur = [], 0, []
    opens, closes = "([{", ")]}"
    if angle:
        opens += "<"; closes += ">"
    prev = ""
    for ch in s:
        if ch in opens:
            depth += 1
        elif ch in closes and not (ch == ">" and prev == "-"):
            depth -= 1
        if ch == sep and depth == 0:
            parts.append("".join(cur)); cur = []
        else:
            cur.append(ch)
        prev = ch
    if "".join(cur).strip():
        parts.append("".join(cur))
    return [p.strip() for p in parts if p.strip()]


def squash(s, limit=110):
    s = re.sub(r"\s+", " ", s).strip()
    return s if len(s) <= limit else s[: limit - 1] + "…"


def cell(s, limit=110):
    return squash(s, limit).replace("|", "\\|") if s else "—"


def line_of(text, idx):
    return text.count("\n", 0, idx) + 1


# --------------------------------------------------------------------------
# Source model
# --------------------------------------------------------------------------

class Src:
    def __init__(self, path):
        self.path = path
        with open(path, encoding="utf-8", errors="replace") as fh:
            self.text = fh.read()
        self.m = mask(self.text)
        self._drop_test_mods()
        self.crate = crate_name(path)

    def _drop_test_mods(self):
        for mt in list(re.finditer(r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]\s*(pub\s+)?mod\s+\w+\s*\{", self.m)):
            ob = mt.end() - 1
            cb = match_close(self.m, ob)
            blank = "".join("\n" if ch == "\n" else " " for ch in self.m[mt.start():cb + 1])
            self.m = self.m[:mt.start()] + blank + self.m[cb + 1:]

    def loc(self, idx):
        return "%s:%d" % (self.path, line_of(self.text, idx))


def crate_name(path):
    parts = path.replace("\\", "/").split("/")
    for i in range(len(parts) - 1, 0, -1):
        if parts[i] == "src" and parts[i - 1] not in ("", "."):
            return parts[i - 1]
    return os.path.splitext(os.path.basename(path))[0]


class Body:
    """A function body: original text, masked text, where it came from."""
    def __init__(self, src, start, end, name):
        self.src, self.start, self.end, self.name = src, start, end, name
        self.text = src.text[start:end]
        self.m = src.m[start:end]

    def loc(self, rel):
        return self.src.loc(self.start + rel)


FN_RE = re.compile(r"\bfn\s+(\w+)\s*(<[^{;]*?>)?\s*\(")


def functions(src, start=0, end=None):
    """Yield (name, params_text, body_start, body_end, fn_idx) for fns with a body."""
    end = len(src.m) if end is None else end
    for mt in FN_RE.finditer(src.m, start, end):
        po = mt.end() - 1
        pc = match_close(src.m, po)
        j = pc + 1
        while j < end and src.m[j] not in "{;":
            j += 1
        if j >= end or src.m[j] == ";":
            continue
        bc = match_close(src.m, j)
        yield mt.group(1), src.text[po + 1:pc], j + 1, bc, mt.start()


# --------------------------------------------------------------------------
# Anchor: #[derive(Accounts)] structs
# --------------------------------------------------------------------------

RAW_TYPES = ("AccountInfo", "UncheckedAccount")
# A /// CHECK note that defers validation to another program/CPI/callee is a frequent
# false assumption (e.g. GLAM audit E20: a sibling CPI path did not actually validate it).
DEFER_CHECK = re.compile(r"(validated|checked|verified|constrained|enforced|handled)\b.*\b(by|in|via|through)\b|(target|downstream|callee|external|cpi|invoked|drift|kamino)\b.*\bprogram\b|by the (target|callee|cpi|downstream|invoked)", re.I)
AUTH_NAME = re.compile(r"(^|_)(authority|admin|owner|signer|creator|manager|operator|governor|maker|taker|depositor|withdrawer|delegate)($|_)", re.I)
USER_NAME = re.compile(r"(user|owner|authority|payer|maker|taker|depositor|signer|creator|wallet|player|buyer|seller|staker|borrower|lender|member|voter|destination|recipient|beneficiary|receiver)", re.I)
SYSVAR_NAME = re.compile(r"^(rent|clock|instructions?|ix_sysvar|instruction_sysvar|sysvar_\w+|recent_blockhashes|slot_hashes|stake_history|epoch_schedule)$", re.I)


class Field:
    def __init__(self, name, ty, attrs, docs, idx):
        self.name, self.ty, self.docs, self.idx = name, ty, docs, idx
        self.items = []          # (key, value) from #[account(...)]
        for a in attrs:
            am = re.match(r"\s*account\s*\((.*)\)\s*$", a, re.S)
            if am:
                for it in split_top(am.group(1)):
                    if "=" in it and not re.match(r"^\w+\s*(==|!=)", it):
                        k, v = it.split("=", 1)
                        self.items.append((k.strip(), v.strip()))
                    else:
                        self.items.append((it.strip(), ""))
        self.keys = {k for k, _ in self.items}

    def val(self, key):
        return [v for k, v in self.items if k == key]

    # type helpers
    @property
    def base(self):
        t = re.sub(r"\s+", "", self.ty)
        t = re.sub(r"^(Option|Box)<(.*)>$", r"\2", t)
        t = re.sub(r"^(Option|Box)<(.*)>$", r"\2", t)
        return t

    @property
    def kind(self):
        return re.split(r"[<:]", self.base.split("::")[-1] if "<" not in self.base else self.base.split("<")[0].split("::")[-1])[0]

    @property
    def inner(self):
        mt = re.search(r"<(?:'\w+,)*([^<>]+(?:<[^<>]*>)?)>$", self.base)
        return mt.group(1) if mt else ""

    @property
    def is_signer(self):
        return self.kind == "Signer" or "signer" in self.keys

    @property
    def is_mut(self):
        return bool(self.keys & {"mut", "init", "init_if_needed", "zero", "close", "realloc"})

    @property
    def is_raw(self):
        return self.kind in RAW_TYPES

    @property
    def has_check_doc(self):
        return any(re.match(r"\s*CHECK\b", d) for d in self.docs)

    @property
    def check_doc(self):
        for i, d in enumerate(self.docs):
            if re.match(r"\s*CHECK\b", d):
                return re.sub(r"^\s*CHECK\s*:?\s*", "", " ".join(x.strip() for x in self.docs[i:]))
        return ""

    def owner_desc(self):
        k = self.kind
        if self.val("owner"):
            return "owner = " + self.val("owner")[0]
        if "init" in self.keys or "init_if_needed" in self.keys:
            return "created here"
        if k in ("Account", "AccountLoader", "LazyAccount"):
            if re.search(r"(TokenAccount|Mint)$", self.inner):
                return "SPL Token (by type)"
            return "this program (by type)"
        if k == "InterfaceAccount":
            return "Token or Token-2022 (by type)"
        if k in ("Program", "Interface"):
            return "executable, ID by type"
        if k == "SystemAccount":
            return "System program (by type)"
        if k == "Sysvar":
            return "sysvar ID (by type)"
        if k == "Signer":
            return "any"
        if self.val("address"):
            return "address-pinned"
        return "NOT CHECKED"

    def type_desc(self):
        k = self.kind
        if k in ("Account", "AccountLoader", "InterfaceAccount", "LazyAccount", "Program", "Interface", "Sysvar"):
            return "%s<%s>" % (k, self.inner.split("::")[-1])
        return k or squash(self.ty, 40)

    def seeds(self):
        v = self.val("seeds")
        return v[0] if v else ""

    def bump_desc(self):
        if "bump" not in self.keys:
            return ""
        v = [x for x in self.val("bump") if x]
        return ("bump = " + v[0]) if v else "canonical (bump found by Anchor)"

    def constraints(self):
        skip = {"mut", "init", "init_if_needed", "zero", "close", "seeds", "bump", "payer", "space", "signer", "owner"}
        out = []
        for k, v in self.items:
            if k in skip:
                continue
            out.append(k + (" = " + v if v else ""))
        return out


def parse_accounts_structs(src):
    out = {}
    for mt in re.finditer(r"#\s*\[\s*derive\s*\(([^)]*)\)\s*\]", src.m):
        if not re.search(r"\bAccounts\b", mt.group(1)):
            continue
        sm = re.compile(r"\bstruct\s+(\w+)\s*(<[^>{]*>)?\s*(where[^{]*)?\{").search(src.m, mt.end())
        if not sm or sm.start() - mt.end() > 600:
            continue
        ix_args = []
        hdr = src.m[mt.end():sm.start()]
        im = re.search(r"#\s*\[\s*instruction\s*\(", hdr)
        if im:
            o = mt.end() + im.end() - 1
            c = match_close(src.m, o)
            for a in split_top(src.text[o + 1:c], angle=True):
                ix_args.append(a.split(":")[0].strip())
        ob = sm.end() - 1
        cb = match_close(src.m, ob)
        fields = parse_fields(src, ob + 1, cb)
        out[(src.crate, src.path, sm.group(1))] = {"fields": fields, "src": src, "idx": sm.start(), "ix_args": ix_args}
    return out


def find_struct(structs, src, name):
    """Same file first, then same crate, then a unique match anywhere."""
    for k, v in structs.items():
        if k[1] == src.path and k[2] == name:
            return v
    same = [v for k, v in structs.items() if k[0] == src.crate and k[2] == name]
    if same:
        return same[0]
    anyw = [v for k, v in structs.items() if k[2] == name]
    return anyw[0] if len(anyw) == 1 else None


def parse_fields(src, start, end):
    fields, attrs, docs = [], [], []
    i = start
    m, t = src.m, src.text
    while i < end:
        if m[i].isspace() or m[i] == ",":
            # doc comments live in the original text, masked out in m
            if t.startswith("///", i):
                j = t.find("\n", i)
                docs.append(t[i + 3:j].strip())
                i = j
                continue
            i += 1
            continue
        if t.startswith("///", i) or t.startswith("//", i):
            j = t.find("\n", i)
            if t.startswith("///", i):
                docs.append(t[i + 3:j].strip())
            i = j if j > 0 else end
            continue
        if m.startswith("#[", i) or m.startswith("#", i):
            ob = m.find("[", i)
            cb = match_close(m, ob)
            attrs.append(t[ob + 1:cb])
            i = cb + 1
            continue
        fm = re.compile(r"(pub(\s*\([^)]*\))?\s+)?(\w+)\s*:").match(m, i)
        if not fm:
            i += 1
            continue
        name = fm.group(3)
        j, depth = fm.end(), 0
        while j < end:
            ch = m[j]
            if ch in "<([":
                depth += 1
            elif ch in ">)]":
                depth -= 1
            elif ch == "," and depth == 0:
                break
            j += 1
        ty = t[fm.end():j].strip()
        fields.append(Field(name, ty, attrs, docs, i))
        attrs, docs = [], []
        i = j + 1
    return fields


# --------------------------------------------------------------------------
# Body analysis (shared by Anchor and native)
# --------------------------------------------------------------------------

CPI_HELPER = re.compile(r"\b((?:anchor_spl::)?(?:token|token_2022|token_interface|associated_token|system_program|anchor_lang::system_program|spl_token|spl_token_2022|metadata|mpl_token_metadata)::(?:\w+::)*\w+)\s*\(")
INVOKE = re.compile(r"\b(invoke_signed_unchecked|invoke_signed|invoke_unchecked|invoke)\s*\(")
CPICTX = re.compile(r"\bCpiContext\s*::\s*(new_with_signer|new)\s*\(")
WITH_SIGNER = re.compile(r"\.\s*with_signer\s*\(")
PINO_CPI = re.compile(r"\}\s*\.\s*(invoke_signed|invoke)\s*\(")
GATE = re.compile(r"\b(require(?:_keys)?(?:_eq|_neq|_gt|_gte)?|assert(?:_eq|_ne)?)\s*!\s*\(")
IF_ERR = re.compile(r"\bif\s+([^{};]{3,200}?)\s*\{\s*(?:msg!\([^;]*\);\s*)*return\s+Err")


def call_args(body_m, body_t, open_idx):
    c = match_close(body_m, open_idx)
    return split_top(body_m[open_idx + 1:c]), body_t[open_idx + 1:c], c


def orig_args(body, open_idx):
    """Split call args on masked text, return original-text slices."""
    c = match_close(body.m, open_idx)
    inner_m = body.m[open_idx + 1:c]
    pieces, depth, last = [], 0, 0
    for k, ch in enumerate(inner_m):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            pieces.append((last, k)); last = k + 1
    pieces.append((last, len(inner_m)))
    t = body.text[open_idx + 1:c]
    return [t[a:b].strip() for a, b in pieces if t[a:b].strip()], c


def resolve_let(body, name, before):
    """Text of `let name = ...;` (last one before index), else ''."""
    best = ""
    for mt in re.finditer(r"\blet\s+(?:mut\s+)?" + re.escape(name) + r"\s*(?::[^=]+)?=\s*", body.m[:before]):
        e = body.m.find(";", mt.end())
        best = body.text[mt.end():e if e > 0 else len(body.text)]
    return best


def expand_seeds(body, seeds, at, depth=3):
    """Inline one level of `let` bindings named inside a signer-seeds expression
    (`&[Signer::from(&seeds)]` -> the `seeds` array), so the user-key and bump
    checks see the real seed list."""
    out = seeds
    for w in dict.fromkeys(re.findall(r"\b([a-z_]\w*)\b", seeds)):
        if w in ("from", "as_ref", "as_slice", "to_le_bytes", "to_bytes", "key", "mut"):
            continue
        if USER_NAME.search(w):
            continue    # keep a name that already says "user key"
        let = resolve_let(body, w, at)
        if re.search(r"next_account_info|\baccounts\b|ctx\.accounts\.\w+\s*$", let or ""):
            continue    # an account binding, not a seed value
        if let and len(let) < 300 and not re.search(r"\b%s\b" % re.escape(w), let):
            if depth > 1:
                let = expand_seeds(body, let, at, depth - 1)
            out = re.sub(r"\b%s\b" % re.escape(w), lambda _m: "{" + squash(let, 200) + "}", out, count=1)
    return out


def program_of_ix(body, expr, at):
    """Best effort: which expression is the program id of an Instruction value."""
    e = expr.strip().lstrip("&").strip()
    if re.match(r"^\w+$", e):
        let = resolve_let(body, e, at)
        if let:
            e = let.strip().lstrip("&").strip()
    mt = re.match(r"([\w:]+)::instruction::(\w+)\s*\(", e)
    if mt:
        crate = mt.group(1)
        if crate.endswith("system_instruction") or crate.startswith("solana_system_interface") or crate == "system_program":
            return "System program (constant)", True, mt.group(0)
        args = split_top(mask(e[e.find("(") + 1:e.rfind(")")]))
        a = args[0] if args else "?"
        return a, False, mt.group(0)
    mt = re.match(r"(?:solana_program::)?system_instruction::(\w+)\s*\(", e)
    if mt:
        return "System program (constant)", True, mt.group(0)
    mt = re.search(r"program_id\s*:\s*([^,}]+)", e)
    if mt:
        return mt.group(1).strip(), False, "Instruction { .. }"
    mt = re.match(r"Instruction\s*::\s*new\w*\s*\(\s*([^,]+),", e)
    if mt:
        return mt.group(1).strip(), False, "Instruction::new"
    return "?", False, squash(e, 50)


def classify_program(expr, fields, body_all, native_names=()):
    """-> (desc, validated: True/False/None)."""
    e = expr.strip().lstrip("&*").strip()
    if e.startswith("System program") or e == "?":
        return e, (True if e.startswith("System") else None)
    fm = re.search(r"(?:ctx\.accounts\.|self\.|accounts\.)?(\w+)\s*\.\s*(?:key|to_account_info|address|clone|as_ref)\b", e)
    fname = fm.group(1) if fm else (e if re.match(r"^\w+$", e) and (e in fields or e in native_names) else None)
    if fname and (fname in fields or fname in native_names):
        f = fields.get(fname)
        if f is not None and f.kind in ("Program", "Interface"):
            return "`%s` (%s — ID checked by type)" % (fname, f.type_desc()), True
        if f is not None and (f.val("address") or any("key()" in v and ("ID" in v or "id()" in v) for v in f.val("constraint"))):
            return "`%s` (address constraint)" % fname, True
        n = re.escape(fname)
        if re.search(r"\b%s\s*\.\s*(key|address)\s*(\(\s*\))?\s*(!=|==)" % n, body_all) or \
           re.search(r"(!=|==)\s*&?\*?\s*(ctx\.accounts\.)?%s\s*\.\s*(key|address)\b" % n, body_all) or \
           re.search(r"require_keys_(eq|neq)\s*!\s*\([^;]*\b%s\b" % n, body_all) or \
           re.search(r"check_id\s*\([^)]*\b%s\b" % n, body_all) or \
           re.search(r"check_program_account\s*\([^)]*\b%s\b" % n, body_all):
            return "`%s` (key compared in code)" % fname, True
        return "`%s` (account-supplied, NO ID check seen)" % fname, False
    if re.search(r"(::ID\b|::id\(\)|\bID\b|crate::id|program::ID|pinocchio_\w+::ID)", e):
        return "`%s` (constant)" % squash(e, 50), True
    return "`%s`" % squash(e, 60), None


def analyse_body(bodies, fields, native_names=()):
    """Collect CPIs, writes, gates, remaining_accounts from a list of Body."""
    res = {"cpis": [], "writes": [], "gates": [], "remaining": [], "lamports": [],
           "rawwrite": [], "deser": [], "reads_after_cpi": [], "reloads": set(),
           "init_checks": False, "any_is_signer": False, "derive": []}
    allm = "\n".join(b.m for b in bodies)
    names = set(fields) | set(native_names)
    aliases = {}
    for b in bodies:
        for mt in re.finditer(r"\blet\s+(?:mut\s+)?(\w+)\s*(?::[^=]+)?=\s*&\s*mut\s+(?:\*\s*)?(?:ctx\.accounts\.|self\.)(\w+)", b.m):
            aliases[mt.group(1)] = mt.group(2)
        for mt in re.finditer(r"\blet\s+(?:mut\s+)?(\w+)\s*(?::[^=]+)?=\s*&\s*(?:mut\s+)?(?:ctx\.accounts\.|self\.)(\w+)\s*;", b.m):
            aliases.setdefault(mt.group(1), mt.group(2))
    res["any_is_signer"] = bool(re.search(r"\bis_signer\b", allm))
    res["init_checks"] = bool(re.search(r"is_initialized|initialized\b|DISCRIMINATOR|discriminator|AccountAlreadyInitialized|lamports\(\)\s*[!=]=\s*0|data_is_empty|data_len\(\)\s*[!=]=\s*0|create_account|CreateAccount\b|allocate\s*\(", allm))
    seen_w = set()
    for b in bodies:
        m, t = b.m, b.text
        # ---- CPIs
        cpi_pos = []
        for mt in INVOKE.finditer(m):
            if re.search(r"(fn|\.)\s*$", m[max(0, mt.start() - 4):mt.start()]):
                continue
            args, c = orig_args(b, mt.end() - 1)
            if not args:
                continue
            prog, const, via = program_of_ix(b, args[0], mt.start())
            desc, ok = classify_program(prog, fields, allm, native_names) if not const else (prog, True)
            seeds = expand_seeds(b, args[2], mt.start()) if mt.group(1).startswith("invoke_signed") and len(args) > 2 else ""
            res["cpis"].append({"how": "%s(%s)" % (mt.group(1), via), "prog": desc, "ok": ok, "seeds": seeds, "loc": b.loc(mt.start())})
            cpi_pos.append(mt.start())
        for mt in CPICTX.finditer(m):
            args, c = orig_args(b, mt.end() - 1)
            if not args:
                continue
            pexpr = args[0]
            if re.match(r"^\w+$", pexpr.strip()) and pexpr.strip() not in fields and pexpr.strip() not in native_names:
                pexpr = resolve_let(b, pexpr.strip(), mt.start()) or pexpr
            desc, ok = classify_program(pexpr, fields, allm, native_names)
            seeds = args[2] if mt.group(1) == "new_with_signer" and len(args) > 2 else ""
            if seeds:
                seeds = expand_seeds(b, seeds, mt.start())
            before = m[max(0, mt.start() - 160):mt.start()]
            hm = list(CPI_HELPER.finditer(before))
            via = hm[-1].group(1) if hm else ""
            if not via:
                after = CPI_HELPER.search(m, c, min(len(m), c + 400))
                via = after.group(1) if after else ""
            res["cpis"].append({"how": "CpiContext::%s%s" % (mt.group(1), (" → " + via) if via else ""), "prog": desc, "ok": ok, "seeds": seeds, "loc": b.loc(mt.start())})
            cpi_pos.append(mt.start())
        for mt in WITH_SIGNER.finditer(m):
            args, c = orig_args(b, mt.end() - 1)
            seeds = expand_seeds(b, args[0], mt.start()) if args else ""
            hm = list(CPI_HELPER.finditer(m[max(0, mt.start() - 200):mt.start()]))
            res["cpis"].append({"how": ".with_signer%s" % ((" → " + hm[-1].group(1)) if hm else ""), "prog": "(program from the CpiContext it signs — see the CpiContext line)", "ok": True, "seeds": seeds, "loc": b.loc(mt.start())})
            cpi_pos.append(mt.start())
        for mt in PINO_CPI.finditer(m):
            # struct-literal CPI: Transfer { .. }.invoke()
            ob = m.rfind("{", 0, mt.start() + 1)
            depth, k = 0, mt.start()
            while k >= 0:
                if m[k] == "}":
                    depth += 1
                elif m[k] == "{":
                    depth -= 1
                    if depth == 0:
                        break
                k -= 1
            nm = re.search(r"([\w:]+)\s*$", m[:k])
            name = nm.group(1) if nm else "?"
            args, c = orig_args(b, mt.end() - 1)
            seeds = expand_seeds(b, args[0], mt.start()) if args and mt.group(1) == "invoke_signed" else ""
            res["cpis"].append({"how": "%s { .. }.%s()" % (name, mt.group(1)), "prog": "fixed by the CPI crate (`%s`) — confirm the crate pins the program ID" % name, "ok": True, "seeds": seeds, "loc": b.loc(mt.start())})
            cpi_pos.append(mt.start())
        # ---- writes
        for mt in re.finditer(r"(?:ctx\.accounts\.|self\.)?\b(\w+)((?:\s*\.\s*\w+)+)\s*([+\-*/%|&^]|<<|>>)?=(?!=)", m):
            base = mt.group(1)
            pre = m[max(0, mt.start() - 3):mt.start()]
            if re.search(r"[=!<>]$", pre.strip()) or re.search(r"\blet\s+$", m[max(0, mt.start() - 8):mt.start()]):
                continue
            acct = aliases.get(base, base)
            if acct not in names:
                continue
            path = re.sub(r"\s+", "", mt.group(2))
            if path.startswith(".key") or "(" in path:
                continue
            w = acct + path
            if w not in seen_w:
                seen_w.add(w); res["writes"].append(w)
        for mt in re.finditer(r"\*\*\s*(?:ctx\.accounts\.|self\.)?(\w+)(?:\s*\.\s*to_account_info\s*\(\s*\))?\s*\.\s*(?:try_borrow_mut_lamports\s*\(\s*\)\s*\?|lamports\s*\.\s*borrow_mut\s*\(\s*\))\s*([+\-]?=)\s*([^;]*)", m):
            acct = aliases.get(mt.group(1), mt.group(1))
            res["lamports"].append((acct, mt.group(2), squash(t[mt.start(3):mt.end(3)], 40), b.loc(mt.start())))
            w = "lamports of " + acct
            if w not in seen_w:
                seen_w.add(w); res["writes"].append(w)
        for mt in re.finditer(r"(?:ctx\.accounts\.|self\.)?\b(\w+)\s*\.\s*(sub_lamports|add_lamports|set_lamports|assign|realloc|resize|close)\s*\(", m):
            acct = aliases.get(mt.group(1), mt.group(1))
            if acct in names:
                w = "%s of %s" % ({"assign": "owner", "realloc": "size", "resize": "size", "close": "closed:"}.get(mt.group(2), "lamports"), acct)
                if w not in seen_w:
                    seen_w.add(w); res["writes"].append(w)
                if mt.group(2) in ("sub_lamports", "set_lamports"):
                    res["lamports"].append((acct, mt.group(2), "", b.loc(mt.start())))
        for mt in re.finditer(r"(?:ctx\.accounts\.|self\.)?\b(\w+)\s*(?:\.\s*to_account_info\s*\(\s*\))?\s*\.\s*(?:try_borrow_mut_data|data\s*\.\s*borrow_mut|try_borrow_mut|borrow_mut_data_unchecked)\s*\(", m):
            acct = aliases.get(mt.group(1), mt.group(1))
            if acct in names:
                res["rawwrite"].append((acct, b.loc(mt.start())))
                w = "raw data of " + acct
                if w not in seen_w:
                    seen_w.add(w); res["writes"].append(w)
        # ---- manual deserialisation of raw accounts
        for mt in re.finditer(r"\b([A-Z]\w*)\s*::\s*(unpack|unpack_unchecked|unpack_from_slice|try_from_slice|deserialize|try_deserialize|try_deserialize_unchecked|load|load_mut|from_account_info|from_account_view|from_bytes|try_from_bytes|load_unchecked)\s*\(\s*&?\s*(?:mut\s+)?\*?\s*(?:ctx\.accounts\.|self\.)?(\w+)", m):
            acct = aliases.get(mt.group(3), mt.group(3))
            if acct in names:
                res["deser"].append((acct, mt.group(1), mt.group(2), b.loc(mt.start())))
        for mt in re.finditer(r"\b(\w+)\s*\.\s*(?:try_borrow_data|data\s*\.\s*borrow|try_borrow)\s*\(\s*\)", m):
            pass
        # ---- PDA derivations
        for mt in re.finditer(r"\b(find_program_address|create_program_address|derive_address)\s*\(", m):
            args, c = orig_args(b, mt.end() - 1)
            lhs = re.search(r"let\s+(?:\(\s*(\w+)\s*,\s*(\w+)\s*\)|(\w+))\s*(?::[^=]+)?=\s*[^;]*$", m[max(0, mt.start() - 120):mt.start()])
            var = (lhs.group(1) or lhs.group(3)) if lhs else ""
            res["derive"].append({"fn": mt.group(1), "seeds": args[0] if args else "", "var": var, "loc": b.loc(mt.start()), "body": b})
        # ---- gates
        for mt in GATE.finditer(m):
            args_t, c = orig_args(b, mt.end() - 1)
            res["gates"].append("%s!(%s)" % (mt.group(1), squash(", ".join(args_t), 90)))
        for mt in IF_ERR.finditer(m):
            res["gates"].append("if %s → Err" % squash(t[mt.start(1):mt.end(1)], 90))
        # ---- remaining accounts
        for mt in re.finditer(r"\bremaining_accounts\b", m):
            res["remaining"].append(b.loc(mt.start()))
        # ---- reads after CPI without reload (Anchor)
        for mt in re.finditer(r"\breload\s*\(", m):
            pre = re.search(r"(\w+)\s*\.\s*$", m[:mt.start()])
            if pre:
                res["reloads"].add(aliases.get(pre.group(1), pre.group(1)))
        if cpi_pos:
            first = min(cpi_pos)
            for mt in re.finditer(r"(?:ctx\.accounts\.|self\.)\b(\w+)\s*\.\s*(amount|supply|lamports\s*\(\s*\))", m[first:]):
                acct = mt.group(1)
                f = fields.get(acct)
                rd = first + mt.start()
                touched = any(re.search(r"\b%s\b" % re.escape(acct), m[max(0, p - 500):min(rd, p + 300)]) for p in cpi_pos if p < rd)
                if f is not None and f.kind in ("Account", "InterfaceAccount", "AccountLoader") and touched:
                    res["reads_after_cpi"].append((acct, re.sub(r"\s+", "", mt.group(2)), b.loc(rd)))
    return res


# --------------------------------------------------------------------------
# Anchor instructions
# --------------------------------------------------------------------------

def anchor_instructions(srcs, structs):
    insts = []
    ctx_fns = {}     # struct -> [Body] for fns taking Context<Struct> outside #[program]
    impls = {}       # struct -> [Body] for impl blocks
    prog_ranges = []
    for s in srcs:
        for mt in re.finditer(r"#\s*\[\s*program\s*\]\s*(?:#\s*\[[^\]]*\]\s*)*(pub\s+)?mod\s+(\w+)\s*\{", s.m):
            ob = mt.end() - 1
            cb = match_close(s.m, ob)
            prog_ranges.append((s, ob, cb, mt.group(2)))
    for s in srcs:
        for name, params, bs, be, fi in functions(s):
            cm = re.search(r"Context\s*<\s*(?:'\w+\s*,\s*)*(\w+)", params)
            if cm and not any(ps is s and ob < fi < cb for ps, ob, cb, _ in prog_ranges):
                ctx_fns.setdefault((s.crate, cm.group(1)), []).append(Body(s, bs, be, name))
        snames = {k[2] for k in structs}
        for mt in re.finditer(r"\bimpl\s*(<[^>]*>)?\s*(\w+)\s*(<[^>{]*>)?\s*\{", s.m):
            if mt.group(2) in snames:
                ob = mt.end() - 1
                cb = match_close(s.m, ob)
                for name, params, bs, be, fi in functions(s, ob, cb):
                    impls.setdefault((s.crate, mt.group(2)), []).append(Body(s, bs, be, name))
    for s, ob, cb, prog in prog_ranges:
        for name, params, bs, be, fi in functions(s, ob, cb):
            cm = re.search(r"Context\s*<\s*(?:'\w+\s*,\s*)*(\w+)", params)
            if not cm:
                continue
            st = cm.group(1)
            bodies = [Body(s, bs, be, name)] + ctx_fns.get((s.crate, st), []) + impls.get((s.crate, st), [])
            args = [a.split(":")[0].strip() for a in split_top(params, angle=True)[1:]]
            insts.append({"program": prog, "name": name, "struct": st, "src": s, "idx": fi,
                          "bodies": bodies, "args": args, "framework": "Anchor"})
    return insts


# --------------------------------------------------------------------------
# Native / Pinocchio handlers
# --------------------------------------------------------------------------

LOCAL_FNS = set()
TRAIT_FNS = {"from", "into", "new", "try_from", "try_into", "as_ref", "as_mut", "default", "fmt", "eq", "clone", "len",
             "deserialize", "serialize", "pack", "unpack", "from_bytes", "to_bytes", "load", "process", "main"}

ACCT_PARAM = re.compile(r"&\s*(?:'\w+\s+)?(?:mut\s+)?\[\s*(?:[\w:]+::)?(AccountInfo|AccountView)\b")


class NAcct:
    def __init__(self, name, how, idx):
        self.name, self.how, self.idx = name, how, idx


def native_handlers(srcs, anchor_struct_names):
    out = []
    for s in srcs:
        if re.search(r"#\s*\[\s*program\s*\]", s.m):
            continue
        fw = "Pinocchio" if re.search(r"\bpinocchio\b|AccountView\b", s.m) else "native solana-program"
        for name, params, bs, be, fi in functions(s):
            if not ACCT_PARAM.search(params):
                continue
            pnames = [p.split(":")[0].strip().lstrip("_") for p in split_top(params, angle=True)]
            body = Body(s, bs, be, name)
            accts = []
            for mt in re.finditer(r"\blet\s+(?:mut\s+)?(\w+)\s*(?::[^=]+)?=\s*next_account_info\s*\(", body.m):
                accts.append(NAcct(mt.group(1), "next_account_info", mt.start()))
            for mt in re.finditer(r"\blet\s+\[([^\]]*)\]\s*=\s*([^;{]*?)(?:else|;)", body.m):
                if "accounts" not in mt.group(2):
                    continue
                for nm in split_top(mt.group(1)):
                    nm = nm.strip().lstrip("&").replace("ref ", "").replace("mut ", "").strip()
                    if re.match(r"^\w+$", nm):
                        accts.append(NAcct(nm, "slice pattern", mt.start()))
            for mt in re.finditer(r"\blet\s+(?:mut\s+)?(\w+)\s*(?::[^=]+)?=\s*&?\s*accounts\s*(?:\[\s*(\d+)\s*\]|\.get\s*\(\s*(\d+)\s*\))", body.m):
                accts.append(NAcct(mt.group(1), "accounts[%s]" % (mt.group(2) or mt.group(3)), mt.start()))
            dispatch = re.findall(r"\b(\w+)\s*\(\s*(?:program_id\s*,\s*)?&?\s*(?:mut\s+)?accounts\b", body.m)
            dispatch = [d for d in dispatch if d not in ("next_account_info", "iter", "len", "get", "Ok", "Some")]
            if not accts and dispatch:
                out.append({"dispatcher": True, "name": name, "src": s, "idx": fi, "calls": dispatch, "framework": fw,
                            "program": s.crate})
                continue
            out.append({"dispatcher": False, "program": s.crate, "name": name, "src": s, "idx": fi,
                        "bodies": [body], "accts": accts, "framework": fw,
                        "delegates": dispatch, "params": pnames})
    return out


def native_account_rows(h, res):
    body = h["bodies"][0]
    m = body.m
    rows, unresolved = [], []
    helper_calls = re.findall(r"\b([a-z_]\w*)\s*\(([^;]*)\)", m)
    for a in h["accts"]:
        n = re.escape(a.name)
        if a.name.startswith("_"):
            used = len(re.findall(r"\b%s\b" % n, m)) > 1
        else:
            used = True
        signer = "checked" if re.search(r"\b%s\s*\.\s*is_signer\b" % n, m) else "—"
        writable = "checked" if re.search(r"\b%s\s*\.\s*is_writable\b" % n, m) else ""
        owner = "checked" if (re.search(r"\b%s\s*\.\s*owner\b" % n, m) or re.search(r"(owned_by|is_owned_by|check_owner|assert_owner\w*)\s*\([^;]*\b%s\b" % n, m) or re.search(r"\b%s\s*\.\s*(is_owned_by|owned_by)\s*\(" % n, m)) else "—"
        key = bool(re.search(r"\b%s\s*\.\s*(key|address)\s*(\(\s*\))?\s*(!=|==)" % n, m) or
                   re.search(r"(!=|==)\s*&?\*?\s*%s\s*\.\s*(key|address)\b" % n, m) or
                   re.search(r"check_id\s*\(\s*&?\*?\s*%s\b" % n, m))
        ty = ""
        for acct, t, how, loc in res["deser"]:
            if acct == a.name:
                ty = t
        written = any(w.endswith(" " + a.name) or w.startswith(a.name + ".") for w in res["writes"])
        seeds, bump = "", ""
        for d in res["derive"]:
            if d["var"] and re.search(r"\b%s\b[^;\n]{0,80}\b%s\s*\.\s*(key|address)|\b%s\s*\.\s*(key|address)[^;\n]{0,80}\b%s\b" % (re.escape(d["var"]), n, n, re.escape(d["var"])), m):
                seeds = d["seeds"]
                bump = "canonical (find_program_address)" if d["fn"] == "find_program_address" else "supplied: " + bump_source(d, h)
        passed = [f for f, args in helper_calls if f in LOCAL_FNS and f not in TRAIT_FNS and re.search(r"\b%s\b" % n, args) and f not in ("msg", "Ok", "Err", "Some", "invoke", "invoke_signed", "next_account_info", "clone", "key", "require", "assert", "map_err", "ok_or")]
        if owner == "—" and passed and not a.name.endswith("_program"):
            owner = "? (passed to %s)" % ", ".join(sorted(set(passed))[:3])
            unresolved.append(a.name)
        if signer == "—" and passed and AUTH_NAME.search(a.name):
            signer = "? (passed to %s)" % ", ".join(sorted(set(passed))[:3])
            unresolved.append(a.name)
        rows.append({"name": a.name, "how": a.how, "signer": signer, "mut": ("written" if written else "") + ((" · is_writable " + writable) if writable else ""),
                     "owner": owner, "key": "key compared" if key else "—", "type": ty or ("?" if used else "unused"),
                     "seeds": seeds, "bump": bump, "written": written, "used": used})
    return rows, sorted(set(unresolved))


def bump_source(d, h):
    s = d["seeds"]
    for mt in re.finditer(r"\b(\w*(?:bump|nonce)\w*)\b", s):
        let = resolve_let(d["body"], mt.group(1), len(d["body"].m))
        if let and re.search(r"\.\s*(bump|nonce)\w*\b", let):
            return "stored field (`%s` = `%s`)" % (mt.group(1), squash(let, 40))
    if re.search(r"\.\s*bump\b", s):
        return "stored field (`%s`)" % squash(re.search(r"[\w.]*\.\s*bump\w*", s).group(0), 40)
    if re.search(r"\b(bump|seed)\w*\b", s):
        return "`bump` from instruction data or caller — verify"
    return "inside seeds"


# --------------------------------------------------------------------------
# Red flags
# --------------------------------------------------------------------------

def seeds_have_user(seeds, fields, extra_user=()):
    if not seeds:
        return True
    for mt in re.finditer(r"\b(\w+)\b", seeds):
        w = mt.group(1)
        f = fields.get(w)
        if f is not None and f.is_signer:
            return True
        if w in extra_user:
            return True
        if w[:1].isupper() or w in ("from", "as_ref", "key", "to_le_bytes", "to_bytes"):
            continue    # type / constructor names (`Signer::from`, `Seed`) are not seed values
        if USER_NAME.search(w):
            return True
    return False


def st_has_one(fields):
    return [v for f in fields.values() for v in f.val("has_one")]


def in_code_checks(inst, fields):
    """Which raw accounts the handler checks by hand: {name: set('signer','owner','key')}."""
    body_all = "\n".join(b.m for b in inst["bodies"])
    out = {}
    for name in fields:
        n = re.escape(name)
        got = set()
        # a `let token = Type::unpack(..)` shadows the account: then only
        # `ctx.accounts.token.owner` / `self.token.owner` name the account itself
        if re.search(r"\blet\s+(?:mut\s+)?%s\s*(?::[^=]+)?=" % n, body_all):
            n = r"(?:ctx\.accounts\.|self\.)" + n
        if re.search(r"\b%s\s*\.\s*is_signer\b" % n, body_all):
            got.add("signer")
        if re.search(r"\b%s\s*(?:\.\s*to_account_info\s*\(\s*\))?\s*\.\s*owner\b(?!\s*=[^=])" % n, body_all) or \
           re.search(r"(owned_by|is_owned_by|check_owner|assert_owner\w*)\s*\([^;]*\b%s\b" % n, body_all):
            got.add("owner")
        if re.search(r"\b%s\s*\.\s*(key|address)\s*(\(\s*\))?\s*(!=|==)" % n, body_all) or \
           re.search(r"(!=|==)\s*&?\*?\s*(ctx\.accounts\.)?%s\s*\.\s*(key|address)\b" % n, body_all) or \
           re.search(r"require_keys_(eq|neq)\s*!\s*\([^;]*\b%s\b" % n, body_all) or \
           re.search(r"require_eq\s*!\s*\([^;]*\b%s\s*\.\s*key\b" % n, body_all):
            got.add("key")
        if got:
            out[name] = got
    return out


def anchor_flags(inst, st, res):
    fl = []
    fields = {f.name: f for f in st["fields"]}
    key = "%s::%s" % (inst["program"], inst["name"])
    hand = in_code_checks(inst, fields)
    signs = lambda f: f.is_signer or "signer" in hand.get(f.name, ())
    has_signer = any(signs(f) for f in fields.values())
    state_change = bool(res["writes"] or res["cpis"] or res["lamports"] or any(f.is_mut for f in fields.values()))
    if not has_signer and state_change:
        fl.append((key, "no-signer", "state-changing instruction with no `Signer` account and no `signer` constraint — anyone can call it with any accounts", inst))
    for f in fields.values():
        relied_on = any(v.split("@")[0].strip() == f.name for v in st_has_one(fields)) or \
            re.search(r"\b%s\s*\.\s*key\b[^;{]*(==|!=)|(==|!=)[^;{]*\b%s\s*\.\s*key\b" % (f.name, f.name), "\n".join(b.m for b in inst["bodies"])) or \
            any(re.search(r"\b%s\b" % f.name, v) for g in fields.values() for v in g.val("constraint"))
        if AUTH_NAME.search(f.name) and not signs(f) and f.kind in RAW_TYPES + ("SystemAccount",) and (relied_on or not has_signer):
            fl.append((key, "authority-not-signer", "`%s` (%s) is named like an authority and %s, but nothing makes it sign" % (f.name, f.type_desc(), "a check relies on its key" if relied_on else "the instruction has no signer at all"), inst))
        if f.is_raw and not (f.val("address") or f.val("owner") or f.val("seeds") or f.val("constraint") or "init" in f.keys or "zero" in f.keys):
            by_hand = hand.get(f.name, set())
            if by_hand:
                fl.append((key, "raw-checked-in-code", "`%s: %s` has no constraint; the handler checks its %s by hand — confirm every instruction that takes it does the same" % (f.name, f.kind, " and ".join(sorted(by_hand))), inst))
            elif not f.has_check_doc:
                fl.append((key, "unchecked-account", "`%s: %s` has no `/// CHECK` comment and no owner/address/seeds/constraint" % (f.name, f.kind), inst))
            elif DEFER_CHECK.search(f.check_doc or ""):
                fl.append((key, "check-deferred", "`%s: %s` has a `/// CHECK` that defers validation to another program/CPI (\"%s\") — confirm that program actually checks it on THIS path; a sibling path (e.g. deposit) validating it does not mean this one (e.g. withdraw) does" % (f.name, f.kind, squash(f.check_doc, 70)), inst))
            else:
                fl.append((key, "check-comment-only", "`%s: %s` relies on its `/// CHECK` comment alone (\"%s\") — verify the claim holds in code" % (f.name, f.kind, squash(f.check_doc, 70)), inst))
        if f.is_raw and SYSVAR_NAME.match(f.name) and not f.val("address") and "key" not in hand.get(f.name, ()):
            fl.append((key, "sysvar-unchecked", "`%s` looks like a sysvar but is a raw `%s` with no `address = ` — use `Sysvar<'info, T>` or pin the ID" % (f.name, f.kind), inst))
        sd = f.seeds()
        if sd and (f.is_mut) and not seeds_have_user(sd, fields):
            fl.append((key, "pda-no-user-key", "`%s` is a writable PDA whose seeds `%s` name no signer or user key — fine for a global singleton, a bug when it holds per-user state" % (f.name, squash(sd, 60)), inst))
        bump = [v for v in f.val("bump") if v]
        if bump and (bump[0] in st["ix_args"] or bump[0] in inst["args"]):
            fl.append((key, "user-bump", "`%s` takes `bump = %s` from instruction data — a non-canonical bump gives a second valid address" % (f.name, bump[0]), inst))
        if "init_if_needed" in f.keys:
            fl.append((key, "init-if-needed", "`%s` uses `init_if_needed` — check that a second call cannot reset state on an existing account" % f.name, inst))
    muts = {}
    for f in fields.values():
        written = any(w == f.name or w.startswith(f.name + ".") or w.endswith(" " + f.name) for w in res["writes"])
        if (f.is_mut or written) and f.kind in ("Account", "AccountLoader", "InterfaceAccount") and not (f.keys & {"init", "init_if_needed"}) and not f.seeds():
            pin = tuple(sorted((k.split("::")[-1], v) for k, v in f.items if k.split("::")[-1] in ("mint", "authority") and "::" in k))
            muts.setdefault((f.inner, pin), []).append(f.name)
    allc = " ".join(v for f in fields.values() for v in f.val("constraint")) + " " + " ".join(res["gates"])
    for (ty, _pin), names in muts.items():
        if len(names) > 1:
            pair = names[:2]
            if not re.search(r"%s[^,;]*(!=|==)[^,;]*%s|%s[^,;]*(!=|==)[^,;]*%s" % (pair[0], pair[1], pair[1], pair[0]), allc):
                fl.append((key, "duplicate-mutable", "`%s` are all mutable (or written) `%s` with no constraint that their keys differ — the same account can be passed twice" % ("`, `".join(names), ty.split("::")[-1]), inst))
    common_flags(fl, key, inst, res, fields)
    for acct, op, val, loc in res["lamports"]:
        f = fields.get(acct)
        if f is not None and "close" not in f.keys and op in ("=", "set_lamports") and val.strip() == "0" and f.kind in ("Account", "AccountLoader"):
            if any(a == acct for a, _l in res["rawwrite"]):
                fl.append((key, "manual-close", "`%s` is drained by hand and its data is rewritten in code (%s) — confirm the closed marker is checked by every instruction that accepts the account, and that it cannot be re-funded and reused in the same transaction" % (acct, loc), inst))
                continue
            fl.append((key, "manual-close", "`%s` is drained by hand (lamports set to 0) without `close = …` — data and discriminator stay; the account can be revived in the same transaction (%s)" % (acct, loc), inst))
    for acct, attr, loc in res["reads_after_cpi"]:
        if acct not in res["reloads"]:
            fl.append((key, "stale-after-cpi", "`%s.%s` is read after a CPI with no `.reload()` — Anchor does not refresh deserialized accounts (%s)" % (acct, attr, loc), inst))
    return fl


def common_flags(fl, key, inst, res, fields, native_names=()):
    for c in res["cpis"]:
        if c["ok"] is False:
            fl.append((key, "arbitrary-cpi", "%s calls program %s (%s)" % (c["how"], c["prog"], c["loc"]), inst))
        if c["seeds"]:
            if not seeds_have_user(c["seeds"], fields):
                fl.append((key, "signer-seeds-no-user-key", "CPI signs with seeds `%s` that name no signer or user key — any two callers that share these seed values share the authority (%s)" % (squash(c["seeds"], 70), c["loc"]), inst))
        if c["seeds"] and re.search(r"\b(bump|nonce)\b", c["seeds"]) and not re.search(r"\.\s*(bump|nonce)\w*\b|bumps\s*\.", c["seeds"]):
            body = inst["bodies"][0]
            m_all = "\n".join(b.m for b in inst["bodies"])
            if re.search(r"\blet\s+(?:mut\s+)?(bump|nonce)\s*(?::[^=]+)?=\s*[^;]*\b(data|ix_data|instruction_data|args|params)\b", m_all) or \
               re.search(r"\b(bump|nonce)\s*:\s*u8\b", "\n".join(b.src.text[max(0, b.start - 400):b.start] for b in inst["bodies"][:1])):
                fl.append((key, "user-bump", "CPI signer seeds `%s` use a bump taken from instruction data, not a stored or derived bump (%s)" % (squash(c["seeds"], 70), c["loc"]), inst))
    if res["remaining"]:
        checks = re.findall(r"\b(owner|is_signer|key\s*\(\s*\)\s*[!=]=|Account\s*::\s*try_from|try_from|find_program_address|create_program_address|address\s*\(\s*\)\s*[!=]=)", "\n".join(b.m for b in inst["bodies"]))
        if not checks:
            fl.append((key, "remaining-accounts", "`remaining_accounts` is used (%s) and no owner/key/type check appears in the handler" % res["remaining"][0], inst))
        else:
            fl.append((key, "remaining-accounts", "`remaining_accounts` is used (%s); checks seen: %s — verify every element is covered" % (res["remaining"][0], ", ".join(sorted(set(re.sub(r"\s+", "", x) for x in checks)))), inst))
    for d in res["derive"]:
        if d["fn"] == "create_program_address" and re.search(r"\b(bump|nonce)\b", d["seeds"]) and not re.search(r"\.\s*(bump|nonce)\b", d["seeds"]):
            fl.append((key, "user-bump", "`create_program_address` with seeds `%s` takes a bump that is not a stored field — a caller-chosen bump gives a second valid address (%s)" % (squash(d["seeds"], 60), d["loc"]), inst))
    for acct, ty, how, loc in res["deser"]:
        f = fields.get(acct)
        if f is not None and f.is_raw and not (f.val("owner") or f.val("address")):
            body_all = "\n".join(b.m for b in inst["bodies"])
            a = re.escape(acct)
            shadowed = re.search(r"\blet\s+(?:mut\s+)?%s\s*(?::[^=]+)?=\s*[A-Z]\w*\s*::" % a, body_all)
            pat = (r"(ctx\.accounts\.|self\.)%s\s*\.\s*(to_account_info\s*\(\s*\)\s*\.\s*)?owner\b" % a) if shadowed else (r"\b%s\s*\.\s*owner\b" % a)
            if not re.search(pat, body_all):
                fl.append((key, "raw-deserialize", "`%s` is a raw account decoded by hand as `%s::%s` with no owner check — a look-alike account from another program decodes the same (%s)" % (acct, ty, how, loc), inst))
    body_all = "\n".join(b.m for b in inst["bodies"])
    for acct, ty, how, loc in res["deser"]:
        f = fields.get(acct)
        raw = (f is not None and f.is_raw) or (f is None and acct in native_names)
        if raw and how in ("try_from_slice", "deserialize", "unpack_unchecked", "from_bytes", "try_from_bytes", "load_unchecked", "try_deserialize_unchecked") and \
           not re.search(r"discrimin|DISCRIMINATOR|account_type|AccountType|\bkind\b|\btag\b|\bkey\s*!=\s*\w+::|Key::", body_all):
            fl.append((key, "type-cosplay", "`%s` is decoded as `%s` by `%s` with no discriminator or type-tag check — another account type with the same layout passes (%s)" % (acct, ty, how, loc), inst))
    if res["rawwrite"] and not res["init_checks"] and re.search(r"init|create|setup|register|open|^new", inst["name"], re.I):
        for acct, loc in res["rawwrite"][:1]:
            f = fields.get(acct)
            if f is None or f.is_raw:
                fl.append((key, "reinit", "raw data of `%s` is written with no is-initialized / discriminator check in the handler — a second call may overwrite live state (%s)" % (acct, loc), inst))


def native_flags(h, rows, res):
    fl = []
    key = "%s::%s" % (h["program"], h["name"])
    names = [r["name"] for r in rows]
    state_change = bool(res["writes"] or res["cpis"] or res["lamports"])
    if state_change and not res["any_is_signer"] and not h.get("delegates"):
        fl.append((key, "no-signer", "handler changes state and checks `is_signer` on no account", h))
    for r in rows:
        if AUTH_NAME.search(r["name"]) and r["signer"] == "—" and r["used"] and r["key"] != "—" and not r["seeds"]:
            fl.append((key, "authority-not-signer", "`%s` is named like an authority and its key is compared, but `is_signer` is never checked on it here — anyone can pass the right key without the signature" % r["name"], h))
        if r["type"] not in ("?", "unused", "") and r["owner"] == "—" and r["key"] == "—":
            fl.append((key, "raw-deserialize", "`%s` is decoded as `%s` with no owner check and no key check — a look-alike account decodes the same" % (r["name"], r["type"]), h))
        if r["written"] and r["owner"] == "—" and r["key"] == "—" and not r["seeds"] and r["name"] not in ("payer", "fee_payer"):
            fl.append((key, "write-unbound", "`%s` is written with no owner, key or PDA check — the runtime only blocks writes to accounts this program does not own, so any account it does own (another user's, another type) can be passed here" % r["name"], h))
        if SYSVAR_NAME.match(r["name"]) and r["key"] == "—" and r["used"] and r["type"] in ("?", ""):
            fl.append((key, "sysvar-unchecked", "`%s` looks like a sysvar; no address check is visible — `Sysvar::from_account_info` checks it, a hand decode does not" % r["name"], h))
    fake_fields = {}
    common_flags(fl, key, h, res, fake_fields, tuple(names))
    return fl


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------

def render(srcs, entries, flags, dispatchers, needs):
    n_anchor = sum(1 for e in entries if e["framework"] == "Anchor")
    out = []
    out.append("# Account map — leads, not findings\n")
    out.append("Generated by `account-map.py` from %d in-scope file(s): %d Anchor instruction(s), %d native/Pinocchio handler(s). "
               "Every line below is a **lead**: a place to look, produced by pattern matching. It is never a finding by itself — "
               "confirm each one in the source, and do not report anything this map says without your own path to it. "
               "`?` = the script could not settle the cell; `—` = no such check was seen in the handler (a helper it calls may still do it).\n"
               % (len(srcs), n_anchor, len(entries) - n_anchor))
    out.append("## Review leads (%d)\n" % len(flags))
    if not flags:
        out.append("_None raised by the script. That is not a clean bill: the script cannot see logic bugs._\n")
    else:
        order = ["no-signer", "authority-not-signer", "arbitrary-cpi", "check-deferred", "unchecked-account", "raw-deserialize", "write-unbound", "sysvar-unchecked",
                 "user-bump", "pda-no-user-key", "signer-seeds-no-user-key", "duplicate-mutable", "manual-close", "reinit",
                 "init-if-needed", "type-cosplay", "remaining-accounts", "stale-after-cpi", "check-comment-only", "raw-checked-in-code"]
        flags = sorted(flags, key=lambda x: (order.index(x[1]) if x[1] in order else 99, x[0]))
        out.append("| # | Where | Flag | Detail |\n| --- | --- | --- | --- |")
        for i, (k, tag, msg, inst) in enumerate(flags, 1):
            out.append("| %d | `%s` | %s | %s |" % (i, k, tag, cell(msg, 320)))
        out.append("")
    if needs:
        out.append("## Needs completion (%d)\n" % len(needs))
        out.append("The script could not resolve these handlers' accounts. Read the handler (and the helpers it passes accounts to) and fill the `?` cells before relying on the entry.\n")
        for k, why in needs:
            out.append("- `%s` — %s" % (k, why))
        out.append("")
    if dispatchers:
        out.append("## Dispatchers\n")
        for d in dispatchers:
            out.append("- `%s::%s` (`%s`) → %s" % (d["program"], d["name"], d["src"].loc(d["idx"]), ", ".join("`%s`" % c for c in dict.fromkeys(d["calls"]))))
        out.append("")
    out.append("## Instructions\n")
    for e in entries:
        out.extend(e["md"])
    return "\n".join(out).rstrip() + "\n"


def render_anchor(inst, st, res):
    md = []
    key = "%s::%s" % (inst["program"], inst["name"])
    md.append("### `%s` — Anchor, accounts `%s` (`%s`)\n" % (key, inst["struct"], inst["src"].loc(inst["idx"])))
    if st is None:
        md.append("_Accounts struct `%s` not found in scope — read it before trusting anything below._\n" % inst["struct"])
        fields = []
    else:
        fields = st["fields"]
        if st["ix_args"]:
            md.append("`#[instruction(%s)]`\n" % ", ".join(st["ix_args"]))
        hand = in_code_checks(inst, {f.name: f for f in fields})
        md.append("| Account | Type | Signer | Mut | Owner | PDA seeds · bump | Init / close | Constraints |")
        md.append("| --- | --- | --- | --- | --- | --- | --- | --- |")
        for f in fields:
            ic = []
            for k in ("init", "init_if_needed", "zero"):
                if k in f.keys:
                    ic.append(k + (" payer=" + f.val("payer")[0] if f.val("payer") else ""))
            if f.val("close"):
                ic.append("close → " + f.val("close")[0])
            if f.val("realloc"):
                ic.append("realloc")
            pda = ""
            if f.seeds():
                pda = squash(f.seeds(), 60) + " · " + (f.bump_desc() or "no bump")
                sp = f.val("seeds::program")
                if sp:
                    pda += " · program " + sp[0]
            cons = f.constraints()
            if f.is_raw:
                cons = cons + ["CHECK: " + squash(f.check_doc, 60) if f.has_check_doc else "no /// CHECK"]
            md.append("| `%s` | %s | %s | %s | %s | %s | %s | %s |" % (
                f.name, cell(f.type_desc()),
                "yes" if f.is_signer else ("checked in code" if "signer" in hand.get(f.name, ()) else "—"),
                "mut" if f.is_mut else "—",
                cell(f.owner_desc() + (" · owner checked in code" if f.owner_desc() == "NOT CHECKED" and "owner" in hand.get(f.name, ()) else "")
                     + (" · key checked in code" if f.is_raw and "key" in hand.get(f.name, ()) else "")),
                cell(pda), cell("; ".join(ic)), cell("; ".join(cons))))
        md.append("")
    render_common(md, res)
    return md


def render_native(h, rows, res, unresolved):
    md = []
    key = "%s::%s" % (h["program"], h["name"])
    md.append("### `%s` — %s handler (`%s`)\n" % (key, h["framework"], h["src"].loc(h["idx"])))
    if not rows:
        md.append("_Accounts: `?` — this handler does not unpack accounts itself%s. Needs completion._\n" % (
            (" (passes them to %s)" % ", ".join("`%s`" % d for d in dict.fromkeys(h["delegates"]))) if h.get("delegates") else ""))
    else:
        md.append("| Account | Unpacked by | Signer | Mut / written | Owner | Key check | Decoded as | PDA seeds · bump |")
        md.append("| --- | --- | --- | --- | --- | --- | --- | --- |")
        for r in rows:
            pda = (squash(r["seeds"], 60) + " · " + r["bump"]) if r["seeds"] else ""
            md.append("| `%s` | %s | %s | %s | %s | %s | %s | %s |" % (
                r["name"], cell(r["how"]), cell(r["signer"]), cell(r["mut"]), cell(r["owner"]), cell(r["key"]), cell(r["type"]), cell(pda)))
        md.append("")
    render_common(md, res)
    return md


def render_common(md, res):
    if res["cpis"]:
        md.append("**CPIs**")
        for c in res["cpis"]:
            md.append("- %s → program %s%s · `%s`" % (squash(c["how"], 80), c["prog"],
                      (" · signer seeds `%s`" % squash(c["seeds"], 80)) if c["seeds"] else "", c["loc"]))
    else:
        md.append("**CPIs** — none")
    md.append("")
    md.append("**State written** — " + (", ".join("`%s`" % w for w in res["writes"][:25]) if res["writes"] else "none seen") + "\n")
    gates = list(dict.fromkeys(res["gates"]))
    md.append("**Gating in code** — " + ("; ".join("`%s`" % g.replace("`", "'") for g in gates[:10]) + (" …(+%d)" % (len(gates) - 10) if len(gates) > 10 else "") if gates else "none seen") + "\n")
    if res["remaining"]:
        md.append("**remaining_accounts** — used at %s\n" % ", ".join("`%s`" % r for r in res["remaining"][:3]))
    md.append("")


def main(argv):
    out_path, files = None, []
    i = 0
    while i < len(argv):
        if argv[i] == "--out":
            out_path = argv[i + 1]; i += 2
        elif argv[i] in ("-h", "--help"):
            print(__doc__); return 0
        else:
            files.append(argv[i]); i += 1
    if not files:
        files = [l.strip() for l in sys.stdin if l.strip()]
    files = [f for f in files if f.endswith(".rs") and os.path.isfile(f)]
    srcs = [Src(f) for f in files]
    for s_ in srcs:
        LOCAL_FNS.update(mt.group(1) for mt in FN_RE.finditer(s_.m))
    structs = {}
    for s in srcs:
        structs.update(parse_accounts_structs(s))
    entries, flags, needs = [], [], []
    for inst in anchor_instructions(srcs, structs):
        st = find_struct(structs, inst["src"], inst["struct"])
        fields = {f.name: f for f in st["fields"]} if st else {}
        res = analyse_body(inst["bodies"], fields)
        md = render_anchor(inst, st, res)
        if st:
            flags.extend(anchor_flags(inst, st, res))
        else:
            needs.append(("%s::%s" % (inst["program"], inst["name"]), "Accounts struct `%s` is outside the scanned files" % inst["struct"]))
        entries.append({"framework": "Anchor", "md": md})
    dispatchers = []
    for h in native_handlers(srcs, {k[2] for k in structs}):
        if h["dispatcher"]:
            dispatchers.append(h); continue
        names = [a.name for a in h["accts"]]
        res = analyse_body(h["bodies"], {}, names)
        rows, unresolved = native_account_rows(h, res)
        key = "%s::%s" % (h["program"], h["name"])
        if not rows:
            needs.append((key, "accounts are not unpacked in this function"))
        elif unresolved:
            needs.append((key, "owner/signer of %s decided in a helper" % ", ".join("`%s`" % u for u in unresolved)))
        if any(r["how"].startswith("accounts[") for r in rows):
            needs.append((key, "accounts read by index — confirm the index → role mapping"))
        flags.extend(native_flags(h, rows, res))
        entries.append({"framework": h["framework"], "md": render_native(h, rows, res, unresolved)})
    # de-duplicate identical flags
    seen, uniq = set(), []
    for f in flags:
        k = (f[0], f[1], f[2])
        if k not in seen:
            seen.add(k); uniq.append(f)
    text = render(srcs, entries, uniq, dispatchers, list(dict.fromkeys(needs)))
    if out_path:
        d = os.path.dirname(out_path)
        if d:
            os.makedirs(d, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(text)
    else:
        sys.stdout.write(text)
    print("account map: %d instruction(s), %d review lead(s), %d need completion" % (len(entries), len(uniq), len(dict.fromkeys(needs))), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
