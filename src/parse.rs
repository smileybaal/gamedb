//! Masking, function/string/symbol extraction, call-site scanning.
//! All indices are character offsets, never byte offsets: the whole parser runs
//! over `Vec<char>`, so a multi-byte character can never shift a line number.

use crate::rx::{self as m, *};
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

pub const MAX_STRINGS_PER_FILE: usize = 5000;
pub const MAX_CALLEES_PER_FN: usize = 1000;

/// Longest run of physical lines one header may span. A wrapped parameter list
/// is two or three lines even after a decompiler formats it; eight is past
/// anything real and stops a runaway join on a stray unbalanced `(`.
pub const MAX_HEADER_LINES: usize = 8;

/// Did the parentheses open and then balance? A bare `)` never counts, so this
/// distinguishes "header complete" from "not a signature".
fn parens_balanced(s: &[char]) -> bool {
    let mut depth = 0i32;
    for &c in s {
        match c {
            '(' => depth += 1,
            ')' => {
                if depth == 0 {
                    return false;
                }
                depth -= 1;
                if depth == 0 {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

/// Can line `li` legitimately continue onto the next one? Only a *declaration*
/// wraps: a call site (`Foo(`, `bar.baz(`) has nothing but a name before its
/// `(`, so requiring whitespace there keeps multi-line joining from turning a
/// wrapped argument list into a phantom function header. Continuation lines are
/// already inside an unbalanced parameter list and need no such test.
fn can_join(masked: &[char], lr: &[(usize, usize)], li: usize) -> bool {
    let line = masked[lr[li].0..lr[li].1].to_vec();
    match line.iter().position(|&c| c == '(') {
        Some(p) => line[..p].iter().any(|&c| is_ws(c) && c != '\r'),
        None => false,
    }
}

/// Join the declaration at `li` into one line, following the header across
/// physical lines until its parentheses balance, then accepting a `{` either on
/// that same line or alone on the next non-blank one. Returns the joined text
/// and the line holding the opening brace.
///
/// Three shapes, one code path:
/// ```text
/// int f(int a) {                 one line
/// void f(int a)                  Allman: `)` ends the line
///     {                          ` { ` alone on the next
/// void f(int a,                  wrapped: parameters across lines
///      int b) {
/// ```
pub fn join_header(
    masked: &[char],
    lr: &[(usize, usize)],
    li: usize,
) -> Option<(Vec<char>, usize)> {
    let mut cand: Vec<char> = Vec::new();
    let mut hdr_end = li;
    loop {
        let seg = trim_line(&masked[lr[hdr_end].0..lr[hdr_end].1]);
        if hdr_end > li {
            cand.push(' ');
        }
        cand.extend(seg.iter().copied());
        if parens_balanced(&cand) || hdr_end - li >= MAX_HEADER_LINES - 1 {
            break;
        }
        if hdr_end == li && !can_join(masked, lr, li) {
            return None;
        }
        hdr_end += 1;
        if hdr_end >= lr.len() {
            return None;
        }
    }
    if !parens_balanced(&cand) {
        return None;
    }
    let cand = strip_where_throws(&cand);
    if cand.last() == Some(&'{') {
        return Some((cand, hdr_end));
    }
    // Single-line body: `int f() { return x; }`. Truncate to the opening brace
    // so the strict matchers see the plain `NAME(params) {` shape; the body
    // walk in `parse_source` still runs to the end of this same line.
    if cand.last() == Some(&'}') {
        if let Some(p) = cand.iter().position(|&c| c == '{') {
            return Some((cand[..=p].to_vec(), hdr_end));
        }
    }
    // Expression-bodied member (C#): the definition ends in `=> expr ;`, with no
    // brace. `parse_source` treats the line itself as the body.
    if cand.last() == Some(&';') && has_arrow(&cand) {
        return Some((cand, hdr_end));
    }
    let mut nx = hdr_end + 1;
    while nx < lr.len() && trim_line(&masked[lr[nx].0..lr[nx].1]).is_empty() {
        nx += 1;
    }
    if nx >= lr.len() || trim_line(&masked[lr[nx].0..lr[nx].1]) != ['{'] {
        return None;
    }
    let mut cand = cand;
    cand.push(' ');
    cand.push('{');
    Some((cand, nx))
}

fn not_a_func() -> &'static HashSet<&'static str> {
    static S: OnceLock<HashSet<&'static str>> = OnceLock::new();
    S.get_or_init(|| {
        [
            "if",
            "for",
            "while",
            "switch",
            "return",
            "sizeof",
            "do",
            "else",
            "catch",
            "case",
            "defined",
            "FUN",
            "func",
            "def",
            "fn",
            "fun",
            "when",
            "synchronized",
            "foreach",
            "lock",
            "using",
            "fixed",
            "checked",
            "unchecked",
            "unsafe",
            "get",
            "set",
            "new",
            "stackalloc",
            "static",
        ]
        .into_iter()
        .collect()
    })
}

fn call_keywords() -> &'static HashSet<&'static str> {
    static S: OnceLock<HashSet<&'static str>> = OnceLock::new();
    S.get_or_init(|| {
        [
            "if",
            "for",
            "while",
            "switch",
            "catch",
            "foreach",
            "using",
            "lock",
            "return",
            "do",
            "else",
            "case",
            "default",
            "new",
            "typeof",
            "sizeof",
            "nameof",
            "checked",
            "unchecked",
            "fixed",
            "stackalloc",
            "in",
            "is",
            "as",
            "yield",
            "await",
            "throw",
            "when",
            "let",
            "var",
        ]
        .into_iter()
        .collect()
    })
}

/// Blank comments (and by default string/char literals) with spaces, keeping
/// length and line numbers intact. `blank_literals=false` blanks comments only,
/// so a real literal can be told from one quoted inside a comment.
pub fn mask(s: &[char], blank_literals: bool) -> Vec<char> {
    let mut out = s.to_vec();
    let n = s.len();
    let mut i = 0;
    while i < n {
        let c = s[i];
        let nx = if i + 1 < n { s[i + 1] } else { '\0' };
        if c == '/' && nx == '/' {
            while i < n && s[i] != '\n' {
                out[i] = ' ';
                i += 1;
            }
        } else if c == '/' && nx == '*' {
            out[i] = ' ';
            out[i + 1] = ' ';
            i += 2;
            while i < n && !(s[i] == '*' && i + 1 < n && s[i + 1] == '/') {
                if s[i] != '\n' {
                    out[i] = ' ';
                }
                i += 1;
            }
            if i < n {
                out[i] = ' ';
                out[i + 1] = ' ';
                i += 2;
            }
        } else if blank_literals && (c == '"' || c == '\'') {
            let q = c;
            out[i] = ' ';
            i += 1;
            while i < n && s[i] != q {
                if s[i] != '\n' {
                    out[i] = ' ';
                }
                if s[i] == '\\' {
                    out[i] = ' ';
                    i += 1;
                }
                i += 1;
            }
            if i < n {
                out[i] = ' ';
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    out
}

/// Character ranges of each line, end-exclusive. Shared by src/masked/no_comments
/// because masking never adds or removes a newline.
pub fn line_ranges(s: &[char]) -> Vec<(usize, usize)> {
    let mut v: Vec<(usize, usize)> = Vec::new();
    let mut start = 0usize;
    for (i, &c) in s.iter().enumerate() {
        if c == '\n' {
            v.push((start, i));
            start = i + 1;
        }
    }
    v.push((start, s.len()));
    v
}
fn trim_ws(s: &[char]) -> &[char] {
    let mut a = 0;
    let mut b = s.len();
    while a < b && is_ws(s[a]) && s[a] != '\n' {
        a += 1;
    }
    while b > a && is_ws(s[b - 1]) && s[b - 1] != '\n' {
        b -= 1;
    }
    &s[a..b]
}

/// Drop a CRLF's `\r` and any trailing blanks. A decompiler that wrote the
/// tree on Windows leaves `\r` at the end of every line, and every pattern below
/// is anchored on the last non-blank character, so it has to go.
pub fn chomp(s: &[char]) -> &[char] {
    let mut b = s.len();
    // CR only: JS `split(/\r?\n/)` leaves trailing spaces on each line, and the
    // reference's `sig` join keeps them.
    while b > 0 && s[b - 1] == '\r' {
        b -= 1;
    }
    &s[..b]
}

fn trim_line(s: &[char]) -> &[char] {
    trim_ws(chomp(s))
}

/// 1-based inclusive line range of the brace body opened at or after `from_line`.
/// Returns `None` for a forward declaration (`class Foo;`), so a type with no
/// body does not make every later line count as a member.
fn brace_body_range(
    masked: &[char],
    lr: &[(usize, usize)],
    from_line: usize,
) -> Option<(usize, usize)> {
    let mut li = from_line;
    let mut found: Option<(usize, usize)> = None;
    while li < lr.len() {
        let (a, b) = lr[li];
        if let Some(p) = masked[a..b].iter().position(|&c| c == '{') {
            found = Some((li, a + p));
            break;
        }
        if masked[a..b].iter().any(|&c| c == ';') {
            return None;
        }
        li += 1;
    }
    let (sli, sc) = found?;
    let mut depth = 0i32;
    let mut nl = sli;
    for &ch in &masked[sc..] {
        match ch {
            '\n' => nl += 1,
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some((sli + 1, nl + 1));
                }
            }
            _ => {}
        }
    }
    None
}

fn enclosing_type<'a>(
    bodies: &'a [(usize, usize, String, &'static str)],
    line1: usize,
) -> Option<&'a (usize, usize, String, &'static str)> {
    bodies.iter().rev().find(|(a, b, _, _)| line1 >= *a && line1 <= *b)
}

/// Java/C#-style enumerators: the identifiers between an enum body's `{` and
/// its first top-level `;`, one per comma-separated item. `RUNNING(3)` yields
/// `RUNNING`; the parenthesised constructor arguments are skipped. Returns
/// `(char offset from `start`, name)` so the caller can recover line numbers.
fn enum_enumerators(masked: &[char], start: usize, end: usize) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut item = start;
    let mut i = start;
    while i < end {
        match masked[i] {
            '(' | '<' | '[' | '{' => depth += 1,
            ')' | '>' | ']' | '}' => {
                if depth == 0 {
                    break;
                }
                depth -= 1;
            }
            ';' if depth == 0 => {
                if let Some(n) = leading_ident(&masked[item..i]) {
                    out.push((item - start, n));
                }
                return out;
            }
            ',' if depth == 0 => {
                if let Some(n) = leading_ident(&masked[item..i]) {
                    out.push((item - start, n));
                }
                item = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    if let Some(n) = leading_ident(&masked[item..i]) {
        out.push((item - start, n));
    }
    out
}

fn leading_ident(seg: &[char]) -> Option<String> {
    let mut i = 0;
    while i < seg.len() && is_ws(seg[i]) {
        i += 1;
    }
    if i >= seg.len() || !is_word_start(seg[i]) {
        return None;
    }
    let s0 = i;
    while i < seg.len() && is_word(seg[i]) {
        i += 1;
    }
    Some(seg[s0..i].iter().collect())
}

/// `"=>"`, the expression-bodied member marker. Adjacent, not two characters
/// that merely appear somewhere on the line.
fn has_arrow(s: &[char]) -> bool {
    s.windows(2).any(|w| w == ['=', '>'])
}

fn collapse_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[derive(Debug, Clone)]
pub struct Func {
    pub name: String,
    pub params: String,
    pub sig: String,
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Clone)]
pub struct Sym {
    pub kind: &'static str,
    pub name: String,
    pub line: usize,
}

#[derive(Debug, Default)]
pub struct Parsed {
    pub funcs: Vec<Func>,
    pub strings: Vec<(usize, String)>,
    pub syms: Vec<Sym>,
}

/// Assumes one-line signatures, true for Ghidra/IDA C and ILSpy C#. Wrapped
/// signatures are stitched by `join_header`.
pub fn parse_source(src: &[char]) -> Parsed {
    let masked = mask(src, true);
    let no_comments = mask(src, false);
    let lr = line_ranges(&masked);
    let mut out = Parsed::default();

    for (li, &(a, b)) in lr.iter().enumerate() {
        // Literals are read from the RAW line. Masking comments first would
        // destroy any literal containing `//` - which is every URL in the tree -
        // so `no_comments` is used only as the guard, at the opening quote.
        let mut lits = Vec::new();
        m::scan_str_lits(&src[a..b], &mut lits);
        for (s, e) in lits {
            if e <= s + 2 || no_comments[a + s] != '"' {
                continue;
            }
            let text: String = src[a + s + 1..a + e - 1].iter().collect();
            if text.chars().count() >= 4 && !is_hexish(&text) {
                out.strings.push((li + 1, text));
            }
        }
    }

    let mut li = 0usize;
    while li < lr.len() {
        let (a, b) = lr[li];
        let line = chomp(&masked[a..b]);
        if !line.contains(&'(') {
            li += 1;
            continue;
        }
        // Allman braces and wrapped parameter lists are both handled by the
        // same joiner, which reports which line the opening brace landed on.
        let (cand, brace_line) = match join_header(&masked, &lr, li) {
            Some(v) => v,
            None => {
                li += 1;
                continue;
            }
        };

        // An expression-bodied member (C#) has no brace: the `=>` line is the
        // whole body, so match the declaration head as if a `{` closed it.
        let expr_body = !cand.iter().any(|&c| c == '{');
        let hit = if expr_body {
            let arrow = cand
                .windows(2)
                .position(|w| w == ['=', '>'])
                .unwrap_or(cand.len());
            let mut head: Vec<char> = cand[..arrow].to_vec();
            head.push('{');
            m::match_header(&head)
                .or_else(|| m::match_csharp_header(&head))
                .or_else(|| m::match_wide_header(&head))
        } else {
            m::match_header(&cand)
                .or_else(|| m::match_csharp_header(&cand))
                .or_else(|| m::match_wide_header(&cand))
        };
        let (name, params) = match hit {
            Some(v) => v,
            None => {
                li += 1;
                continue;
            }
        };
        if not_a_func().contains(name.as_str()) || name.starts_with("__") {
            li += 1;
            continue;
        }
        // A type declaration with a parenthesised primary constructor
        // (`class Foo(...) {`) is a type, not a function.
        if m::match_type(&cand).as_deref() == Some(name.as_str()) {
            li += 1;
            continue;
        }
        if !expr_body && m::has_close_paren_semi(&cand) {
            li += 1;
            continue;
        }

        // Body end: walk masked chars from the header's '{' to its match.
        let mut end = brace_line + 1;
        if !expr_body {
            let (ba, bb) = lr[brace_line];
            let mut depth = 0i32;
            let mut nl = brace_line;
            let rel = masked[ba..bb].iter().rposition(|&c| c == '{');
            let start = match rel {
                Some(r) => ba + r,
                None => ba,
            };
            for &ch in &masked[start..] {
                match ch {
                    '\n' => nl += 1,
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            end = nl + 1;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            if end < li + 1 {
                end = li + 1; // unbalanced tail: claim this line, never rewind
            }
        }
        let mut sig_parts: Vec<String> = Vec::new();
        // rawLines are split on /\r?\n/, so a CRLF tree contributes no `\r` here
        for k in li..=brace_line {
            sig_parts.push(String::from_iter(chomp(&src[lr[k].0..lr[k].1])));
        }
        out.funcs.push(Func {
            name,
            params: collapse_ws(&params),
            sig: sig_parts.join(" ").trim().to_string(),
            start: li + 1,
            end,
        });
        li = end; // functions do not nest; resume after the body
    }

    // Member symbols: declarations outside any function body. Locals live inside
    // bodies, so "not inside one" separates members from noise.
    let mut fi = 0usize;
    // Line ranges (1-based, inclusive) of each type's brace body, so a member
    // with no access modifier can be told from a file-scope declaration.
    let mut type_bodies: Vec<(usize, usize, String, &'static str)> = Vec::new();
    for li in 0..lr.len() {
        while fi < out.funcs.len() && out.funcs[fi].end < li + 1 {
            fi += 1;
        }
        if fi < out.funcs.len() && out.funcs[fi].start <= li + 1 {
            continue;
        }
        let (a, b) = lr[li];
        let t = trim_line(&masked[a..b]);
        if t.is_empty() {
            continue;
        }
        if let Some(n) = m::match_namespace(t) {
            out.syms.push(Sym {
                kind: "namespace",
                name: n,
                line: li + 1,
            });
            continue;
        }
        // An annotation may lead the declaration (`@interface Marker {`,
        // `@Deprecated class X {`); the type matcher wants the bare keyword.
        let bare = if t.first() == Some(&'@') { &t[1..] } else { t };
        if let Some((kw, n)) = m::type_decl(bare) {
            out.syms.push(Sym {
                kind: "type",
                name: n.clone(),
                line: li + 1,
            });
            if let Some((s, e)) = brace_body_range(&masked, &lr, li) {
                // A Java `record` header declares its components as implicit fields.
                if kw == "record" {
                    for c in m::record_components(bare).unwrap_or_default() {
                        out.syms.push(Sym {
                            kind: "field",
                            name: c,
                            line: li + 1,
                        });
                    }
                }
                // Enumerators sit between the opening `{` and the first top-level `;`.
                if kw == "enum" {
                    let (ba, bb) = lr[s - 1];
                    if let Some(open) = masked[ba..bb].iter().position(|&c| c == '{') {
                        let body_a = ba + open + 1;
                        let body_b = lr[e - 1].1;
                        for (off, name) in enum_enumerators(&masked, body_a, body_b) {
                            let line = s
                                + masked[body_a..body_a + off]
                                    .iter()
                                    .filter(|&&c| c == '\n')
                                    .count();
                            out.syms.push(Sym { kind: "field", name, line });
                        }
                    }
                }
                type_bodies.push((s, e, n, kw));
            }
            continue;
        }
        let mem = match m::match_member(t) {
            Some(n) => n,
            None => {
                // A bare `Type name;` inside a type body is a member too; at file
                // scope the same shape is a global, which is deliberately not swept.
                if enclosing_type(&type_bodies, li + 1).is_some() {
                    if let Some(n) = m::match_bare_member(t) {
                        out.syms.push(Sym {
                            kind: "field",
                            name: n,
                            line: li + 1,
                        });
                    }
                }
                continue;
            }
        };
        // A Java record's compact constructor has no parameter list:
        // `public Point { ... }`. That is the type's own name, not a field.
        if t.last() == Some(&'{')
            && !t.contains(&'(')
            && enclosing_type(&type_bodies, li + 1)
                .is_some_and(|(_, _, tn, tk)| *tk == "record" && *tn == mem)
        {
            out.syms.push(Sym {
                kind: "method",
                name: mem,
                line: li + 1,
            });
            continue;
        }
        // A property is a declaration followed by an accessor - `=>` on the same
        // line, or a lone Allman `{` and then `get`/`set`/`init`. A field has
        // `;` or `=` after the name and nothing else.
        let mut is_prop = has_arrow(t) || m::brace_then_accessor(t);
        let mut hops = 0;
        let mut k = li + 1;
        while !is_prop && k < lr.len() && hops < 3 {
            let u = trim_line(&masked[lr[k].0..lr[k].1]);
            if u.is_empty() {
                k += 1;
                continue;
            }
            hops += 1;
            if m::is_accessor_start(u) {
                is_prop = true;
                break;
            }
            if u.len() != 1 || u[0] != '{' {
                break;
            }
            k += 1;
        }
        out.syms.push(Sym {
            kind: if is_prop { "property" } else { "field" },
            name: mem,
            line: li + 1,
        });
    }
    out
}

/// Distinct callees in one body as `(dst, first line, hits)`. Name-only
/// resolution: no type information, so `a.Bar()` lands on Bar and a shadowing
/// local yields a false edge. The function's own name in its header is the
/// declaration, not a call, so the first `self_name(` before the body opens is
/// skipped - otherwise every `void Update()` calls every other `Update`.
pub fn scan_calls(
    masked: &[char],
    lr: &[(usize, usize)],
    start: usize,
    end: usize,
    self_id: i64,
    self_name: &str,
    by_name: &HashMap<String, Vec<i64>>,
) -> Vec<(i64, usize, i64)> {
    let mut out: Vec<(i64, usize, i64)> = Vec::new();
    let mut seen: HashMap<i64, usize> = HashMap::new();
    let hi = end.min(lr.len());
    // Where the body opens: the first `{` or `=>` from the header on.
    let body_at = if start == 0 || start > hi {
        0
    } else {
        let (a, b) = (lr[start - 1].0, lr[hi - 1].1);
        (a..b)
            .find(|&i| masked[i] == '{' || (masked[i] == '=' && masked.get(i + 1) == Some(&'>')))
            .unwrap_or(b)
    };
    let mut declared = false;
    for li in start..=hi {
        if li == 0 || li > lr.len() {
            continue;
        }
        let (a, b) = lr[li - 1];
        let mut sites = Vec::new();
        m::scan_calls(&masked[a..b], &mut sites);
        for (name, at) in sites {
            if !declared && a + at < body_at && name == self_name {
                declared = true;
                continue;
            }
            if call_keywords().contains(name.as_str()) {
                continue;
            }
            let dsts = match by_name.get(&name) {
                Some(v) => v,
                None => continue,
            };
            for &dst in dsts {
                if dst == self_id {
                    continue;
                }
                if let Some(&k) = seen.get(&dst) {
                    out[k].2 += 1;
                } else if out.len() < MAX_CALLEES_PER_FN {
                    seen.insert(dst, out.len());
                    out.push((dst, li, 1));
                }
            }
        }
    }
    out
}
