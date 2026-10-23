//! Hand-written matchers. No regex crate: this file *is* the pattern set, and
//! every character class is ASCII by construction. There is no code path by
//! which `\w` can mean "Unicode letters" the way a default regex engine allows,
//! so the parity hazard is structurally impossible rather than merely tested.

pub fn is_ws(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\r' | '\u{c}' | '\u{b}')
}
pub fn is_word(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}
pub fn is_word_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_'
}
/// `[\w<>\[\],.?*]` -- `*` is here so a pointer return type or a by-pointer
/// parameter does not abort the C# prefix scan before it reaches the name.
pub fn is_tok(c: char) -> bool {
    is_word(c) || matches!(c, '<' | '>' | '[' | ']' | ',' | '.' | '?' | '*')
}

/// True for the tokens that sit *between* a return type and the function's name:
/// calling conventions (MSVC, GCC/Clang itanium, MinGW), storage classes and
/// inlining hints. Decompilers emit these unasked - `undefined4 * __thiscall
/// FUN_004087c6(void)` is Ghidra's standard shape - and a matcher that assumes
/// "second token is the name" silently drops every one of them.
///
/// The rule is structural rather than a fixed list: any `__`-prefixed
/// convention spelling ends in `call` (`__stdcall`, `__fastcall`, `__thiscall`,
/// `__vectorcall`, `__clrcall`, `__swiftcall`, ...) or `decl` (`__cdecl`). The
/// explicit cases cover the uppercase Windows spellings, which have no prefix.
pub fn is_modifier_tok(w: &str) -> bool {
    if w.starts_with("__") && (w.ends_with("call") || w.ends_with("decl")) {
        return true;
    }
    matches!(
        w,
        "WINAPI"
            | "APIENTRY"
            | "CALLBACK"
            | "extern"
            | "static"
            | "inline"
            | "__inline"
            | "__forceinline"
            | "noinline"
            | "__declspec"
    )
}

/// Character offset of the `)` that closes the `(` at `open`, counting nested
/// parens. Returns `None` if they never balance.
///
/// Deliberately paren-aware rather than "scan to the first `)`": a
/// function-pointer parameter (`int (*cb)(int)`) or a nested generic would
/// otherwise close the scan early and the whole header would be dropped.
fn close_paren(s: &[char], open: usize) -> Option<(usize, String)> {
    let mut depth = 0i32;
    let mut i = open;
    while i < s.len() {
        match s[i] {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some((i, s[open + 1..i].iter().collect()));
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

fn read_word(s: &[char], i: usize) -> Option<(String, usize)> {
    if i >= s.len() || !is_word_start(s[i]) {
        return None;
    }
    let mut j = i;
    while j < s.len() && is_word(s[j]) {
        j += 1;
    }
    Some((s[i..j].iter().collect(), j))
}

fn skip_ws(s: &[char], mut i: usize) -> usize {
    while i < s.len() && is_ws(s[i]) {
        i += 1;
    }
    i
}

fn at_end(s: &[char], mut i: usize) -> bool {
    while i < s.len() && is_ws(s[i]) {
        i += 1;
    }
    i == s.len()
}

/// `(NAME) (<...>)? \s* \( ([^()]*) \) \s* { \s* $`
fn tail(s: &[char], i: usize) -> Option<(String, String)> {
    let (name, j) = read_word(s, i)?;
    let mut k = skip_ws(s, j);
    if k < s.len() && s[k] == '<' {
        k += 1;
        while k < s.len() && s[k] != '>' {
            k += 1;
        }
        if k >= s.len() {
            return None;
        }
        k = skip_ws(s, k + 1);
    }
    if k >= s.len() || s[k] != '(' {
        return None;
    }
    let (pe, params) = close_paren(s, k)?;
    let k = skip_ws(s, pe + 1);
    if k >= s.len() || s[k] != '{' {
        return None;
    }
    if !at_end(s, k + 1) {
        return None;
    }
    Some((name, params))
}

fn match_pointer_return_header(s: &[char]) -> Option<(String, String)> {
    let wrapper = s.iter().position(|&c| c == '(')?;
    let prefix: String = s[..wrapper].iter().collect();
    if prefix.trim().is_empty()
        || !s[..wrapper]
            .iter()
            .all(|&c| is_word(c) || is_ws(c) || matches!(c, '*' | '&' | ':' | '<' | '>'))
    {
        return None;
    }
    let mut at = skip_ws(s, wrapper + 1);
    loop {
        match read_word(s, at) {
            Some((word, end)) if is_modifier_tok(&word) => at = skip_ws(s, end),
            _ => break,
        }
    }
    if s.get(at) != Some(&'*') {
        return None;
    }
    while s.get(at) == Some(&'*') {
        at = skip_ws(s, at + 1);
    }
    let (name, end) = qualified_name(s, at)?;
    let args = skip_ws(s, end);
    if s.get(args) != Some(&'(') {
        return None;
    }
    let (end, params) = close_paren(s, args)?;
    let end = skip_ws(s, end + 1);
    if s.get(end) != Some(&')') {
        return None;
    }
    let returns = skip_ws(s, end + 1);
    if s.get(returns) != Some(&'(') {
        return None;
    }
    let (end, _) = close_paren(s, returns)?;
    let end = skip_ws(s, end + 1);
    if s.get(end) != Some(&'{') || !at_end(s, end + 1) {
        return None;
    }
    Some((name, collapse_ws(&params)))
}

/// `HEADER`: optional `Type <*>* `, optional modifier words, then the tail,
/// then an optional `/*...*/` comment.
pub fn match_header(s: &[char]) -> Option<(String, String)> {
    if let Some(found) = match_pointer_return_header(s) {
        return Some(found);
    }
    // ^\s*(?:WORD(?:\s*\*)*\s+(?:MOD\s+)*)?(WORD)\s*\(([^()]*)\)\s*(?:/\*.*)?\{\s*$
    let p = skip_ws(s, 0);
    // Storage and calling-class keywords may lead the whole declaration rather
    // than sit in the name slot: `static inline int f(`, `extern void g(`.
    // Skipping them first is what lets the type word below be the type.
    let mut head = p;
    loop {
        let r = skip_ws(s, head);
        match read_word(s, r) {
            Some((w, j)) if is_modifier_tok(&w) => head = j,
            _ => break,
        }
    }
    let head = skip_ws(s, head);
    // Optional `(?:TYPE\s*\*\s+)?`: pointer stars live *before* the name and must be
    // separated from it by whitespace, so `char **foo(` is deliberately rejected.
    let mut name_at = head;
    if head < s.len() && is_word_start(s[head]) {
        if let Some((_, after)) = read_word(s, head) {
            let mut q = after;
            loop {
                let r = skip_ws(s, q);
                if r < s.len() && s[r] == '*' {
                    q = r + 1;
                } else {
                    break;
                }
            }
            // Calling conventions and storage hints sit in the same slot as a
            // second type word: `void __thiscall f(`, `static inline int g(`.
            loop {
                let r = skip_ws(s, q);
                if r < s.len() && s[r] == '*' {
                    q = r + 1;
                    continue;
                }
                match read_word(s, r) {
                    Some((w, j)) if r > q && is_modifier_tok(&w) => q = j,
                    _ => break,
                }
            }
            let k = skip_ws(s, q);
            if k > q && k < s.len() && is_word_start(s[k]) {
                name_at = k;
            }
        }
    }
    if name_at >= s.len() || !is_word_start(s[name_at]) {
        return None;
    }
    let (name, j) = read_word(s, name_at)?;
    let k = skip_ws(s, j);
    if k >= s.len() || s[k] != '(' {
        return None;
    }
    let (close, params) = close_paren(s, k)?;
    // only `\s*` and an optional `/* */` may sit between `)` and `{` - the regex
    // does not tolerate a trailing `throws ...`, which is why Java constructors
    // that declare one are not indexed.
    let mut e = skip_ws(s, close + 1);
    if e + 1 < s.len() && s[e] == '/' && s[e + 1] == '*' {
        e = s.len();
    }
    if e >= s.len() || s[e] != '{' || !at_end(s, e + 1) {
        return None;
    }
    Some((name, collapse_ws(&params)))
}

/// `m[2].trim().replace(/\s+/g, " ")`
pub fn collapse_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// `CSHARP_HEADER`: `(?:[\w<>\[\],.?]+\s+)*?` then the tail. Non-greedy, so
/// the earliest viable name start wins.
pub fn match_csharp_header(s: &[char]) -> Option<(String, String)> {
    let i0 = skip_ws(s, 0);
    let mut i = i0;
    loop {
        if i >= s.len() {
            return None;
        }
        if i == i0 || is_ws(s[i - 1]) {
            if let Some(hit) = tail(s, i) {
                return Some(hit);
            }
        }
        if is_tok(s[i]) {
            i += 1;
        } else if is_ws(s[i]) {
            i = skip_ws(s, i);
        } else {
            return None;
        }
    }
}

/// A name that may be scope-qualified (`A::B::name`) or carry a template
/// argument list on the final segment. Returns the final segment and the index
/// just past it, so `Game::Core::Player::Update` yields `Update`.
fn qualified_name(s: &[char], i: usize) -> Option<(String, usize)> {
    let (mut name, mut j) = read_word(s, i)?;
    loop {
        let k = skip_ws(s, j);
        if k + 1 < s.len() && s[k] == ':' && s[k + 1] == ':' {
            let m = skip_ws(s, k + 2);
            match read_word(s, m) {
                Some((w, j2)) => {
                    name = w;
                    j = j2;
                }
                None => break,
            }
        } else {
            break;
        }
    }
    Some((name, j))
}

/// Index just past the `>` that balances the `<` at `open`, counting nesting so
/// `Map<String, List<int>>` closes on the right one.
fn skip_angle(s: &[char], open: usize) -> Option<usize> {
    let mut depth = 0i32;
    let mut i = open;
    while i < s.len() {
        match s[i] {
            '<' => depth += 1,
            '>' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i + 1);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// The identifier ending immediately before `i` (skipping whitespace).
fn prev_word(s: &[char], i: usize) -> Option<String> {
    let mut j = i;
    while j > 0 && is_ws(s[j - 1]) {
        j -= 1;
    }
    let mut a = j;
    while a > 0 && is_word(s[a - 1]) {
        a -= 1;
    }
    (a < j).then(|| s[a..j].iter().collect())
}

/// A word that owns the parenthesised text after it: a statement keyword, an
/// operator, or a type-declaration keyword. `if constexpr (x) {` must not read
/// as a function called `constexpr`, and `class Foo(...) {` is a type, not a
/// constructor definition.
fn is_blocking_prefix(w: &str) -> bool {
    matches!(
        w,
        "if" | "while"
            | "for"
            | "switch"
            | "catch"
            | "return"
            | "else"
            | "case"
            | "do"
            | "new"
            | "throw"
            | "throws"
            | "using"
            | "lock"
            | "assert"
            | "sizeof"
            | "decltype"
            | "alignof"
            | "typeid"
            | "noexcept"
            | "static_assert"
            | "when"
            | "yield"
            | "await"
            | "select"
            | "class"
            | "struct"
            | "interface"
            | "record"
            | "enum"
            | "delegate"
            | "object"
            | "impl"
            | "trait"
            | "namespace"
            | "union"
            | "template"
    )
}

/// Everything that may legally sit between a definition's `)` and its `{`:
/// trailing qualifiers (`const`, `override`, `final`, `noexcept`, `volatile`),
/// a `throws`/`where` clause, a trailing return type (`-> T`), a constructor
/// init-list, and balanced parentheses inside any of those. Anything else
/// (`;`, `=`, an unbalanced `)`/`}`) ends the scan with `None`.
fn wide_gap(s: &[char], mut i: usize) -> Option<usize> {
    loop {
        i = skip_ws(s, i);
        if i >= s.len() {
            return None;
        }
        match s[i] {
            '{' => return Some(i),
            '(' => i = close_paren(s, i)?.0 + 1,
            ')' | '}' | ';' | '=' => return None,
            '-' => {
                if i + 1 < s.len() && s[i + 1] == '>' {
                    i += 2;
                } else {
                    return None;
                }
            }
            ':' | '&' | '*' | '<' | '>' | ',' | '.' | '?' | '~' | '[' | ']' | '@' => i += 1,
            c if is_word(c) => {
                let (_, j) = read_word(s, i)?;
                i = j;
            }
            _ => return None,
        }
    }
}

/// `WIDE_HEADER`: the tolerant sibling of `match_header`/`match_csharp_header`.
/// It accepts what a decompiler actually emits for C++ and Java - scope-qualified
/// names (`A::B::f`), namespaced return types (`std::string f`), trailing
/// qualifiers (`const`, `override`, `noexcept`), `throws`/`where` clauses,
/// trailing return types, and constructor init-lists - while still refusing
/// statement keywords and non-definition shapes.
///
/// A candidate is tried at the start of the line, after whitespace, and after a
/// qualified-name/parenthesis boundary (`*`, `&`, `>`, `]`, `:`); the strict
/// matchers run first, so this only ever *adds* definitions.
fn wide_tail(s: &[char], i: usize) -> Option<(String, String)> {
    if is_blocking_prefix(&prev_word(s, i).unwrap_or_default()) {
        return None;
    }
    let (name, j) = qualified_name(s, i)?;
    let mut k = skip_ws(s, j);
    if k < s.len() && s[k] == '<' {
        k = skip_angle(s, k)?;
        k = skip_ws(s, k);
    }
    if k >= s.len() || s[k] != '(' {
        return None;
    }
    let (pe, params) = close_paren(s, k)?;
    let brace = wide_gap(s, pe + 1)?;
    if !at_end(s, brace + 1) {
        return None;
    }
    Some((name, collapse_ws(&params)))
}

pub fn match_wide_header(s: &[char]) -> Option<(String, String)> {
    let i0 = skip_ws(s, 0);
    let mut i = i0;
    loop {
        if i >= s.len() {
            return None;
        }
        let candidate =
            i == i0 || is_ws(s[i - 1]) || matches!(s[i - 1], '*' | '&' | '>' | ']' | ':');
        if candidate {
            if let Some(hit) = wide_tail(s, i) {
                return Some(hit);
            }
        }
        if is_tok(s[i]) || matches!(s[i], ':' | '@' | '~') {
            i += 1;
        } else if is_ws(s[i]) {
            i = skip_ws(s, i);
        } else {
            return None;
        }
    }
}

/// `BARE_MEMBER`: a member with no access modifier - the shape a C `struct`,
/// a C++ class at its default access level, or a language without visibility
/// keywords uses. `Type name;`, `Type *name;`, `Type name[8];`, `Type name = 0;`.
/// Only called for lines known to sit inside a type body, so file-scope globals
/// are not swept in.
pub fn match_bare_member(s: &[char]) -> Option<String> {
    let semi = s.iter().position(|&c| c == ';')?;
    let mut end = semi;
    if let Some(eq) = s[..end].iter().position(|&c| c == '=') {
        end = eq;
    }
    // drop trailing array extents: `name[8]`, `name[8][4]`
    loop {
        let mut i = end;
        while i > 0 && is_ws(s[i - 1]) {
            i -= 1;
        }
        if i > 0 && s[i - 1] == ']' {
            let mut d = 0i32;
            let mut j = i;
            while j > 0 {
                j -= 1;
                match s[j] {
                    ']' => d += 1,
                    '[' => {
                        d -= 1;
                        if d == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
            }
            if d != 0 {
                return None;
            }
            end = j;
        } else {
            break;
        }
    }
    let body = &s[..end];
    if body
        .iter()
        .any(|&c| matches!(c, '(' | ')' | '{' | '}' | '"' | '\''))
    {
        return None;
    }
    // a lone `:` is a label or a bitfield; `::` is a scope qualifier
    let mut ci = 0;
    while ci < body.len() {
        if body[ci] == ':' {
            if ci + 1 < body.len() && body[ci + 1] == ':' {
                ci += 2;
                continue;
            }
            return None;
        }
        ci += 1;
    }
    // the last identifier is the member name
    let mut j = body.len();
    while j > 0 && is_ws(body[j - 1]) {
        j -= 1;
    }
    let name_end = j;
    while j > 0 && is_word(body[j - 1]) {
        j -= 1;
    }
    if j == name_end {
        return None;
    }
    // a type must precede it, past any pointer/reference/template punctuation
    let mut k = j;
    while k > 0 && (is_ws(body[k - 1]) || matches!(body[k - 1], '*' | '&' | '>' | ']')) {
        k -= 1;
    }
    let mut t = k;
    while t > 0 && is_word(body[t - 1]) {
        t -= 1;
    }
    if t == k {
        return None;
    }
    let name: String = body[j..name_end].iter().collect();
    if matches!(
        name.as_str(),
        "return"
            | "using"
            | "typedef"
            | "import"
            | "package"
            | "class"
            | "struct"
            | "union"
            | "enum"
            | "namespace"
            | "template"
            | "friend"
            | "public"
            | "private"
            | "protected"
            | "static"
            | "const"
            | "unsigned"
            | "signed"
            | "long"
            | "short"
            | "void"
            | "int"
            | "char"
            | "float"
            | "double"
            | "bool"
            | "auto"
            | "var"
    ) {
        return None;
    }
    Some(name)
}

/// `namespace\s+([\w.]+)` — greedy through dots, so `A.B.C` is one name.
pub fn match_namespace(s: &[char]) -> Option<String> {
    const KW: &str = "namespace";
    let mut i = skip_ws(s, 0);
    for c in KW.chars() {
        if i >= s.len() || s[i] != c {
            return None;
        }
        i += 1;
    }
    let j = skip_ws(s, i);
    if j == i {
        return None; // `\s+` is required, so `namespace.Foo()` is not a declaration
    }
    let mut k = j;
    while k < s.len() && (is_word(s[k]) || s[k] == '.') {
        k += 1;
    }
    while k > j && s[k - 1] == '.' {
        k -= 1;
    }
    (k > j).then(|| s[j..k].iter().collect())
}

/// `CS_TYPE`: `^(?:[\w<>\[\],.?]+\s+)*(?:class|...)\s+([A-Za-z_]\w*)`. The
/// prefix is greedy, so the *last* viable keyword inside one contiguous
/// token+whitespace run at position 0 wins; a keyword further along the line
/// (after a `(` or `;`) is not a declaration.
pub fn match_type(s: &[char]) -> Option<String> {
    type_decl(s).map(|(_, n)| n)
}

/// `(keyword, name)` for a type declaration, so a caller can tell a `record`
/// (whose header components are implicit fields) from a plain `class` before
/// deciding what else the header declares.
pub fn type_decl(s: &[char]) -> Option<(&'static str, String)> {
    const KWS: [&str; 6] = ["class", "struct", "interface", "enum", "record", "delegate"];
    let mut ends: Vec<usize> = vec![0]; // zero repetitions is the last fallback
    let mut i = 0;
    loop {
        let mut j = i;
        while j < s.len() && is_tok(s[j]) {
            j += 1;
        }
        if j == i {
            break;
        }
        let k = skip_ws(s, j);
        if k == j {
            break;
        }
        ends.push(k);
        i = k;
    }
    for &p in ends.iter().rev() {
        for kw in KWS {
            let k: Vec<char> = kw.chars().collect();
            if p + k.len() <= s.len() && s[p..p + k.len()] == k[..] {
                let j = skip_ws(s, p + k.len());
                if j > p + k.len() && j < s.len() && is_word_start(s[j]) {
                    if let Some((n, _)) = read_word(s, j) {
                        return Some((kw, n));
                    }
                }
            }
        }
    }
    None
}

/// Java `record`: the parenthesised header components are implicitly declared
/// `private final` fields, so they belong in `symbols` alongside ordinary ones.
/// `record Point(int x, int y)` yields `["x", "y"]`.
pub fn record_components(s: &[char]) -> Option<Vec<String>> {
    let (kw, name) = type_decl(s)?;
    if kw != "record" {
        return None;
    }
    let mut i = 0;
    while i < s.len() {
        if is_word_start(s[i]) && (i == 0 || !is_word(s[i - 1])) {
            let (w, j) = read_word(s, i)?;
            if w == name {
                let mut k = skip_ws(s, j);
                if k < s.len() && s[k] == '<' {
                    k = skip_angle(s, k)?;
                    k = skip_ws(s, k);
                }
                if k >= s.len() || s[k] != '(' {
                    return None;
                }
                let (_, params) = close_paren(s, k)?;
                return Some(component_names(&params));
            }
            i = j;
            continue;
        }
        i += 1;
    }
    None
}

/// The last identifier of each top-level comma-separated parameter: for
/// `@NotNull String name, List<Integer> tags` that is `["name", "tags"]`.
fn component_names(params: &str) -> Vec<String> {
    let params: Vec<char> = params.chars().collect();
    let params = &params[..];
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut start = 0usize;
    let mut i = 0usize;
    while i <= params.len() {
        let at_end = i == params.len();
        if !at_end {
            match params[i] {
                '(' | '<' | '[' => depth += 1,
                ')' | '>' | ']' => depth -= 1,
                _ => {}
            }
        }
        if (at_end || params[i] == ',') && depth == 0 {
            if let Some(n) = last_ident(&params[start..i]) {
                out.push(n);
            }
            start = i + 1;
        }
        i += 1;
    }
    out
}

fn last_ident(part: &[char]) -> Option<String> {
    let mut end = part.len();
    while end > 0 && is_ws(part[end - 1]) {
        end -= 1;
    }
    let mut j = end;
    while j > 0 && !is_word(part[j - 1]) {
        j -= 1;
    }
    let stop = j;
    while j > 0 && is_word(part[j - 1]) {
        j -= 1;
    }
    (stop > j).then(|| part[j..stop].iter().collect())
}

const MODIFIERS: [&str; 20] = [
    "public",
    "private",
    "protected",
    "internal",
    "static",
    "readonly",
    "const",
    "volatile",
    "virtual",
    "override",
    "abstract",
    "sealed",
    "partial",
    "new",
    "unsafe",
    "extern",
    "required",
    "event",
    "implicit",
    "explicit",
];

/// `CS_MEMBER`: `(?:MODIFIER)\s+(?:tok\s+)*?(NAME)\s*(?=$|[=;{])`, non-greedy.
pub fn match_member(s: &[char]) -> Option<String> {
    let mut p = None;
    for kw in MODIFIERS {
        let k: Vec<char> = kw.chars().collect();
        if s.len() >= k.len() && s[..k.len()] == k[..] {
            let j = skip_ws(s, k.len());
            if j > k.len() {
                p = Some(j);
                break;
            }
        }
    }
    let p = p?;
    let mut i = p;
    loop {
        if i >= s.len() {
            return None;
        }
        if (i == p || is_ws(s[i - 1])) && is_word_start(s[i]) {
            if let Some((name, j)) = read_word(s, i) {
                let e = skip_ws(s, j);
                if e == s.len() || matches!(s[e], '=' | ';' | '{') {
                    return Some(name);
                }
            }
        }
        if is_tok(s[i]) {
            i += 1;
        } else if is_ws(s[i]) {
            i = skip_ws(s, i);
        } else {
            return None;
        }
    }
}

/// `CALL_SCAN` + `CALL_KEYWORDS`: `(name, start_index)` for every `name(` site.
pub fn scan_calls(s: &[char], out: &mut Vec<(String, usize)>) {
    let mut i = 0;
    while i < s.len() {
        if is_word_start(s[i]) && (i == 0 || !is_word(s[i - 1])) {
            if let Some((name, j)) = read_word(s, i) {
                let k = skip_ws(s, j);
                if k < s.len() && s[k] == '(' {
                    out.push((name, i));
                }
            }
        }
        i += 1;
    }
}

/// `STR_LIT`: `(start, end)` of each complete `"..."` literal, quotes included.
/// A backslash escape may not span a newline, so an unterminated literal fails.
pub fn scan_str_lits(s: &[char], out: &mut Vec<(usize, usize)>) {
    let mut i = 0;
    while i < s.len() {
        if s[i] == '"' {
            let mut j = i + 1;
            let mut ok = false;
            while j < s.len() && s[j] != '\n' {
                if s[j] == '\\' {
                    if j + 1 < s.len() && s[j + 1] != '\n' {
                        j += 2;
                        continue;
                    }
                    break;
                }
                if s[j] == '"' {
                    ok = true;
                    break;
                }
                j += 1;
            }
            if ok {
                out.push((i, j + 1));
                i = j + 1;
                continue;
            }
        }
        i += 1;
    }
}

/// `^[0-9a-fA-F\s]+$` — a "hex literal" that is really just a checksum.
pub fn is_hexish(t: &str) -> bool {
    !t.is_empty() && t.chars().all(|c| c.is_ascii_hexdigit() || is_ws(c))
}

/// `\)\s*;`
pub fn has_close_paren_semi(s: &[char]) -> bool {
    let mut i = 0;
    while i < s.len() {
        if s[i] == ')' {
            let j = skip_ws(s, i + 1);
            if j < s.len() && s[j] == ';' {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// `\s+(?:where|throws)\s+[\w\s:<>,.()]+$`, cut at the first match.
pub fn strip_where_throws(s: &[char]) -> Vec<char> {
    let mut i = 0;
    while i < s.len() {
        if is_ws(s[i]) {
            let j = skip_ws(s, i);
            for kw in ["where", "throws"] {
                let k: Vec<char> = kw.chars().collect();
                if j + k.len() <= s.len() && s[j..j + k.len()] == k[..] {
                    let e = skip_ws(s, j + k.len());
                    if e > j + k.len()
                        // the class is [\w\s:<>,.()] - `:` carries the `where T : ...`
                        && (0..s.len() - e).all(|o| {
                            let c = s[e + o];
                            is_word(c)
                                || is_ws(c)
                                || matches!(c, ':' | '<' | '>' | ',' | '.' | '(' | ')')
                        })
                    {
                        let mut head: Vec<char> = s[..i].to_vec();
                        while head.last().is_some_and(|&c| c != '\n' && is_ws(c)) {
                            head.pop();
                        }
                        return head;
                    }
                }
            }
        }
        i += 1;
    }
    s.to_vec()
}

/// `\{\s*(get|set|init)\b`
pub fn brace_then_accessor(s: &[char]) -> bool {
    let mut i = 0;
    while i < s.len() {
        if s[i] == '{' {
            let j = skip_ws(s, i + 1);
            for kw in ["get", "set", "init"] {
                let k: Vec<char> = kw.chars().collect();
                if j + k.len() <= s.len() && s[j..j + k.len()] == k[..] {
                    let e = j + k.len();
                    if e == s.len() || !is_word(s[e]) {
                        return true;
                    }
                }
            }
        }
        i += 1;
    }
    false
}

/// `^(get|set|init)\b`
pub fn is_accessor_start(s: &[char]) -> bool {
    for kw in ["get", "set", "init"] {
        let k: Vec<char> = kw.chars().collect();
        if s.len() >= k.len()
            && s[..k.len()] == k[..]
            && (s.len() == k.len() || !is_word(s[k.len()]))
        {
            return true;
        }
    }
    false
}
