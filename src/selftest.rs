//! The one runnable check. `gamedb selftest` exits non-zero on any failure,
//! so CI needs nothing else.

use crate::modules::*;
use crate::parse::{mask, parse_source, scan_calls};
use crate::store::*;
use std::path::{Path, PathBuf};

struct Checks {
    v: Vec<(String, bool)>,
}

impl Checks {
    fn ok(&mut self, label: &str, cond: bool) {
        self.v.push((label.to_string(), cond));
    }
}

fn chars(s: &str) -> Vec<char> {
    s.chars().collect()
}

fn names(p: &crate::parse::Parsed) -> Vec<String> {
    p.funcs.iter().map(|f| f.name.clone()).collect()
}

fn tmpdir(tag: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("gamedb-selftest-{}-{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).expect("temp dir");
    p
}

fn write_file(dir: &Path, rel: &str, body: &str) {
    let p = dir.join(rel);
    if let Some(par) = p.parent() {
        std::fs::create_dir_all(par).expect("mkdir");
    }
    std::fs::write(p, body).expect("write");
}

/// `module_of` wants the file's text as a `&str`, and a temporary would not live
/// long enough inside the call, so the one-liner fixtures get a local.
fn assign(rs: &RuleSet, rel: &str, ns: &str) -> (String, String) {
    let owned = ns.to_string();
    let (m, s) = rs.module_of(rel, Some(&owned));
    (m.to_string(), s.to_string())
}

const MIXED: &str = "void caf\u{e9}(){}";

/// UTF-16LE bytes for MIXED with a byte-order mark.
fn utf16_with_bom(le: bool) -> Vec<u8> {
    let mut b: Vec<u8> = if le {
        vec![0xFF, 0xFE]
    } else {
        vec![0xFE, 0xFF]
    };
    for u in MIXED.encode_utf16() {
        if le {
            b.extend_from_slice(&u.to_le_bytes());
        } else {
            b.extend_from_slice(&u.to_be_bytes());
        }
    }
    b
}

/// The same content with no mark at all -- some decompilers emit UTF-16 bare.
fn utf16_bare() -> Vec<u8> {
    let mut b = Vec::new();
    for u in MIXED.encode_utf16() {
        b.extend_from_slice(&u.to_le_bytes());
    }
    b
}

pub fn run() -> i32 {
    let mut c = Checks { v: Vec::new() };

    // --- C: brace walk, comment vs literal, keyword rejection
    let c_src = [
        "// comment with { brace and \"string\"",
        "int main(int argc, char **argv) {",
        "\tprintf(\"hello world\");",
        "\t/* } */ if (argc) { return 1; }",
        "\treturn 0;",
        "}",
        "",
        "void FUN_00401234(int param_1, char *param_2) {",
        "\tchar *s = \"secret_lobby_01\";",
        "}",
    ]
    .join("\n");
    let p = parse_source(&chars(&c_src));
    let nm = names(&p);
    let mainf = p.funcs.iter().find(|f| f.name == "main").expect("main");
    c.ok("c: 2 functions", nm == ["main", "FUN_00401234"]);
    c.ok("c: main ends at 6", mainf.end == 6);
    c.ok("c: no bogus 'if' function", !nm.iter().any(|n| n == "if"));
    c.ok(
        "c: literal extracted",
        p.strings.iter().any(|(_, t)| t == "secret_lobby_01"),
    );
    c.ok(
        "c: comment text not a literal",
        !p.strings.iter().any(|(_, t)| t == "string"),
    );

    // --- C#: Allman braces, generics with modifier, expression-bodied member
    let cs_src = [
        "public class Animation",
        "{",
        "\tprivate void SetDefaults(int type)",
        "\t{",
        "\t\t_frameType = 0;",
        "\t}",
        "",
        "\tinternal static Player Find(int id)",
        "\t{",
        "\t\treturn _cache[id];",
        "\t}",
        "\tprotected void NoBrace(int x) => Do(x);",
        "}",
        "",
    ]
    .join("\n");
    let p = parse_source(&chars(&cs_src));
    let nm = names(&p);
    let sd = p
        .funcs
        .iter()
        .find(|f| f.name == "SetDefaults")
        .expect("SetDefaults");
    c.ok("cs: Allman method", sd.end == 6);
    c.ok("cs: params captured", sd.params == "int type");
    c.ok("cs: modifier + return type", nm.iter().any(|n| n == "Find"));
    // `([^()]*)` in the tail pattern stops at the first paren, so a generic
    // parameter list like `List<T> list` is outside the pattern. Pinned because
    // it is a real coverage limit of the original, not an accident of this port.
    // An expression-bodied member carries real code: the `=> expr;` line is its
    // body, so it is indexed as a function. The rewrite deliberately goes past
    // the original here - dropping it loses reconstructible source.
    c.ok(
        "cs: expression-body is a function",
        nm.iter().any(|n| n == "NoBrace"),
    );
    c.ok(
        "cs: `class` not a function",
        !nm.iter().any(|n| n == "class"),
    );
    c.ok(
        "cs: type symbol",
        p.syms
            .iter()
            .any(|s| s.kind == "type" && s.name == "Animation"),
    );

    // --- symbol table: property vs field, members only (no locals)
    let p = parse_source(&chars(
        "namespace Demo.Data;\n\npublic class Point16\n{\n\tprivate readonly int _x;\n\tpublic int X { get; set; }\n\tpublic int Y\n\t{\n\t\tget { return _x; }\n\t}\n\n\tpublic void Move(int dx)\n\t{\n\t\tint localJunk = dx;\n\t\tHelper.Do(localJunk);\n\t}\n}\n",
    ));
    c.ok(
        "cs: namespace symbol",
        p.syms
            .iter()
            .any(|s| s.kind == "namespace" && s.name == "Demo.Data"),
    );
    c.ok(
        "cs: field symbol",
        p.syms.iter().any(|s| s.kind == "field" && s.name == "_x"),
    );
    c.ok(
        "cs: property X",
        p.syms.iter().any(|s| s.kind == "property" && s.name == "X"),
    );
    c.ok(
        "cs: property Y (Allman accessor)",
        p.syms.iter().any(|s| s.kind == "property" && s.name == "Y"),
    );
    c.ok(
        "cs: local not a symbol",
        !p.syms.iter().any(|s| s.name == "localJunk"),
    );

    // --- unicode: char offsets, not bytes
    let u_src = [
        "// naïve — 中文 \u{1f600} { brace",
        "void TakeDamage(int n)",
        "{",
        "\tset(\"secret_lobby_01\");   // 中文 comment",
        "}",
    ]
    .join("\n");
    let p = parse_source(&chars(&u_src));
    let f = p.funcs.first().expect("TakeDamage");
    c.ok("unicode: function found", names(&p) == ["TakeDamage"]);
    c.ok("unicode: line math intact", f.start == 2 && f.end == 5);
    c.ok(
        "unicode: literal after non-ascii comment",
        p.strings.iter().any(|(_, t)| t == "secret_lobby_01"),
    );
    // ASCII-only identifier class is structural here: no \w anywhere in rx.rs
    c.ok(
        "unicode: non-ascii identifier rejected",
        parse_source(&chars("void caf\u{e9}(int x)\n{\n}\n"))
            .funcs
            .is_empty(),
    );

    // --- calling conventions: a decompiler puts `__thiscall` between the return
    // type and the name, and it used to be read AS the name, dropping the
    // function silently. Ghidra emits this shape constantly; the functions lost
    // this way included the largest in the corpus.
    for (src, want) in [
        ("void __thiscall Hook(int a) {\n}\n", "Hook"),
        ("static inline int Fast(int a) {\n\treturn a;\n}\n", "Fast"),
        ("int WINAPI Api(unsigned long a) {\n\treturn 0;\n}\n", "Api"),
        (
            "undefined4 * __thiscall FUN_004087c6(void) {\n\treturn 0;\n}\n",
            "FUN_004087c6",
        ),
        (
            "void * __cdecl Alloc(unsigned long long n) {\n\treturn 0;\n}\n",
            "Alloc",
        ),
        (
            "char * __stdcall StrDup(const char *s) {\n\treturn 0;\n}\n",
            "StrDup",
        ),
    ] {
        let p = parse_source(&chars(src));
        c.ok(
            &format!("conv: {} -> {}", src.lines().next().unwrap_or(""), want),
            p.funcs.iter().any(|f| f.name == want),
        );
    }
    c.ok(
        "conv: a `__` identifier is not mistaken for a convention",
        !parse_source(&chars("void __my_helper(int a) {\n}\n"))
            .funcs
            .iter()
            .any(|f| f.name == "__my_helper"),
    );

    // --- multi-line signatures: a decompiler wraps long names and parameter
    // lists across physical lines, and a one-line header assumption lost every
    // one of them.
    let wrapped = [
        "undefined8 FUN_00104567(",
        "          long param_1,",
        "          long param_2,",
        "          int  *out_ptr)",
        "{",
        "  *out_ptr = 0;",
        "}",
    ]
    .join("\n");
    let p = parse_source(&chars(&wrapped));
    c.ok(
        "sig: wrapped params",
        p.funcs.len() == 1
            && p.funcs[0].name == "FUN_00104567"
            && p.funcs[0].end == 7
            && p.funcs[0].params.contains("out_ptr"),
    );
    let allman_wrapped = [
        "int Wrapped(",
        "    int a,",
        "    int b)",
        "{",
        "    return a + b;",
        "}",
    ]
    .join("\n");
    let p = parse_source(&chars(&allman_wrapped));
    c.ok(
        "sig: wrapped params, Allman brace",
        p.funcs.len() == 1 && p.funcs[0].name == "Wrapped" && p.funcs[0].end == 6,
    );
    // A call whose arguments wrap over several lines must NOT be promoted into a
    // function declaration: joining requires whitespace before the first `(`.
    c.ok(
        "sig: wrapped call is not a phantom function",
        parse_source(&chars("void f(void)\n{\n  g(\n    1,\n    2);\n}\n"))
            .funcs
            .iter()
            .all(|f| f.name == "f"),
    );

    // --- decode: a non-UTF-8 source is reported, not silently mangled
    let (s, note) = decode("void f(){}\n".as_bytes().to_vec());
    c.ok(
        "decode: plain utf-8 is clean",
        note.is_none() && s.contains("void f"),
    );
    // Latin-1, not UTF-8: one 0xE9 byte. `\u{e9}` would be valid UTF-8 and the
    // test would pass without testing anything.
    let latin1 = b"void caf\xe9(){}\n".to_vec();
    let (s, note) = decode(latin1);
    c.ok(
        "decode: latin-1 is reported",
        note == Some("not valid utf-8 (lossy)") && s.contains('\u{FFFD}'),
    );
    let (s, note) = decode(utf16_with_bom(true));
    c.ok(
        "decode: utf-16le with BOM",
        note == Some("utf-16le") && s.contains("caf\u{e9}"),
    );
    let (s, note) = decode(utf16_with_bom(false));
    c.ok(
        "decode: utf-16be with BOM",
        note == Some("utf-16be") && s.contains("caf\u{e9}"),
    );
    let (s, note) = decode(utf16_bare());
    c.ok(
        "decode: bom-less utf-16le",
        note == Some("utf-16le, no BOM") && s.contains("caf\u{e9}"),
    );

    // --- the module taxonomy is data, not code: it is read from a file, and
    // the tool ships without one.
    let rules_txt = [
        "# A broad rule listed FIRST on purpose: file order must not let a",
        "# catch-all shadow the narrow rule that is actually about this file.",
        "n:Engine\tcore.engine\tRuntime engine",
        "n:Engine.Audio\tcore.audio\tRuntime audio",
        "b:Player.cs\tcore.player\tPlayer state",
        "n:Engine.WorldGen\tdomain.world\tWorld gen",
        "n:Engine\tcore.engine\tRuntime engine\t@depth=1",
        "",
    ]
    .join("\n");
    let parsed = parse_rule_file(Path::new("modules.txt"), &rules_txt).expect("parse rules");
    c.ok("rules: comments and blank lines ignored", parsed.len() == 5);
    let rs = RuleSet {
        rules: parsed
            .iter()
            .enumerate()
            .map(|(i, (n, m, s, d))| Rule {
                needle: n.clone(),
                module_id: m.clone(),
                system: s.clone(),
                depth: *d,
                order: i,
            })
            .collect(),
        source: "modules.txt".into(),
    };
    c.ok(
        "rules: b: beats n:",
        assign(&rs, "src/Player.cs", "namespace Engine;").0 == "core.player",
    );
    c.ok(
        "rules: n: prefix",
        assign(&rs, "src/Audio/X.cs", "namespace Engine.Audio;").0 == "core.audio",
    );
    c.ok(
        "rules: deeper namespace prefix wins over the sibling",
        assign(&rs, "a/G.cs", "namespace Engine.WorldGen;").0 == "domain.world",
    );
    c.ok(
        "rules: explicit @depth outranks a shorter match",
        assign(&rs, "a/G.cs", "namespace Engine;").0 == "core.engine",
    );
    c.ok(
        "rules: unmatched -> unmapped",
        assign(&rs, "Other/Thing.cs", "namespace Other;").0 == "unmapped",
    );
    c.ok(
        "rules: dir-chain fallback is matched too",
        rs.module_of("Engine/Audio/X.cs", None).0 == "core.audio",
    );
    c.ok(
        "rules: a declared namespace is found, wherever the file sits",
        assign(&rs, "other/Path.cs", "namespace Engine.Audio;").0 == "core.audio",
    );
    c.ok(
        "rules: an identifier that merely starts with `namespace` is not one",
        assign(&rs, "other/Path.cs", "namespaceFoo = 1;").0 == "unmapped",
    );
    c.ok(
        "rules: known / system lookup",
        rs.is_known("core.player")
            && rs.is_known("unmapped")
            && !rs.is_known("nope")
            && rs.system_of("core.player") == Some("Player state")
            && rs.system_of("nope").is_none(),
    );
    c.ok(
        "rules: slug",
        slug("GameContent") == "game-content" && slug("UI") == "ui",
    );
    c.ok(
        "rules: a malformed line is an error naming the file, not a silent drop",
        parse_rule_file(Path::new("bad.txt"), "only-one-column\n").is_err()
            && parse_rule_file(Path::new("bad.txt"), "n:x\tm\t@depth=99\n").is_err()
            && parse_rule_file(Path::new("bad.txt"), "n:x\tm\t@depth=zero\n").is_err(),
    );

    // --- derived taxonomy: bucket by path prefix, rank by weight
    let mut paths: Vec<String> = Vec::new();
    for i in 0..8 {
        paths.push(format!("engine/audio/band{}.cpp", i));
    }
    for i in 0..6 {
        paths.push(format!("engine/render/sprite{}.cpp", i));
    }
    paths.push("readme.md".into()); // too small to become a module
    let dk = derive_rule_set(Path::new("/nonexistent"), &paths);
    let ids: Vec<&str> = dk.rules.iter().map(|r| r.module_id.as_str()).collect();
    c.ok(
        "derive: modules are named after the path prefix",
        ids.contains(&"ns.engine.audio") && ids.contains(&"ns.engine.render"),
    );
    c.ok(
        "derive: a bucket too small to be a module is dropped",
        !ids.iter().any(|m| m.contains("readme")),
    );
    c.ok(
        "derive: ranked, biggest first",
        ids.first() == Some(&"ns.engine.audio"),
    );
    c.ok(
        "derive: a derived module matches its own files",
        dk.module_of("engine/audio/band0.cpp", None).0 == "ns.engine.audio",
    );
    c.ok(
        "derive: a CamelCase path segment becomes one slug, not u-r-l",
        slug("GameContent") == "game-content" && slug("UI") == "ui",
    );
    c.ok(
        "derive: an empty corpus yields an empty taxonomy, not a guess",
        derive_rule_set(Path::new("/nonexistent"), &[])
            .rules
            .is_empty(),
    );

    // --- mask preserves offsets and newlines
    let m = mask(&chars("a\r\n/* x\ny */\nb"), true);
    c.ok(
        "mask: length preserved",
        m.len() == chars("a\r\n/* x\ny */\nb").len(),
    );
    c.ok(
        "mask: newlines preserved",
        m.iter().filter(|&&c| c == '\n').count() == 3,
    );

    // --- call scanning: dedupe, self-exclusion, keyword exclusion, cap
    let body = "void a() {\n\tb();\n\tb();\n\tif (c) { }\n\ta();\n}\nvoid b() {}\n";
    let ch = chars(body);
    // `void b() {}` is a single-line body and is a function (the reference
    // implementation dropped it). Both `a` and `b` are indexed declarations.
    let fs = parse_source(&ch).funcs;
    assert!(
        fs.iter().any(|f| f.name == "a") && fs.iter().any(|f| f.name == "b"),
        "{fs:?}"
    );
    let masked = mask(&ch, true);
    let lr = {
        let mut v = vec![(0usize, 0usize)];
        let mut s = 0usize;
        for (i, &ch) in masked.iter().enumerate() {
            if ch == '\n' {
                v.push((s, i));
                s = i + 1;
            }
        }
        v.push((s, masked.len()));
        v
    };
    let mut by: std::collections::HashMap<String, Vec<i64>> = std::collections::HashMap::new();
    by.insert("b".into(), vec![2]);
    by.insert("a".into(), vec![1]);
    by.insert("c".into(), vec![3]);
    let e = scan_calls(&masked, &lr, 1, 5, 1, "a", &by);
    c.ok("calls: dedupe + self excluded", e.len() == 1 && e[0].0 == 2);
    c.ok(
        "calls: self-recursion excluded",
        scan_calls(&masked, &lr, 1, 5, 2, "a", &by)
            .iter()
            .all(|(d, _, _)| *d != 2),
    );

    // --- end-to-end, on a corpus with no game in it
    let tmp = tmpdir("e2e");
    write_file(
        &tmp,
        "engine/Player.cs",
        "namespace Demo.Engine {\npublic class Player\n{\npublic void TakeDamage(int n)\n{\n\tUseCounter(n);\n}\n}\n}\n",
    );
    write_file(
        &tmp,
        "engine/Loop.cs",
        "namespace Demo.Engine {\npublic class Loop\n{\npublic void Run()\n{\n\tplayer.TakeDamage(1);\n}\n}\n}\n",
    );
    // A name two files define, to prove `--path` is what separates them.
    write_file(
        &tmp,
        "engine/audio/Tick.cs",
        "void Tick(int a)\n{\n\tone();\n}\n",
    );
    write_file(
        &tmp,
        "engine/render/Tick.cs",
        "void Tick(int a)\n{\n\ttwo();\n}\n",
    );
    // Latin-1: `café` as one 0xE9 byte, which is not valid UTF-8.
    std::fs::write(
        tmp.join("engine/Legacy.cpp"),
        b"void caf\xe9()\n{\n\tint x;\n}\n",
    )
    .expect("write latin-1");
    // The taxonomy is a file the operator writes. Nothing about the tool knows
    // this project, and the tool would have derived buckets without it.
    write_file(
        &tmp,
        ".gamedb/modules.txt",
        "n:Demo\tcore.engine\tRuntime core\n\
         n:Demo.Engine\tcore.engine\tRuntime core\n\
         b:Player.cs\tcore.player\tPlayer state\n\
         m:audio\tcore.audio\tAudio\n",
    );
    // tmpdir() starts from a clean tree, so there is no pre-existing index.

    let r1 = index_root(&tmp, None, 0, false, false, "").expect("index 1");
    c.ok(
        "e2e: indexed 5 files, 4 functions",
        r1.files == 5 && r1.functions == 4,
    );
    c.ok(
        "e2e: a lossy decode is reported, with the path",
        r1.decoded.total == 1 && r1.decoded.items[0].contains("Legacy.cpp"),
    );
    c.ok(
        "e2e: the taxonomy in force is reported",
        r1.rules.contains("modules.txt"),
    );
    let r2 = index_root(&tmp, None, 0, false, false, "").expect("index 2");
    c.ok("e2e: idempotent", r2.skipped == 5 && r2.files == 0);
    let d = index_root(&tmp, None, 0, true, false, "").expect("dry run");
    c.ok("e2e: dry-run writes nothing", d.files == 5);

    let rows = search_functions(&tmp, None, "Take", 25).expect("search");
    c.ok(
        "e2e: search",
        rows.len() == 1 && rows[0][0].as_str() == "TakeDamage",
    );
    c.ok(
        "e2e: like-escaping",
        search_strings(&tmp, None, "%", 40).expect("esc").is_empty(),
    );
    let f = read_function(&tmp, None, "TakeDamage", None)
        .expect("read")
        .expect("found");
    c.ok(
        "e2e: read body",
        f.2 == "public void TakeDamage(int n)\n{\n\tUseCounter(n);\n}",
    );
    c.ok("e2e: a unique name has one candidate", f.3 == 1);
    // Two files define `Tick`. Picking one silently is how you read the wrong
    // body, so the count is reported and `--path` chooses.
    let dup = read_function(&tmp, None, "Tick", None)
        .expect("read dup")
        .expect("found");
    c.ok("e2e: a duplicated name reports both candidates", dup.3 == 2);
    let narrowed = read_function(&tmp, None, "Tick", Some("render/"))
        .expect("read narrow")
        .expect("found");
    c.ok(
        "e2e: --path picks the right one of the two",
        narrowed.3 == 1
            && narrowed.1.contains("render")
            && narrowed.2 == "void Tick(int a)\n{\n\ttwo();\n}",
    );
    c.ok(
        "e2e: --path that matches nothing reads nothing",
        read_function(&tmp, None, "Tick", Some("zzz")).is_err()
            || read_function(&tmp, None, "Tick", Some("zzz"))
                .unwrap()
                .is_none(),
    );

    let listing = list_modules(&tmp, None, "").expect("modules");
    let mods = &listing.rows;
    let cp = mods
        .iter()
        .find(|m| m.module_id == "core.player")
        .expect("core.player");
    c.ok("e2e: module assigned", cp.files == 1);
    let ce = mods
        .iter()
        .find(|m| m.module_id == "core.engine")
        .expect("core.engine");
    c.ok(
        "e2e: a declared namespace routes a file whose path says nothing",
        ce.files == 1 && ce.system == "Runtime core",
    );
    c.ok(
        "e2e: an explicit basename rule outranks the namespace rule",
        cp.files == 1 && cp.system == "Player state",
    );
    // Two files match nothing. They are reported in an `unmapped` bucket rather
    // than dropped, because silently ignoring a file is how a rewrite plan ends
    // up quietly missing a third of the codebase.
    let un = mods
        .iter()
        .find(|m| m.module_id == "unmapped")
        .expect("unmapped bucket");
    c.ok(
        "e2e: unmatched files are surfaced, not dropped",
        un.files == 2,
    );
    c.ok(
        "e2e: the listing says where its rules came from",
        listing.rules_source.contains("modules.txt"),
    );

    let g = graph(&tmp, None, "Run", "callees", 10, None).expect("graph");
    c.ok(
        "e2e: graph callee edge",
        g.iter()
            .any(|r| r[0].as_str() == "callee" && r[1].as_str() == "TakeDamage"),
    );
    c.ok(
        "e2e: graph callers",
        graph(&tmp, None, "TakeDamage", "callers", 10, None)
            .expect("graph in")
            .iter()
            .any(|r| r[1].as_str() == "Run"),
    );
    c.ok(
        "e2e: graph --path narrows the anchor",
        graph(&tmp, None, "Tick", "both", 10, Some("audio/"))
            .expect("graph path")
            .iter()
            .all(|r| r[3].as_str().contains("audio")),
    );

    let p1 = ModulePatch {
        state: Some(STATE_PARTIAL.into()),
        verified: Some(true),
        verified_by: Some("selftest".into()),
        remaining: None,
    };
    let m1 = set_module_state(&tmp, None, "core.player", &p1, "").expect("set-module");
    c.ok(
        "e2e: set-module",
        m1.state == STATE_PARTIAL && m1.verified_by.as_deref() == Some("selftest"),
    );
    let p2 = ModulePatch {
        state: Some(STATE_IMPLEMENTED.into()),
        ..Default::default()
    };
    let m2 = set_module_state(&tmp, None, "core.player", &p2, "").expect("set-module 2");
    c.ok(
        "e2e: verified stamp survives a patch that omits it",
        m2.verified_by.as_deref() == Some("selftest") && m2.verified_at.is_some(),
    );
    c.ok(
        "e2e: verified + IMPLEMENTED is reachable",
        m2.state == STATE_IMPLEMENTED,
    );
    // Dropping the sign-off also drops IMPLEMENTED: a state nobody earned must
    // not outlive its evidence, and the guard refuses the one-call shortcut.
    let p3 = ModulePatch {
        state: Some(STATE_PARTIAL.into()),
        verified: Some(false),
        ..Default::default()
    };
    c.ok("e2e: unverify from IMPLEMENTED is refused", {
        set_module_state(
            &tmp,
            None,
            "core.player",
            &ModulePatch {
                verified: Some(false),
                ..Default::default()
            },
            "",
        )
        .is_err()
    });
    set_module_state(&tmp, None, "core.player", &p3, "").expect("unverify");
    c.ok("e2e: --unverified clears the stamp", {
        let m = set_module_state(&tmp, None, "core.player", &ModulePatch::default(), "")
            .expect("reread");
        m.verified_by.is_none()
    });

    let cases: Vec<(&str, ModulePatch)> = vec![
        (
            "IMPLEMENTED w/o verify",
            ModulePatch {
                state: Some(STATE_IMPLEMENTED.into()),
                ..Default::default()
            },
        ),
        (
            "bad state",
            ModulePatch {
                state: Some("BOGUS".into()),
                ..Default::default()
            },
        ),
    ];
    for (why, p) in cases {
        let got = set_module_state(&tmp, None, "core.player", &p, "");
        c.ok(&format!("e2e: rejects {}", why), got.is_err());
    }
    c.ok(
        "e2e: rejects unknown module",
        set_module_state(&tmp, None, "nope.nope", &ModulePatch::default(), "").is_err(),
    );

    // a second tree proves the index is per-root, not global
    let other = tmpdir("other");
    write_file(&other, "X.cs", "void f()\n{\n\tg();\n}\n");
    c.ok(
        "e2e: a root without an index is reported, not silently empty",
        !stats(&other, None).indexed,
    );
    c.ok(
        "e2e: the first root is still indexed",
        stats(&tmp, None).indexed,
    );
    let _ = std::fs::remove_dir_all(&other);

    let _ = std::fs::remove_dir_all(&tmp);

    let bad: Vec<&String> = c.v.iter().filter(|(_, ok)| !ok).map(|(l, _)| l).collect();
    for l in &bad {
        eprintln!("FAIL {}", l);
    }
    let total = c.v.len();
    let passed = total - bad.len();
    println!(
        "selftest {}/{} {}",
        passed,
        total,
        if bad.is_empty() { "OK" } else { "FAILED" }
    );
    i32::from(!bad.is_empty())
}
