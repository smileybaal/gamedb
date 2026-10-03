//! Focused `cargo test` coverage for the parts of gamedb where a regression is
//! expensive to spot inside the 90-line self-test rollup: the header matcher,
//! the encoding decoder, the module rule ranking, and the rule-file parser.
//!
//! `selftest_passes` runs the whole built-in suite too, so `cargo test` is a
//! superset of `gamedb selftest` rather than a second, thinner thing to remember.

use gamedb::modules::{derive_rule_set, parse_rule_file, slug, Rule, RuleSet};
use gamedb::parse::parse_source;
use gamedb::rx::{is_modifier_tok, match_header};
use gamedb::selftest;
use gamedb::store::decode;
use std::path::Path;

fn chars(s: &str) -> Vec<char> {
    s.chars().collect()
}

fn names(s: &str) -> Vec<String> {
    parse_source(&chars(s))
        .funcs
        .into_iter()
        .map(|f| f.name)
        .collect()
}

#[test]
fn selftest_passes() {
    assert_eq!(selftest::run(), 0, "gamedb selftest reported a failure");
}

// --- rx.rs: the modifier skip is what stops decompiler calling conventions
// from being read as the function's own name.
#[test]
fn a_calling_convention_is_not_the_name() {
    for header in [
        "void __thiscall FUN_004087c6(void)\n{",
        "static inline int helper(int a)\n{",
        "int __cdecl thing(void)\n{",
        "__fastcall FUN_00(void)\n{",
    ] {
        let (name, params) = match_header(&chars(header)).expect(header);
        assert!(!is_modifier_tok(&name), "{header} -> {name}");
        assert!(!params.is_empty(), "{header} lost its parameters");
    }
}

#[test]
fn a_call_convention_token_is_recognised_by_shape_not_by_list() {
    // Ghidra emits `__thiscall`, MSVC emits `__stdcall`; both are `__` + a word
    // ending in `call`. A hardcoded list would need every vendor's spelling.
    assert!(is_modifier_tok("__thiscall"));
    assert!(is_modifier_tok("__stdcall"));
    assert!(is_modifier_tok("WINAPI"));
    assert!(!is_modifier_tok("actual"));
}

// --- parse.rs: wrapped signatures. Losing these loses whole subsystems on a
// corpus that formats its declarations over several lines.
#[test]
fn a_signature_wrapped_over_lines_is_one_function() {
    let src = "void FUN_00104567(\n  char *out_ptr,\n  int a)\n{\n  *out_ptr = 0;\n}\n";
    let p = parse_source(&chars(src));
    assert_eq!(p.funcs.len(), 1, "got {:?}", names(src));
    assert_eq!(p.funcs[0].name, "FUN_00104567");
    assert!(p.funcs[0].params.contains("out_ptr"));
}

#[test]
fn a_wrapped_call_site_is_not_a_phantom_function() {
    // `g(` on its own line must not be promoted into a declaration.
    let src = "void f(void)\n{\n  g(\n    1,\n    2);\n}\n";
    assert_eq!(names(src), vec!["f".to_string()]);
}

// --- store.rs: encoding. NUL is valid UTF-8, so BOM-less UTF-16 decodes
// "successfully" into garbage and every line offset still looks right.
#[test]
fn bom_less_utf16_is_not_mistaken_for_utf8() {
    let mut le = Vec::new();
    for c in "void f(){}".encode_utf16() {
        le.extend_from_slice(&c.to_le_bytes());
    }
    let (s, note) = decode(le);
    assert_eq!(note, Some("utf-16le, no BOM"));
    assert_eq!(s, "void f(){}");

    let mut be = Vec::new();
    for c in "void f(){}".encode_utf16() {
        be.extend_from_slice(&c.to_be_bytes());
    }
    let (s, note) = decode(be);
    assert_eq!(note, Some("utf-16be, no BOM"));
    assert_eq!(s, "void f(){}");
}

#[test]
fn a_bom_is_consumed_not_indexed_as_text() {
    let mut b = vec![0xEF, 0xBB, 0xBF];
    b.extend_from_slice(b"void f(){}");
    let (s, note) = decode(b);
    assert_eq!(note, None);
    assert_eq!(s, "void f(){}");
}

#[test]
fn undecodable_bytes_are_reported_not_swallowed() {
    // One 0xE9 byte is Latin-1 `e-acute` and not valid UTF-8.
    let (s, note) = decode(b"void caf\xe9(){}".to_vec());
    assert_eq!(note, Some("not valid utf-8 (lossy)"));
    assert!(
        s.contains('\u{FFFD}'),
        "lossy decode should say so in the text too"
    );
}

// --- modules.rs: the taxonomy. No rule here mentions any real project.
fn rules_from(text: &str) -> RuleSet {
    let rows = parse_rule_file(Path::new("test-rules.txt"), text).expect("rules parse");
    RuleSet {
        rules: rows
            .into_iter()
            .enumerate()
            .map(|(order, (needle, module_id, system, depth))| Rule {
                needle,
                module_id,
                system,
                depth,
                order,
            })
            .collect(),
        source: "test-rules.txt".into(),
    }
}

const RULES: &str = "\
# Broad first on purpose: a catch-all listed before the narrow rule it
# shadows must still lose. Ordering rules by hand is a losing game.
n:Acme\tcore.acme\tAcme core
n:Acme.Audio\tcore.audio\tAudio
b:Player.cs\tcore.player\tPlayer state
x:Acme\tcore.exact\tExact only
";

#[test]
fn a_narrow_namespace_beats_a_broad_one_in_any_file_order() {
    let rs = rules_from(RULES);
    assert_eq!(
        rs.module_of("src/A.cs", Some("namespace Acme.Audio;")).0,
        "core.audio"
    );
    assert_eq!(
        rs.module_of("src/A.cs", Some("namespace Acme.Rendering;"))
            .0,
        "core.acme"
    );
}

#[test]
fn naming_a_file_outranks_naming_its_namespace() {
    let rs = rules_from(RULES);
    assert_eq!(
        rs.module_of("deep/dir/Player.cs", Some("namespace Acme.Audio;"))
            .0,
        "core.player"
    );
}

#[test]
fn an_exact_namespace_does_not_match_its_children() {
    let rs = rules_from(RULES);
    assert_eq!(
        rs.module_of("src/A.cs", Some("namespace Acme;")).0,
        "core.exact"
    );
    assert_eq!(
        rs.module_of("src/A.cs", Some("namespace Acme.Audio;")).0,
        "core.audio"
    );
}

#[test]
fn a_file_matching_nothing_is_reported_not_dropped() {
    let rs = rules_from(RULES);
    assert_eq!(
        rs.module_of("src/A.cs", Some("namespace Other;")).0,
        "unmapped"
    );
    assert!(rs.is_known("unmapped"));
    assert!(!rs.is_known("core.nonexistent"));
}

#[test]
fn a_malformed_rule_file_names_the_line_instead_of_being_skipped() {
    for bad in [
        "only-one-column\n",
        "n:x\tm\t@depth=99\n",
        "n:x\tm\t@depth=zero\n",
    ] {
        let err = parse_rule_file(Path::new("bad.txt"), bad)
            .expect_err(&format!("{bad:?} should not parse"));
        assert!(
            err.contains("bad.txt:1"),
            "error should name the file: {err}"
        );
    }
}

#[test]
fn tab_aligned_columns_parse_the_way_a_person_writes_them() {
    // Aligning a rule file with tab stops is what every editor does by
    // default. Empty fields between real ones are not a malformed rule.
    let rows = parse_rule_file(
        Path::new("aligned.txt"),
        "n:Acme.Audio\t\t\tcore.audio\t\tRuntime\nb:Player.cs\tcore.player\tPlayer state\n",
    )
    .expect("aligned rules parse");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].1, "core.audio");
    assert_eq!(rows[0].2, "Runtime");
    assert_eq!(rows[1].2, "Player state");
}

#[test]
fn a_derived_taxonomy_names_itself_after_the_corpus() {
    let mut paths: Vec<String> = Vec::new();
    for i in 0..8 {
        paths.push(format!("engine/audio/band{i}.cpp"));
    }
    for i in 0..6 {
        paths.push(format!("engine/render/sprite{i}.cpp"));
    }
    let rs = derive_rule_set(Path::new("."), &paths);
    let ids: Vec<&str> = rs.rules.iter().map(|r| r.module_id.as_str()).collect();
    assert_eq!(
        ids,
        vec!["ns.engine.audio", "ns.engine.render"],
        "biggest bucket first"
    );
    assert_eq!(
        rs.module_of("engine/audio/band0.cpp", None).0,
        "ns.engine.audio"
    );
    assert!(derive_rule_set(Path::new("."), &[]).rules.is_empty());
}

#[test]
fn a_camel_case_name_slugifies_without_splitting_the_acronym() {
    assert_eq!(slug("GameContent"), "game-content");
    assert_eq!(slug("UI"), "ui");
    assert_eq!(slug("HTTPClient"), "http-client");
    assert_eq!(slug("engine.audio"), "engine.audio");
}

// --- language coverage: the shapes decompilers actually emit for C, C++, C#,
// Java. Each of these was a silent miss before the tolerant matcher existed.
#[test]
fn cpp_out_of_line_definitions_are_functions() {
    let src = concat!(
        "namespace Game {\n",
        "class Player {\n",
        "public:\n",
        "    void Update(int dt);\n",
        "    int GetHealth() const;\n",
        "private:\n",
        "    int health_;\n",
        "};\n",
        "void Player::Update(int dt) {\n",
        "    health_ += dt;\n",
        "}\n",
        "int Player::GetHealth() const {\n",
        "    return health_;\n",
        "}\n",
        "std::shared_ptr<Player> MakePlayer() {\n",
        "    return nullptr;\n",
        "}\n",
        "}\n",
    );
    let p = parse_source(&chars(src));
    let nm: Vec<&str> = p.funcs.iter().map(|f| f.name.as_str()).collect();
    for want in ["Update", "GetHealth", "MakePlayer"] {
        assert!(nm.contains(&want), "missing {want} in {nm:?}");
    }
    // `void Update(int dt);` is a declaration, not a second definition.
    assert_eq!(nm.iter().filter(|n| **n == "Update").count(), 1);
    let fields: Vec<&str> = p
        .syms
        .iter()
        .filter(|s| s.kind == "field")
        .map(|s| s.name.as_str())
        .collect();
    assert!(fields.contains(&"health_"), "fields: {fields:?}");
}

#[test]
fn a_java_throws_clause_does_not_hide_the_method() {
    let src = concat!(
        "public class Player {\n",
        "    @Override\n",
        "    public void update(int dt) throws IllegalStateException {\n",
        "        this.health += dt;\n",
        "    }\n",
        "}\n",
    );
    let nm = names(src);
    assert!(nm.iter().any(|n| n == "update"), "{nm:?}");
}

#[test]
fn a_c_struct_body_yields_its_fields() {
    let src = concat!(
        "typedef struct SavedEntity {\n",
        "    int id;\n",
        "    char name[32];\n",
        "    SavedEntity *next;\n",
        "} SavedEntity;\n",
    );
    let p = parse_source(&chars(src));
    let fields: Vec<&str> = p
        .syms
        .iter()
        .filter(|s| s.kind == "field")
        .map(|s| s.name.as_str())
        .collect();
    for want in ["id", "name", "next"] {
        assert!(fields.contains(&want), "missing {want} in {fields:?}");
    }
}

#[test]
fn an_expression_body_is_the_function_body() {
    let src = concat!(
        "public class Player {\n",
        "    private int health;\n",
        "    public int TakeDamage(int amount) => this.health -= amount;\n",
        "}\n",
    );
    let p = parse_source(&chars(src));
    let f = p
        .funcs
        .iter()
        .find(|f| f.name == "TakeDamage")
        .expect("TakeDamage");
    assert_eq!(f.start, 3);
    assert_eq!(f.end, 3);
}

#[test]
fn statement_keywords_and_primary_constructors_are_not_functions() {
    let src = concat!(
        "fun main() {\n",
        "    if (ready) {\n",
        "        when (state) {\n",
        "            else -> go();\n",
        "        }\n",
        "    }\n",
        "}\n",
        "class Player(private var health: Int) {\n",
        "    fun update(dt: Int) {\n",
        "        health += dt\n",
        "    }\n",
        "}\n",
    );
    let nm = names(src);
    assert!(
        !nm.iter().any(|n| n == "if" || n == "when"),
        "control keyword became a function: {nm:?}"
    );
    assert!(
        !nm.iter().any(|n| n == "Player"),
        "a primary constructor is a type, not a function: {nm:?}"
    );
    assert!(nm.iter().any(|n| n == "update"), "{nm:?}");
}

// --- Java parity: the four shapes C/C++/C# already cover, plus the two
// Java-only member sources (record components, enum constants).
fn fields_of(s: &str) -> Vec<String> {
    parse_source(&chars(s))
        .syms
        .iter()
        .filter(|x| x.kind == "field")
        .map(|x| x.name.clone())
        .collect()
}

#[test]
fn a_single_line_body_is_a_function() {
    let src = concat!(
        "public class P {\n",
        "    public int getHealth() { return this.health; }\n",
        "    public void setHealth(int h) { this.health = h; }\n",
        "}\n",
    );
    let nm = names(src);
    assert!(nm.iter().any(|n| n == "getHealth"), "{nm:?}");
    assert!(nm.iter().any(|n| n == "setHealth"), "{nm:?}");
}

#[test]
fn java_enum_constants_are_fields() {
    let src = concat!(
        "enum State {\n",
        "    IDLE, RUNNING(3), DEAD;\n",
        "    private final int speed;\n",
        "    State(int s) { this.speed = s; }\n",
        "}\n",
    );
    let f = fields_of(src);
    for want in ["IDLE", "RUNNING", "DEAD", "speed"] {
        assert!(f.contains(&want.to_string()), "missing {want} in {f:?}");
    }
}

#[test]
fn java_record_components_are_fields() {
    let src = concat!(
        "record Point(int x, int y) {\n",
        "    public int sum() { return x + y; }\n",
        "}\n",
    );
    let f = fields_of(src);
    for want in ["x", "y"] {
        assert!(f.contains(&want.to_string()), "missing {want} in {f:?}");
    }
}

#[test]
fn a_record_compact_constructor_is_not_a_field() {
    let src = concat!(
        "record Point(int x, int y) {\n",
        "    public Point {\n",
        "        if (x < 0) { throw new IllegalArgumentException(\"x\"); }\n",
        "    }\n",
        "}\n",
    );
    let p = parse_source(&chars(src));
    let fields: Vec<&str> = p
        .syms
        .iter()
        .filter(|s| s.kind == "field")
        .map(|s| s.name.as_str())
        .collect();
    assert_eq!(
        fields,
        vec!["x", "y"],
        "a compact constructor must not masquerade as a field: {fields:?}"
    );
    assert!(
        p.syms
            .iter()
            .any(|s| s.kind == "method" && s.name == "Point"),
        "the compact constructor should still be recorded: {:?}",
        p.syms
    );
}

/// Index `files` into a throwaway tree and return every edge as
/// `(caller, callee, line, hits)`, sorted.
fn edges_of(tag: &str, files: &[(&str, &str)]) -> Vec<(String, String, i64, i64)> {
    let mut root = std::env::temp_dir();
    root.push(format!("gamedb-audit-{}-{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    for (rel, body) in files {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    }
    gamedb::store::index_root(&root, None, 0, false, false, "").expect("index");
    let db = gamedb::db::open_existing(&root, None, true).expect("open");
    let mut out: Vec<_> = db
        .query(
            "SELECT s.name, d.name, e.line, e.hits FROM edges e \
             JOIN symbols s ON s.id = e.src_id JOIN symbols d ON d.id = e.dst_id",
            &[],
        )
        .expect("query")
        .into_iter()
        .map(|r| {
            (
                r[0].as_str().to_string(),
                r[1].as_str().to_string(),
                r[2].as_i64(),
                r[3].as_i64(),
            )
        })
        .collect();
    out.sort();
    drop(db);
    let _ = std::fs::remove_dir_all(&root);
    out
}

#[test]
fn a_definition_line_is_not_a_call_to_its_namesakes() {
    let e = edges_of(
        "defline",
        &[
            ("A.cs", "public class A\n{\n    private void Update()\n    {\n        Tick();\n    }\n}\n"),
            ("B.cs", "public class B\n{\n    private void Update()\n    {\n        Tick();\n    }\n    private void Tick()\n    {\n    }\n}\n"),
        ],
    );
    // Each `Update` calls `Tick` on line 5 and nothing else; neither
    // `void Update()` header is a call to the other `Update`.
    assert_eq!(
        e,
        vec![
            ("Update".to_string(), "Tick".to_string(), 5, 1),
            ("Update".to_string(), "Tick".to_string(), 5, 1),
        ],
        "{e:?}"
    );
}

#[test]
fn hits_counts_repeated_calls_and_line_is_the_first() {
    let e = edges_of(
        "hits",
        &[(
            "A.cs",
            "public class A\n{\n    void Run()\n    {\n        Tick();\n        Tick();\n        Tick();\n    }\n    void Tick() { }\n}\n",
        )],
    );
    assert_eq!(
        e,
        vec![("Run".to_string(), "Tick".to_string(), 5, 3)],
        "{e:?}"
    );
}
