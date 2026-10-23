use gamedb::parse::parse_source;

#[test]
fn ida_function_pointer_returns_are_indexed_without_callback_variables() {
    let source = "__int64 (**init_proc())(void)\n{\n  __int64 (**result)(void);\n  result = &_gmon_start__;\n  return result;\n}\n\nint (*factory(int mode))(double)\n{\n  int (*callback)(double) = handler;\n  return callback;\n}\n\nint __fastcall mcp_probe(int value)\n{\n  return 7 * value + 13;\n}\n";
    let parsed = parse_source(&source.chars().collect::<Vec<_>>());
    let names: Vec<_> = parsed.funcs.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, ["init_proc", "factory", "mcp_probe"]);
    assert_eq!(parsed.funcs[1].params, "int mode");
}

#[test]
fn ghidra_and_ida_declarations_can_share_one_source_tree() {
    let source = "undefined4 __thiscall FUN_004087c6(int value)\n{\n  return FUN_00401000(value);\n}\n\nundefined4 FUN_00401000(int value)\n{\n  return value + 1;\n}\n\n__int64 (**init_proc())(void)\n{\n  return callback;\n}\n\nint __fastcall ida_probe(int value)\n{\n  return value * 7 + 13;\n}\n";
    let parsed = parse_source(&source.chars().collect::<Vec<_>>());
    let names: Vec<_> = parsed.funcs.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(
        names,
        ["FUN_004087c6", "FUN_00401000", "init_proc", "ida_probe"]
    );
    assert_eq!(parsed.funcs[0].params, "int value");
    assert_eq!(parsed.funcs[3].params, "int value");
}
