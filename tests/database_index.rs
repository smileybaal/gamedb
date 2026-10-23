use gamedb::db::{Db, Val};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

struct Project {
    root: PathBuf,
    ghidra: PathBuf,
}

impl Project {
    fn path(&self) -> PathBuf {
        self.root.join("round-trip.gpr")
    }
    fn ghidra(&self, args: &[&str]) {
        let result = Command::new(&self.ghidra)
            .args(args)
            .arg("--project")
            .arg(self.path())
            .arg("--program")
            .arg("probe")
            .arg("--json")
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
    }
}

impl Drop for Project {
    fn drop(&mut self) {
        let _ = Command::new(&self.ghidra)
            .arg("stop")
            .arg("--project")
            .arg(self.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn indexed_names(source: &Path) -> Vec<String> {
    let db = Db::open(&source.join(".gamedb/index.sqlite"), true).unwrap();
    db.query(
        "SELECT name FROM functions WHERE name LIKE ? ORDER BY name",
        &[Val::Text("sync_probe%".into())],
    )
    .unwrap()
    .iter()
    .map(|row| row[0].as_str().into())
    .collect()
}

#[test]
#[ignore = "requires configured akiselev/ghidra-cli, Ghidra and cc"]
fn real_ghidra_index_refreshes_export_after_rename() {
    let root = std::env::temp_dir().join(format!(
        "gamedb-ghidra-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    let project = Project {
        root,
        ghidra: std::env::var_os("GAMEDB_GHIDRA")
            .map(PathBuf::from)
            .unwrap_or_else(|| "ghidra".into()),
    };
    let source = project.root.join("probe.c");
    let binary = project.root.join("probe");
    fs::write(&source, "__attribute__((noinline)) int sync_probe(int x) { return x * 7 + 13; }\nint main(void) { return sync_probe(6); }\n").unwrap();
    assert!(Command::new("cc")
        .args(["-g", "-O1", "-fno-inline"])
        .arg(&source)
        .arg("-o")
        .arg(&binary)
        .status()
        .unwrap()
        .success());
    let imported = Command::new(&project.ghidra)
        .arg("import")
        .arg(&binary)
        .arg("--project")
        .arg(project.path())
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        imported.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&imported.stdout),
        String::from_utf8_lossy(&imported.stderr)
    );
    let output = project.root.join("export ü 'quoted'");
    let index = || {
        let result = Command::new(env!("CARGO_BIN_EXE_gamedb"))
            .arg("index")
            .arg(project.path())
            .args(["--program", "probe", "--output-dir"])
            .arg(&output)
            .arg("--ghidra-command")
            .arg(&project.ghidra)
            .arg("--json")
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
    };
    index();
    assert_eq!(indexed_names(&output), ["sync_probe"]);
    project.ghidra(&["rename", "sync_probe", "sync_probe_renamed"]);
    index();
    assert_eq!(indexed_names(&output), ["sync_probe_renamed"]);
    let exported = fs::read_to_string(output.join("decompiled.c")).unwrap();
    assert!(exported.contains("sync_probe_renamed"));
    assert!(!exported.contains("sync_probe("));
    let result = Command::new(env!("CARGO_BIN_EXE_gamedb"))
        .args(["index", "-r"])
        .arg(&output)
        .arg("--json")
        .output()
        .unwrap();
    assert!(result.status.success());
    assert_eq!(indexed_names(&output), ["sync_probe_renamed"]);
}
