use crate::cli::{jstr, Args};
use crate::db::{Db, Val};
use crate::ida::field;
use crate::store::index_root;
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

type Result<T> = std::result::Result<T, String>;

struct Stage(PathBuf);

impl Drop for Stage {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn ghidra(args: &Args, database: &Path, output: &Path, json: &Db) -> Result<String> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_nanos();
    let stage = Stage(output.join(format!(".gamedb-stage-{}-{stamp}", std::process::id())));
    fs::create_dir(&stage.0).map_err(|e| e.to_string())?;
    let source = stage.0.join("decompiled.c");
    let response = stage.0.join("response.json");
    let command = args
        .ghidra_command
        .as_ref()
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("GAMEDB_GHIDRA").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("ghidra"));
    let mut child = Command::new(command)
        .args(["program", "export", "c", "--project"])
        .arg(database)
        .arg("--program")
        .arg(args.program.as_deref().unwrap())
        .arg("--output")
        .arg(&source)
        .arg("--json")
        .stdin(Stdio::null())
        .stdout(fs::File::create(&response).map_err(|e| e.to_string())?)
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("start ghidra-cli: {e}"))?;
    let started = Instant::now();
    let timeout = Duration::from_secs(args.timeout.unwrap_or(3600));
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() < timeout => thread::sleep(Duration::from_millis(20)),
            result => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(match result {
                    Err(e) => e.to_string(),
                    _ => "Ghidra export timed out; the bridge job may still be running".into(),
                });
            }
        }
    };
    let response = fs::read_to_string(&response).map_err(|e| e.to_string())?;
    if !status.success() {
        return Err(format!("Ghidra export failed ({status}): {response}"));
    }
    for path in ["$.error", "$[0].error", "$[0].data.error"] {
        let error = field(json, &response, path)?;
        if error != Val::Null {
            return Err(format!("Ghidra export: {}", error.as_str()));
        }
    }
    if fs::metadata(&source)
        .map_err(|e| format!("Ghidra produced no C export: {e}"))?
        .len()
        == 0
    {
        return Err("Ghidra produced an empty C export; previous export was preserved".into());
    }
    let summary = format!("{{\"backend\":\"ghidra\",\"database\":{},\"program\":{},\"source\":{},\"manifest\":{},\"exported\":null,\"failed\":null,\"exported_at_unix\":{stamp}}}", jstr(&database.to_string_lossy()), jstr(args.program.as_deref().unwrap()), jstr(&output.join("decompiled.c").to_string_lossy()), jstr(&output.join(".gamedb-export.json").to_string_lossy()));
    fs::write(stage.0.join("manifest.json"), &summary).map_err(|e| e.to_string())?;
    fs::rename(&source, output.join("decompiled.c")).map_err(|e| e.to_string())?;
    if stage.0.join("decompiled.h").exists() {
        fs::rename(stage.0.join("decompiled.h"), output.join("decompiled.h"))
            .map_err(|e| e.to_string())?;
    }
    fs::rename(
        stage.0.join("manifest.json"),
        output.join(".gamedb-export.json"),
    )
    .map_err(|e| e.to_string())?;
    Ok(summary)
}

pub fn run(args: &Args) -> Result<i32> {
    let database = fs::canonicalize(&args.root).map_err(|e| e.to_string())?;
    let extension = database
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let backend = match extension.as_str() {
        "i64" | "idb" => "ida",
        "gpr" => "ghidra",
        _ => {
            return Err(
                "index input must be a source directory, .i64/.idb database or .gpr project".into(),
            )
        }
    };
    if backend == "ghidra" && args.program.as_deref().is_none_or(|p| p.trim().is_empty()) {
        return Err(
            "index PROJECT.gpr requires --program NAME to select the Ghidra program".into(),
        );
    }
    if backend == "ida" && (args.program.is_some() || args.ghidra_command.is_some()) {
        return Err("--program and --ghidra-command apply only to .gpr projects".into());
    }
    if backend == "ghidra" && (args.ida_dir.is_some() || args.mcp_command.is_some()) {
        return Err("--ida-dir and --mcp-command apply only to IDA databases".into());
    }
    let stem = database.file_stem().unwrap().to_string_lossy();
    let default_name = if let Some(program) = &args.program {
        let safe: String = program
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || matches!(c, '-' | '_' | '.') {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        format!("{stem}-{safe}-source")
    } else {
        format!("{stem}-source")
    };
    let output = args
        .output_dir
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(|| database.with_file_name(default_name));
    if args.dry_run {
        if args.json {
            println!(
                "{{\"dry_run\":true,\"backend\":{},\"source_root\":{}}}",
                jstr(backend),
                jstr(&output.to_string_lossy())
            );
        } else if !args.quiet {
            println!(
                "dry-run backend={backend} database={} source_root={}",
                database.display(),
                output.display()
            );
        }
        return Ok(0);
    }
    fs::create_dir_all(&output).map_err(|e| e.to_string())?;
    let output = fs::canonicalize(output).map_err(|e| e.to_string())?;
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(output.join(".gamedb-export.lock"))
        .map_err(|e| e.to_string())?;
    lock.try_lock()
        .map_err(|e| format!("export directory is locked: {e}"))?;
    let json = Db::open(Path::new(":memory:"), false)?;
    let manifest = output.join(".gamedb-export.json");
    let previous = if manifest.exists() {
        manifest.clone()
    } else {
        output.join(".ida-export.json")
    };
    if previous.exists() {
        let contents = fs::read_to_string(&previous).map_err(|e| e.to_string())?;
        if field(&json, &contents, "$.database")?.as_str() != database.to_string_lossy()
            || field(&json, &contents, "$.program")?.as_str()
                != args.program.as_deref().unwrap_or("")
        {
            return Err("output directory belongs to another database or Ghidra program".into());
        }
    } else if output.join("decompiled.c").exists() {
        return Err("refusing to overwrite decompiled.c without an export manifest; choose another --output-dir".into());
    }
    let summary = if backend == "ida" {
        crate::ida::export(args, &database, &output)?
    } else {
        ghidra(args, &database, &output, &json)?
    };
    let report = index_root(
        &output,
        args.db.as_deref(),
        args.verbose,
        false,
        true,
        args.rules.as_deref().unwrap_or(""),
    )?;
    let failed = field(&json, &summary, "$.failed")?;
    if args.json {
        println!(
            "{{\"export\":{summary},\"indexed_functions\":{},\"index_failed\":{},\"index\":{}}}",
            report.functions,
            report.failed.total,
            jstr(&crate::db::db_path_for(&output, args.db.as_deref()).to_string_lossy())
        );
    } else if !args.quiet {
        let count = match &failed {
            Val::Int(n) => n.to_string(),
            _ => "unreported".into(),
        };
        println!("backend={backend} indexed={} decompile_failed={count} index_failed={} source_root={} db={}", report.functions, report.failed.total, output.display(), crate::db::db_path_for(&output, args.db.as_deref()).display());
    }
    if failed.as_i64() > 0 {
        eprintln!(
            "partial export: {} functions could not be decompiled; see {}",
            failed.as_i64(),
            manifest.display()
        );
    }
    if report.failed.total > 0 {
        return Err(format!(
            "indexing failed for {} files: {}",
            report.failed.total,
            report.failed.items.join(", ")
        ));
    }
    Ok(0)
}
