use crate::cli::{jstr, Args};
use crate::db::{Db, Val};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

type Result<T> = std::result::Result<T, String>;

struct Mcp {
    child: Child,
    input: Option<ChildStdin>,
    replies: Receiver<std::io::Result<String>>,
    json: Db,
    sequence: u64,
    timeout: Duration,
}

pub(crate) fn field(json: &Db, document: &str, path: &str) -> Result<Val> {
    let mut row = json
        .query_one(
            "SELECT json_extract(?1, ?2)",
            &[Val::Text(document.into()), Val::Text(path.into())],
        )?
        .ok_or("JSON extraction returned no row")?;
    Ok(row.remove(0))
}

impl Mcp {
    fn start(command: &Path, ida_dir: Option<&Path>, timeout: Duration) -> Result<Self> {
        let json = Db::open(Path::new(":memory:"), false)?;
        field(&json, "{\"ready\":true}", "$.ready")
            .map_err(|e| format!("database export requires SQLite JSON support: {e}"))?;
        let mut command = Command::new(command);
        command
            .args(["stdio", "--agent=gamedb-index"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        if let Some(directory) = ida_dir {
            command.env("IDADIR", directory);
        }
        let mut child = command
            .spawn()
            .map_err(|e| format!("start official IDA MCP: {e}"))?;
        let input = child.stdin.take();
        let output = child.stdout.take().ok_or("MCP stdout unavailable")?;
        let (tx, replies) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(output).lines() {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let mut client = Self {
            child,
            input,
            replies,
            json,
            sequence: 0,
            timeout,
        };
        client.request("initialize", "{\"protocolVersion\":\"2025-03-26\",\"capabilities\":{},\"clientInfo\":{\"name\":\"gamedb-index\",\"version\":\"1.0\"}}")?;
        client.send("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}")?;
        Ok(client)
    }

    fn send(&mut self, message: &str) -> Result<()> {
        let input = self.input.as_mut().ok_or("MCP stdin is closed")?;
        writeln!(input, "{message}")
            .and_then(|_| input.flush())
            .map_err(|e| format!("write MCP: {e}"))
    }

    fn request(&mut self, method: &str, params: &str) -> Result<String> {
        self.sequence += 1;
        let id = self.sequence;
        self.send(&format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":{},\"params\":{params}}}",
            jstr(method)
        ))?;
        let started = Instant::now();
        loop {
            let remaining = self
                .timeout
                .checked_sub(started.elapsed())
                .ok_or_else(|| format!("MCP {method} timed out"))?;
            let message = self
                .replies
                .recv_timeout(remaining)
                .map_err(|e| format!("MCP {method}: {e}"))?
                .map_err(|e| e.to_string())?;
            if field(&self.json, &message, "$.id")? != Val::Int(id as i64) {
                continue;
            }
            let error = field(&self.json, &message, "$.error")?;
            if error != Val::Null {
                return Err(format!("MCP {method}: {}", error.as_str()));
            }
            return match field(&self.json, &message, "$.result")? {
                Val::Text(result) => Ok(result),
                _ => Err(format!("MCP {method} returned no result object")),
            };
        }
    }

    fn call(&mut self, tool: &str, arguments: &str) -> Result<String> {
        let result = self.request(
            "tools/call",
            &format!("{{\"name\":{},\"arguments\":{arguments}}}", jstr(tool)),
        )?;
        let text = field(&self.json, &result, "$.content[0].text")?;
        if field(&self.json, &result, "$.isError")? == Val::Int(1) {
            return Err(format!("{tool}: {}", text.as_str()));
        }
        match field(&self.json, &result, "$.structuredContent")? {
            Val::Text(structured) => Ok(structured),
            _ => Ok(text.as_str().into()),
        }
    }
}

impl Drop for Mcp {
    fn drop(&mut self) {
        self.input.take();
        let started = Instant::now();
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if started.elapsed() < Duration::from_secs(2) => {
                    thread::sleep(Duration::from_millis(20))
                }
                _ => {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    break;
                }
            }
        }
    }
}

pub(crate) fn export(args: &Args, database: &Path, output: &Path) -> Result<String> {
    let json = Db::open(Path::new(":memory:"), false)?;
    let command = args
        .mcp_command
        .as_ref()
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("GAMEDB_IDA_MCP").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("ida-mcp"));
    let ida_dir = args
        .ida_dir
        .as_ref()
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("IDADIR").map(PathBuf::from));
    let timeout = args.timeout.unwrap_or(3600);
    let mut client = Mcp::start(&command, ida_dir.as_deref(), Duration::from_secs(timeout))?;
    client.call(
        "open_database",
        &format!("{{\"path\":{}}}", jstr(&database.to_string_lossy())),
    )?;
    let exported = (|| -> Result<String> {
        client.call(
            "reference",
            "{\"query\":\"decompile pseudocode functions\"}",
        )?;
        let code = format!(
            "import json\nEXPORT_DIRECTORY = json.loads({})\nDATABASE_PATH = json.loads({})\n{}",
            jstr(&jstr(&output.to_string_lossy())),
            jstr(&jstr(&database.to_string_lossy())),
            include_str!("ida_export.py")
        );
        let result = client.call(
            "execute_python",
            &format!("{{\"code\":{},\"timeout\":{timeout}}}", jstr(&code)),
        )?;
        let summary = field(&json, &result, "$.result")?;
        if summary == Val::Null || field(&json, summary.as_str(), "$.exported")? == Val::Null {
            return Err(format!(
                "IDA export did not complete: {}",
                field(&json, &result, "$.stderr")?.as_str()
            ));
        }
        client.call("save_database", "{}")?;
        Ok(summary.as_str().into())
    })();
    let closed = client.call("close_database", "{}");
    let summary = exported?;
    closed?;
    drop(client);
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::search_functions;
    use std::fs;

    struct Scratch(PathBuf);

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn args_for_test(args: &Args) -> Args {
        Args {
            cmd: "index".into(),
            pos: args.pos.clone(),
            output_dir: args.output_dir.clone(),
            timeout: args.timeout,
            quiet: true,
            root: ".".into(),
            ..Default::default()
        }
    }

    #[test]
    #[ignore = "requires licensed IDA 9.4+, official ida-mcp, IDADIR and a C compiler"]
    fn real_ida_sync_refreshes_exports_and_removes_renamed_index_entries() {
        let directory = std::env::temp_dir().join(format!(
            "gamedb-ida-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&directory).unwrap();
        let scratch = Scratch(directory);
        let source = scratch.0.join("probe.c");
        let binary = scratch.0.join("probe");
        fs::write(&source, "__attribute__((noinline)) int sync_probe(int x) { return x * 7 + 13; }\nint main(void) { return sync_probe(6); }\n").unwrap();
        assert!(Command::new("cc")
            .args(["-g", "-O1", "-fno-inline"])
            .arg(&source)
            .arg("-o")
            .arg(&binary)
            .status()
            .unwrap()
            .success());
        let command =
            PathBuf::from(std::env::var_os("GAMEDB_IDA_MCP").unwrap_or_else(|| "ida-mcp".into()));
        let ida_dir = std::env::var_os("IDADIR").map(PathBuf::from);
        let mut client =
            Mcp::start(&command, ida_dir.as_deref(), Duration::from_secs(120)).unwrap();
        client
            .call(
                "open_database",
                &format!("{{\"path\":{}}}", jstr(&binary.to_string_lossy())),
            )
            .unwrap();
        client.call("save_database", "{}").unwrap();
        client.call("close_database", "{}").unwrap();
        drop(client);
        let database = binary.with_extension("i64");
        let output = scratch.0.join("export ü 'quoted'");
        let args = Args {
            cmd: "index".into(),
            pos: vec![database.to_string_lossy().into()],
            output_dir: Some(output.to_string_lossy().into()),
            timeout: Some(120),
            quiet: true,
            ..Default::default()
        };
        assert_eq!(crate::cli::run(args_for_test(&args)).unwrap(), 0);
        let before = fs::read_to_string(output.join("decompiled.c")).unwrap();
        assert!(before.contains("sync_probe"));
        let rows = search_functions(&output, None, "sync_probe", 25).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0][0].as_str(), "sync_probe");
        let mut client =
            Mcp::start(&command, ida_dir.as_deref(), Duration::from_secs(120)).unwrap();
        client
            .call(
                "open_database",
                &format!("{{\"path\":{}}}", jstr(&database.to_string_lossy())),
            )
            .unwrap();
        client
            .call("reference", "{\"query\":\"rename functions\"}")
            .unwrap();
        let code = "import ida_name, ida_idaapi\nea = ida_name.get_name_ea(ida_idaapi.BADADDR, 'sync_probe')\nassert ea != ida_idaapi.BADADDR\nassert ida_name.set_name(ea, 'sync_probe_renamed', ida_name.SN_CHECK)";
        client
            .call("execute_python", &format!("{{\"code\":{}}}", jstr(code)))
            .unwrap();
        client.call("save_database", "{}").unwrap();
        client.call("close_database", "{}").unwrap();
        drop(client);
        assert_eq!(crate::cli::run(args_for_test(&args)).unwrap(), 0);
        let rows = search_functions(&output, None, "sync_probe", 25).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0][0].as_str(), "sync_probe_renamed");
        let after = fs::read_to_string(output.join("decompiled.c")).unwrap();
        assert!(after.contains("sync_probe_renamed"));
        assert!(!after.contains("sync_probe("));
        assert_ne!(before, after);
    }
}
