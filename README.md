# gamedb

A single native command-line utility that indexes a directory of decompiled source into
SQLite so you can search, read, and traverse it from a shell — no editor plugin, no GUI,
no language server, no host process.

```
gamedb index -r C:\src
gamedb search -r C:\src UpdateParticles
gamedb read -r C:\src Tick
gamedb graph -r C:\src Tick --direction callees
```

`gamedb.exe` is a standalone executable. There is nothing to install alongside it and no
runtime to host it in. Drop it on `PATH` (or keep it anywhere and call it by path) and it
works on a machine that has never seen this repository.

## Index source, IDA databases or Ghidra projects

```sh
gamedb index -r /analysis/exported-source
gamedb index /analysis/game.i64 --ida-dir /opt/ida-pro-9.4
gamedb index /analysis/game.gpr --program Game.exe
```

`index` detects the input: directories use the existing incremental source indexer; `.i64`/`.idb` files are exported through the official [Hex-Rays IDA MCP](https://github.com/HexRaysSA/ida-mcp); `.gpr` projects are exported through [akiselev/ghidra-cli](https://github.com/akiselev/ghidra-cli)'s built-in C exporter. Database paths work positionally or with `-r`. There is no separate synchronization command. Directory indexing still needs neither IDA nor Ghidra.

Database indexing is orchestrated in Rust and invokes gamedb's Rust indexer directly, without starting another gamedb process. The embedded `ida_export.py` routine runs inside IDA through `execute_python`; the official MCP server and IDA still require their Python environment and a valid license. Ghidra uses its native C exporter through ghidra-cli, without an additional Python wrapper.

For IDA, the default source root is `game-source/` beside `game.i64`. For Ghidra it is `game-Game.exe-source/`, including the selected program name with path separators replaced. `--output-dir DIR` overrides this directory. The index is `<source-root>/.gamedb/index.sqlite`, unless `--db PATH` overrides it. Pass the source root to subsequent `search`, `read`, `graph` and other source commands.

Exports replace `decompiled.c` atomically and force a refresh of its index, so removed or renamed functions do not leave stale definitions. `.gamedb-export.json` records database/backend identity and export metadata; a directory is locked against simultaneous exports and cannot be reused for another database or Ghidra program. Existing `.ida-export.json` ownership manifests are recognized. IDA's manifest also includes function addresses/names, UTC timestamp, SHA-256, skipped external imports and per-function decompilation failures. Imports have no local bodies and are skipped. Partial IDA exports are reported; if no functions decompile, the previous export is preserved. Ghidra's built-in exporter does not expose a per-function failure count through this CLI, so `exported` and `failed` are `null` in its manifest; inspect its export warnings rather than treating an unknown count as zero.

IDA requires IDA 9.4+ with Hex-Rays and the official `ida-mcp` server. `--mcp-command PROGRAM` overrides `GAMEDB_IDA_MCP`, otherwise `ida-mcp` is looked up on `PATH`. `--ida-dir DIR` overrides `IDADIR`, otherwise the server uses its configured installation. Ghidra requires `ghidra-cli` with `program export c` support, configured for the installed Ghidra distribution. `--ghidra-command PROGRAM` overrides `GAMEDB_GHIDRA`, otherwise the executable is `ghidra`. `--program NAME` is required for `.gpr` projects and prevents accidentally indexing a different program in a multi-program project. Do not open the same Ghidra project concurrently in another owner.

`--timeout SECONDS` allows long exports (default 3600). `--json`, `--quiet`, `--rules`, `--db` and `--verbose` are supported. For database input, `--dry-run` prints the detected backend and destination without exporting or creating directories. Database integration requires SQLite JSON functions (SQLite 3.38+ or an older SQLite with JSON1) and adds no Cargo dependencies. Ordinary source commands retain their existing SQLite requirements. This command runs when invoked; it does not install a save hook or watcher. Run `index` again after completing analysis changes in either backend.

The real IDA integration test compiles an original C program, exports it, renames a function in IDA, and verifies replacement in both the C export and SQLite:

```sh
GAMEDB_IDA_MCP=/path/to/venv/bin/ida-mcp IDADIR=/opt/ida-pro-9.4 cargo test real_ida_sync -- --ignored --nocapture
```

The Ghidra equivalent creates a temporary project, indexes it, renames a function, and checks that the export and SQLite replace the old name; it also checks ordinary directory indexing on the resulting source:

```sh
GAMEDB_GHIDRA=/path/to/ghidra cargo test real_ghidra_index -- --ignored --nocapture
```

These opt-in checks require their configured backend and `cc`; the normal test suite does not.

## Why it exists

Decompiling something gives you a directory of `.c`, `.cpp`, `.java`, or `.cs` files.
Finding one function in it means `grep`, and `grep` cannot tell you callers, callees,
string literals, or which subsystem a file belongs to. `gamedb` parses the tree once and
answers those questions from SQLite.

It is optimized for the way an agent (or a person at 3am) consumes it: terse text by
default, one `--json` flag for machine parsing, short help, and results instead of
narration. It is also built to be honest about what it did not manage to read, because an
index that silently skips files is indistinguishable from a complete one.

Nothing about it is specific to any one project. The language list, the module taxonomy,
and the rewrite-tracking table are all data or configuration, not compiled-in knowledge.

## Build

```sh
cargo build --release --target x86_64-pc-windows-msvc
# -> target\x86_64-pc-windows-msvc\release\gamedb.exe
```

Requires the Rust toolchain and a C linker for your platform. Nothing else — see
*Dependencies*.

## Dependencies

**None.** `Cargo.toml` has no `[dependencies]` section, deliberately:

| Usually needed | Replaced by |
|---|---|
| `rusqlite` or `libsqlite3-sys` | `src/db.rs` — a direct FFI binding to the system SQLite: `winsqlite3.dll` (ships with Windows 10 1809+) on Windows, `libsqlite3` elsewhere |
| `regex` | `src/rx.rs` — hand-written matchers mirroring the reference patterns |
| `clap` | `src/cli.rs` — hand-rolled argument parsing |
| `serde` / `serde_json` | a small string escaper in `src/cli.rs` |

SQLite itself is not vendored or compiled in; it is the one already on the machine.

## Commands

```
gamedb index    -r SRC [-v0] [--dry-run] [--force] [--rules FILE|derive]   build/refresh the index
gamedb search   -r SRC QUERY [--limit N]             find functions by name substring
gamedb strings  -r SRC QUERY [--limit N]             find string literals
gamedb read     -r SRC NAME [--path SUBSTR] [--out F] [--force]   print one function body verbatim
gamedb stats    -r SRC                               counts per table
gamedb modules  -r SRC [--rules FILE|derive]         which subsystem each file belongs to
gamedb set-module -r SRC --module ID [--state S] [--verified|--unverified]
                    [--verified-by WHO] [--remaining TEXT]        track rewrite progress
gamedb graph    -r SRC NAME [--path SUBSTR] [--direction both|callers|callees]   call graph
gamedb sql      -r SRC --sql Q [--param V]...        escape hatch: raw SQLite
gamedb selftest                                         run the built-in checks
```

Global flags: `-r/--root SRC` (default `.`), `--db PATH`, `--json`, `-q`, `--verbose=N`,
`--rules FILE|derive`, `-h`, `-V`.

The index is written to `<root>\.gamedb\index.sqlite`. Delete that directory to discard it.

## Examples

```sh
# what is in here?
gamedb stats -r C:\src
# files=1549 functions=14083 strings=10269 symbols=47852 edges=436798 db=C:\src\.gamedb\index.sqlite

# who calls this, and what does it call?
gamedb graph -r C:\src Tick --direction callers
# caller  MainLoop   (src/main.c)   called at src/main.c:219 (x1)
gamedb graph -r C:\src Tick --direction callees
# callee  Advance    (src/world.c)  called at src/main.c:6530 (x1)

# machine-readable
gamedb search -r C:\src Tick --limit 2 --json
[{"name":"Tick","params":"int steps","sig":"void Tick(int steps) {","start_line":4021,"end_line":4060,"path":"src/world.c"},
 {"name":"TickWorld","params":"","sig":"void TickWorld() {","start_line":910,"end_line":988,"path":"src/world.c"}]

# two files define `Tick`; the count is reported and --path picks one
gamedb read -r C:\src Tick
# note: 2 definitions match Tick; showing src/net/tick.c - narrow with --path SUBSTR
gamedb read -r C:\src Tick --path net/ --out tick.c

# see everything
gamedb read -r C:\src Tick --out tick.c
```

A `graph` row is `{direction, name, path, call_path, line, hits}`: `name`/`path` are the other
endpoint, and `line` is the call site inside `call_path` — which is the file the call is
written in, not necessarily the file the callee lives in.

Notes on behaviour worth knowing:

- `index` is **incremental**. Unchanged files are skipped by mtime + size; a re-run over an
  unchanged tree writes nothing and finishes in milliseconds. `--force` re-parses
  everything, `--dry-run` reports what would change without writing.
- The whole indexing pass is **one transaction**. An interrupted or failing run leaves the
  previous index intact rather than half-rewritten.
- Files it could not read are **named**, not counted. A file that is not valid UTF-8, or
  that is UTF-16 without a BOM, is decoded and reported with its path and the encoding
  used, instead of being indexed as quietly mangled text.
- Search is a case-sensitive substring match with SQL wildcards escaped, so `%` and `_`
  are literal. Results are ordered by shortest name first, then path, then line.
- `read` needs the exact function name (use `search` to find it). When several files define
  it, `read` says how many matched instead of silently showing one, and `--path` chooses.
- Call edges resolve by **name only** — no type inference. `a.Bar()` is recorded as an edge
  to whatever `Bar` is in the file, and a local variable can shadow a global. Treat the
  graph as a map, not as proof.
- Exit codes: `0` success, `1` runtime error (nothing found, unindexed root, bad SQL),
  `2` usage error.

## Modules

Every indexed file is assigned to a module, so `gamedb modules` answers "what is this
codebase made of" without asking anyone.

With no configuration, gamedb **derives** a taxonomy from the corpus itself: it buckets
source files by the first two path segments, keeps the buckets worth keeping, and names
them after the path. That is enough to start, on any project, on the first run — before
there is an index to derive from.

When a derived taxonomy is not good enough, write one. Copy
[`modules.example.txt`](modules.example.txt) to `<root>\.gamedb\modules.txt`:

```
#   selector        module_id          system
n:Acme.Audio       core.audio         Runtime
n:Acme.Rendering   core.rendering     Runtime
n:Acme             core.acme          Platform
b:Player.cs        core.player        Runtime
m:generated        build.generated    Generated
```

A file's namespace is the first `namespace` it declares, or its directory chain dotted
together (`src/net/http/Sock.c` → `src.net.http`) when it declares none — which is why the
same rules work on C and on generated code with no namespaces at all.

gamedb tries **every** rule and keeps the most specific match, so the order of the lines
does not matter and a broad catch-all can never quietly shadow a narrow one:

| Selector | Matches | Rank |
|---|---|---|
| `b:Player.cs` | that one file | strongest |
| `x:Acme` | that namespace, excluding its children | |
| `n:Acme.Audio` | a namespace prefix; the longer one wins | |
| `m:generated` | any path segment with that name | weakest |

Files that match no rule appear in an `unmapped` bucket rather than being dropped, so a
gap in the rules is visible instead of silently shrinking the plan.

`set-module` tracks progress per module and records who verified what:

```sh
gamedb set-module -r C:\src --module core.player --state PARTIALLY_IMPLEMENTED --remaining "12 functions left"
gamedb set-module -r C:\src --module core.player --state IMPLEMENTED --verified --verified-by alice
```

`--state IMPLEMENTED` requires `--verified`: a module is never declared done, only
recorded as verified by someone. Omitting `--verified` on a later call preserves the
previous sign-off rather than wiping it.

## Languages

Brace-delimited source, which is what decompiler output is:

- **C, C++** (Ghidra and friends), **C#** (ILSpy, dnSpy), **Java** (JADX, CFR) — the
  four target languages, read by the heuristic matcher in `src/rx.rs`.
- Go, Rust, Swift, Kotlin, Scala, Dart, PHP, JavaScript/TypeScript — read
  *heuristically*: plain declarations index, but receivers, arrow functions, and
  return-typed signatures are not faithfully recovered. These need a real
  grammar; see [`docs/language-mockups.md`](docs/language-mockups.md).

Outstanding per-language work is tracked in [`ENHANCEMENTS.md`](ENHANCEMENTS.md),
ordered most common language first.

[`docs/language-support.md`](docs/language-support.md) has the measured verdict per
language and the honest limits of a brace scanner.

Also read, because decompilers emit them alongside code: `.txt` header dumps and `.asm`
disassembly listings. `SRC_EXT` in `src/store.rs` is the authoritative list.

Declaration shapes understood:

```c
void f(int a) { ... }                  // one line
void f(int a)                          // Allman: `{` on its own line
{                                      // ... blank lines allowed
void __thiscall f(void) { ... }        // calling convention between type and name
static inline int g(int a) { ... }     // storage class leading the declaration
void f(                                // parameters wrapped across lines
    char *out,
    int n)
{ ... }
void Player::Update(int dt) { ... }    // qualified owner: name is the final segment
int GetHealth() const { ... }          // trailing qualifiers after `)`
public void update() throws E { ... }  // throws / where clauses after `)`
std::shared_ptr<Player> Make() { ... } // namespace-qualified return type
int id;                                // C struct field (no access modifier)
int X => Y;                            // expression body: one-line function
```

Declarations must be brace-delimited, except expression bodies (`int X => Y;`), which
are indexed with their `=>` line as the body. `int x = f();` on one line with no `{}`
body is a declaration, not a function, and is deliberately not indexed.

## What is in the index

| Table | Contents |
|---|---|
| `files` | path, mtime, size, module |
| `functions` | name, params, signature, line range, owning file |
| `symbols` | namespace / type / method / property / field declarations |
| `strings` | string literals, 4+ characters |
| `edges` | caller → callee, with line and hit count |
| `module_status` | per-module rewrite state and sign-off |

The schema in `src/db.rs` is the single source of truth: a new database is built complete
from it, and `migrate()` only exists to bring an *older* file up to date.

`gamedb sql` gives you direct access if you need something the commands do not cover:

```sh
gamedb sql -r C:\src --sql "SELECT p.path, count(*) c FROM edges e JOIN functions f ON f.id=e.src_id JOIN files p ON p.id=f.file_id GROUP BY p.path ORDER BY c DESC LIMIT 10"
```

## Development

```sh
cargo build --release --target x86_64-pc-windows-msvc
cargo test  --release --target x86_64-pc-windows-msvc
cargo clippy --release --target x86_64-pc-windows-msvc --all-targets
cargo fmt --check
./gamedb.exe selftest        # 87 checks
```

| File | Role |
|---|---|
| `src/lib.rs` | the library: everything, so `cargo test` can reach it |
| `src/main.rs` | entry point, exit codes — a shim over `cli` |
| `src/cli.rs` | argument parsing, text/JSON output |
| `src/store.rs` | directory walk, decoding, indexing, queries |
| `src/parse.rs` | comment/string masking, function and symbol parsing |
| `src/rx.rs` | hand-written pattern matchers |
| `src/modules.rs` | module rule file, rule ranking, taxonomy derivation |
| `src/db.rs` | system SQLite FFI, schema, migrations |
| `src/selftest.rs` | built-in checks, runnable without `cargo` |
| `tests/audit.rs` | `cargo test` coverage, named per behaviour |

`gamedb selftest` exists so the checks are runnable from a shell on a machine with no Rust
toolchain. `cargo test` is a superset of it: it runs the same suite and adds focused tests
whose names localize a regression instead of reporting one line of a monolith.

## Porting note

The on-disk format is shared with the TypeScript `gamedb` extension for the Pi coding
agent, and is preserved exactly: a database built by either is read and incrementally
updated by the other. The schema, the queries, and the JSON output are the compatibility
surface; anything added here is additive.

## License

MIT
