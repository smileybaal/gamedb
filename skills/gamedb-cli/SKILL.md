---
name: gamedb-cli
description: Navigate a decompiled source tree (Ghidra/IDA C or C++, ILSpy/dnSpy C#, JADX/CFR Java) with the `gamedb` CLI's SQLite index instead of grep. Use when finding a function or string literal, reading one function body, tracing callers or callees, mapping a codebase into modules or tracking rewrite progress per module, or writing raw SQL against `.gamedb/index.sqlite`.
---

# gamedb CLI

`gamedb` parses a directory of brace-delimited source once into `<root>/.gamedb/index.sqlite`, then answers name, string, body, call-graph, and module questions from it. `gamedb --help` is the authoritative flag list; this skill holds what `--help` does not say.

Every command takes `-r SRC` (default `.`). Pass the same `-r` (and `--db PATH`, if you used one) on every call: the index is found through them.

## Start here

The user may invoke this skill with a question attached (for example `/gamedb-cli who calls PlayerUpdate`). Do the setup yourself, then answer:

1. **Root.** Use the folder the user names; otherwise the current project root. Never guess a root from folder or file names.
2. **Binary.** If `gamedb` is not on `PATH`, stop and tell the user how to build it: from a gamedb checkout, `cargo build --release`, then put `target/release/gamedb` on `PATH`. Do not run the build unless they ask.
3. **Index.** Run `gamedb index -r ROOT` before the first query. It is incremental, so it is always safe, and it refreshes a stale index.
4. **Check.** Run `gamedb stats -r ROOT`. If `files` or `functions` is zero or near zero, the root is wrong; queries against it return empty output with exit `0`, not an error. Decompiler output under a skipped directory (see *Indexing flags and scope*) is a common cause: if the code's location is obvious, re-run with `-r` pointing inside that directory. Otherwise ask the user where the code is rather than answering from an empty index.
5. **Answer** the question with the workflow below.

## Workflow

1. **Index.** `gamedb index -r SRC`. Re-run it whenever source has changed since the last run: it is incremental (unchanged files skipped by mtime + size, deleted files dropped), so a no-op run costs milliseconds. The first line is `indexed files=N ...`, where `files`/`fn`/`str`/... count only files re-parsed *this run*; use `gamedb stats -r SRC` for index totals. Read every line after the first:
   - `unreadable: PATH` — the file is missing from the index.
   - `lossy-decode: PATH: <encoding>` — indexed, but text may be mangled (UTF-16 without BOM, legacy code page).
2. **Orient.** `gamedb stats -r SRC`, then `gamedb modules -r SRC` for what the tree is made of (see *Modules*).
3. **Find.** `gamedb search -r SRC PART` for function names, `gamedb strings -r SRC PART` for string literals (4+ chars). Both are substring matches: `search` rows are `path:start-end Name(params)`, `strings` rows are `path:line text`.
4. **Read.** `gamedb read -r SRC ExactName` prints the body verbatim. If the first line is `note: N definitions match ...`, a different definition may be the one you want: re-run with `--path SUBSTR` (substring of the file path) until the note is gone.
5. **Trace.** `gamedb graph -r SRC ExactName --direction callers|callees|both`. Row: `caller|callee  OtherName  (other's path) called at CALL_PATH:LINE (xHITS)`. Pivot by running `read` or `graph` on a name from the result.

Add `--json` to any command for machine-readable output (one JSON array or object on stdout). `-q` suppresses text output only; errors still go to stderr.

## Matching rules

- `search` and `strings` match **case-insensitively** (SQLite `LIKE`): `search update` returns `Update` and `update`. `%` and `_` are literal. An empty query matches everything.
- `read` and `graph` take the **exact, case-sensitive** name. Get it from `search` first.
- `--limit N` defaults to 25. `search`/`strings` cap at 60 regardless of `--limit`; `graph` applies the limit to each direction separately.
- `search` orders shortest name first, then path, then line. `strings` has no defined order.

## Reading call-graph results

Edges resolve **by name only**, with no type or scope information. Treat a graph as a map of candidates, never as proof:

- A name defined in several files fans out: every call to `update` links to every `update` in the tree, across languages.
- A function's own definition line usually shows up as an edge to itself or to same-named functions (`caller Update ... called at file:19` where line 19 is `void Update(...) {`). Discard rows whose `LINE` is the anchor's `start_line`.
- `--path SUBSTR` filters on `CALL_PATH`, the file the call is written in: for `callees` that is the anchor's own file; for `callers` it is the caller's file. Use it to pin the anchor to one definition.
- `call_path:line` is the call site; the parenthesised path is where the other function is defined. They differ for cross-file calls.

## Exit codes and empty results

`0` success, `1` runtime error, `2` usage error (unknown command or flag; the usage text follows). `search`, `strings`, and `graph` with no match exit `0` with empty output (`[]` under `--json`), so test the output rather than the exit code. `read` with no match exits `1` and suggests a `search`. Every query command exits `1` with `no index at ... - run: gamedb index -r SRC` before the first index.

## Modules

Every file is assigned a module **when it is parsed**, from one of:

- `--rules FILE`: an explicit rule file;
- `--rules derive`: buckets by the first two path/namespace segments, ignoring any rule file;
- default: `<root>/.gamedb/modules.txt` if it exists, otherwise derive.

The rule format, selectors (`b:` file, `x:` exact namespace, `n:` namespace prefix, `m:` path segment), and specificity ranking are documented in `modules.example.txt`. Files no rule claims land in `unmapped`.

`gamedb modules` lists `module_id files functions state verified_by system` and ends with `taxonomy: <rule source>`.

**Changing the rules does not reassign already-indexed files.** After adding or editing a rule file, run `gamedb index -r SRC --force` (plus the same `--rules`), otherwise `modules` shows the new module ids with `0 0` and the old assignments stay in `unmapped` or their old buckets. Pass the same `--rules` to `index`, `modules`, and `set-module`; `set-module` rejects a module id the active rules do not know.

### Tracking rewrite progress

```sh
gamedb set-module -r SRC --module core.audio --state PARTIALLY_IMPLEMENTED --remaining "12 functions left"
gamedb set-module -r SRC --module core.audio --state IMPLEMENTED --verified --verified-by alice
```

- States: `UNIMPLEMENTED`, `PARTIALLY_IMPLEMENTED`, `IMPLEMENTED`.
- `IMPLEMENTED` requires `--verified` in the same call. To retract, lower the state and pass `--unverified` together; `--unverified` alone on an `IMPLEMENTED` module is refused.
- Omitted fields keep their previous values. `--verified` without `--verified-by` records `user`.

## Indexing flags and scope

- `--force` re-parses every file. Use it after changing module rules.
- `--dry-run` parses everything and reports file/function/string counts and decode problems without writing (symbols and edges show `0`). It needs an existing index, and it does not diff against it: it counts every file, not just changed ones.
- `-v N` (or `--verbose=N`) prints progress to stderr every N files. The value is required: `-v0` is a usage error, write `-v 0`.
- `--db PATH` stores the index somewhere other than `<root>/.gamedb/index.sqlite`.
- Directories named `build`, `bin`, `obj`, `dist`, `node_modules`, `.git`, `.svn`, or `.gamedb` are skipped at any depth. If decompiler output lives under one of those, point `-r` inside it.
- Indexed extensions: `c h cpp hpp cc cs java kt kts scala swift go rs dart js jsx mjs cjs ts tsx php txt asm`. C, C++, C#, and Java are the supported targets; the others parse heuristically and miss some declaration shapes.
- `read` slices the *current* file by the line range stored at index time. If a file changed since the last `index`, the body comes back shifted: re-index first.

## Raw SQL

`gamedb sql -r SRC --sql "QUERY" [--param VALUE]...` runs one read-only statement (writes fail with `attempt to write a readonly database`). `?` placeholders bind `--param` values in order, always as text.

Use `--json` with `sql`: the plain-text output prints integer columns as empty strings. Without `--json`, `CAST(x AS TEXT)` the numbers.

Schema (authoritative copy: `SCHEMA` in `src/db.rs`):

| Table | Columns |
|---|---|
| `files` | `id, path, mtime, size, edges_mtime, module` |
| `functions` | `id, file_id, name, params, sig, start_line, end_line, sym_id` |
| `symbols` | `id, file_id, kind, name, line` — `kind` is `namespace`, `type`, `method`, `property`, or `field` |
| `strings` | `id, file_id, line, text` |
| `edges` | `src_id, dst_id, line, hits` |
| `module_status` | `module_id, system, state, verified, verified_by, verified_at, remaining` |

**`edges.src_id`/`dst_id` are `symbols.id`, not `functions.id`.** Reach a function through `functions.sym_id`. `dst_id` can also be a `type` symbol. `edges.line` is in the caller's file.

```sql
-- most-called symbols
SELECT d.name, d.kind, p.path, COUNT(*) AS callers
FROM edges e JOIN symbols d ON d.id = e.dst_id JOIN files p ON p.id = d.file_id
GROUP BY e.dst_id ORDER BY callers DESC LIMIT 20;

-- functions nothing else calls (entry points or dead code)
SELECT f.name, p.path FROM functions f JOIN files p ON p.id = f.file_id
WHERE NOT EXISTS (SELECT 1 FROM edges e WHERE e.dst_id = f.sym_id AND e.src_id <> f.sym_id);

-- every function in one module
SELECT p.path, f.name, f.start_line FROM functions f JOIN files p ON p.id = f.file_id
WHERE p.module = ? ORDER BY 1, 3;
```

Prefer the subcommands for single lookups. Reach for `sql` when you need aggregates, joins across tables, or a filter the commands lack (by module, by symbol kind, by line range).
