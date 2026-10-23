//! gamedb: index a directory of decompiled source into SQLite and answer
//! questions about it from a shell.
//!
//! The binary in `src/main.rs` is a thin shim over [`cli`]. Everything lives in
//! the library so that `cargo test` can reach it: a bug in the parser is a
//! failing test with a name, not one line of a 90-check monolith.

pub mod cli;
pub mod db;
pub mod ida;
pub mod export;
pub mod modules;
pub mod parse;
pub mod rx;
pub mod selftest;
pub mod store;
