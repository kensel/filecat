//! Phase 2: the Windows agent. Not built yet (`mod` is `cfg(windows)` only, and `main.rs` refuses
//! non-Unix targets). What it has to provide, from docs/agent-protocol.md and
//! docs/agent-allowlist.md section 13:
//!
//! - `wmi {id}` through the `wmi` crate: the 19 read-only queries of the table, `capabilities`
//!   with `class` instead of `binary`, 30 s timeout.
//! - `list_dir` `attributes` (`FindFirstFileW`); cloud placeholders (0x400000, 0x40000, 0x1000)
//!   never opened: `measure` answers `unread: "cloud_placeholder"`, `read_file` / `read_range`
//!   are `refused` ("not on this device (cloud placeholder), not read"), sums count from the
//!   directory entry.
//! - Default allowed roots: fixed local volumes except the system drive (unless
//!   `Win32_OperatingSystem.ProductType` is 1), plus disk-share paths; `;` separator; entries
//!   compared case-insensitively; canonicalisation with `GetFinalPathNameByHandle`;
//!   `capabilities.product_type`.
//! - The Windows deny list (`scope::DENY_WINDOWS`, `NTUSER.DAT*`, `UsrClass.dat*`, `*.dit`,
//!   `.env*` case-insensitively).
//! - No `run` (no process is ever started on Windows).

compile_error!("the Windows agent is phase 2");
