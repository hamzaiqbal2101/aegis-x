//! AEGIS X Windows adapter.
//!
//! Two halves:
//! * `translate` — policy → WFP filter data. Pure Rust, unit-tested on
//!   every platform.
//! * `engine` — installs those filters into the live WFP engine. This
//!   half is Windows-only (`cfg(windows)`) and is **NOT compile-checked
//!   on Linux**: it uses the `windows` crate's WFP bindings, which only
//!   exist on Windows. The first Windows build (`cargo build -p
//!   aegis-windows` on a Windows host) is the compile check, and any API
//!   name mismatches the compiler reports must be fixed there before any
//!   enforcement claim is made. See `README.md` in this crate and
//!   `docs/VALIDATION.md` §6 for the verification procedure.

pub mod engine;
pub mod translate;

pub use translate::{
    translate, WfpAction, WfpFilter, WfpLayer, WEIGHT_BASE, WEIGHT_STEP,
};
