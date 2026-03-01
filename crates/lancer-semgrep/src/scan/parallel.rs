//! Re-export of the rayon prelude for binary-level callers. The actual
//! `par_iter` over `(target × rule)` lives in `run.rs`; this module exists so
//! tests and future helpers can `use crate::scan::parallel::*` without
//! pulling rayon's whole prelude into every file.

pub use rayon::prelude::*;
