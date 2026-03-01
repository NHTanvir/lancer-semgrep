//! semgrep-taint — forward dataflow, taint propagation, sanitizers,
//! propagators, taint labels with `requires:` expressions, and a
//! Pro-mode inter-procedural stub.
//!
//! See plan.md §"Internal architecture → taint/" and §"Engineering hard
//! parts → Taint analysis".

pub mod cfg;
pub mod dataflow;
pub mod interproc;
pub mod labels;
pub mod lattice;
pub mod matching;
pub mod nodes;
pub mod propagator;
pub mod requires;
pub mod runner;
pub mod sanitizer;
pub mod traces;
pub mod variadic;

pub use cfg::{build_for_root, Cfg, CfgBuilder, FunctionScope};
pub use dataflow::{
    run_dataflow, DataflowResult, PropagatorHit, SanitizerHit, SinkHit, SinkPatternHit,
    SourceHit, TaintNodeMatches, TaintOptions,
};
pub use interproc::{
    build_summaries, FunctionSummary, ScalaForYieldDesugaring, SummaryTable,
};
pub use lattice::{ProgramPointState, TaintLattice, VarTaint};
pub use matching::{
    collect_taint_matches, find_propagator_matches, find_sanitizer_matches,
    find_sink_matches, find_source_matches,
};
pub use nodes::{CfgNode, CfgNodeKind, EdgeKind};
pub use requires::eval_requires;
pub use runner::run_taint_rule;
pub use traces::{build_trace, TraceBuilder, TraceRecord};
pub use variadic::is_variadic_arg;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
