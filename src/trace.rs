//! Internal shim so the crate can emit `tracing` events without forcing the
//! dependency on users. With the `tracing` feature disabled these macros
//! expand to nothing.

#[cfg(feature = "tracing")]
pub(crate) use tracing::{debug, trace};

// The disabled variants still type-check their arguments (at zero runtime
// cost) so code compiles identically with and without the feature.
#[cfg(not(feature = "tracing"))]
macro_rules! debug {
    ($($arg:tt)*) => {{
        let _ = format_args!($($arg)*);
    }};
}

#[cfg(not(feature = "tracing"))]
macro_rules! trace {
    ($($arg:tt)*) => {{
        let _ = format_args!($($arg)*);
    }};
}

#[cfg(not(feature = "tracing"))]
pub(crate) use {debug, trace};
