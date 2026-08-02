//! Platform-independent OAuth state machine (D-011, architecture.md L136).
//! No `#[cfg(target_os = ...)]` allowed here — see lib.rs composition-root comment.

pub mod authorization;
pub mod disconnect;
pub mod refresh;
pub mod state;

pub use authorization::{AuthorizationError, AuthorizationFlow, PendingAuthorization, AUTHORIZATION_TIMEOUT};
pub use disconnect::{DisconnectError, DisconnectOrchestrator, DisconnectOutcome, DisconnectRequest};
pub use refresh::{
    is_refresh_due, BackoffSleeper, RealSleeper, RefreshCoordinator, RefreshError,
    RefreshOrchestrator, RefreshOutcome, RefreshRequest, REFRESH_LEAD_TIME,
};
pub use state::{ConnectionState, TransitionError, transition};
