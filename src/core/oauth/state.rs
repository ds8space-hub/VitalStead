//! OAuth connection state machine transitions (architecture.md L108-124, T-202).
//!
//! No `#[cfg(target_os = ...)]` allowed here — this is platform-independent state logic.

/// Connection state in the OAuth lifecycle (architecture.md L108-124).
///
/// Represents the current state of a provider connection, from initial disconnect
/// through authorization, connection, sync, token refresh, and final disconnection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// No connection; authorization has not been attempted or was cancelled.
    NotConnected,

    /// Authorization flow in progress (user is on provider's login page).
    /// Token exchange (T-203) and credential storage (T-204) have not yet occurred.
    AuthorizationPending,

    /// Successfully authenticated and tokens are stored. Ready to sync.
    Connected,

    /// Currently fetching data from the provider API.
    Syncing,

    /// Refresh token expired or is invalid; user must re-authenticate.
    TokenRefreshRequired,

    /// Access token valid but needs reauthorization due to scope change or provider revocation.
    ReauthorizationRequired,

    /// Explicitly disconnected by user; tokens have been revoked from vault (T-011).
    Disconnected,
}

/// Error when attempting an invalid state transition (T-202 criterion 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionError {
    /// The state we're trying to leave.
    pub from: ConnectionState,

    /// The state we're trying to reach.
    pub to: ConnectionState,
}

impl std::fmt::Display for TransitionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "invalid state transition: {:?} -> {:?}",
            self.from, self.to
        )
    }
}

impl std::error::Error for TransitionError {}

/// Validate and execute a state transition.
///
/// Returns `Ok(to_state)` if the transition is allowed, or `Err(TransitionError)`
/// if the transition is not permitted per the state machine rules.
///
/// **Allowed transitions** (T-202 criterion 3):
/// - NotConnected → AuthorizationPending
/// - AuthorizationPending → Connected
/// - AuthorizationPending → NotConnected (cancel, T-202 criterion 4, EPIC-03-oauth.md L19)
/// - Connected → Syncing
/// - Syncing → Connected
/// - Connected → TokenRefreshRequired
/// - TokenRefreshRequired → Connected
/// - Connected → ReauthorizationRequired
/// - Connected → Disconnected
///
/// All other transitions are rejected.
pub fn transition(
    from: ConnectionState,
    to: ConnectionState,
) -> Result<ConnectionState, TransitionError> {
    let allowed = matches!(
        (from, to),
        // NotConnected → AuthorizationPending (start auth flow)
        (ConnectionState::NotConnected, ConnectionState::AuthorizationPending)
        // AuthorizationPending → Connected (successful token exchange + storage)
        | (ConnectionState::AuthorizationPending, ConnectionState::Connected)
        // AuthorizationPending → NotConnected (user cancelled)
        | (ConnectionState::AuthorizationPending, ConnectionState::NotConnected)
        // Connected → Syncing (start data fetch)
        | (ConnectionState::Connected, ConnectionState::Syncing)
        // Syncing → Connected (data fetch complete)
        | (ConnectionState::Syncing, ConnectionState::Connected)
        // Connected → TokenRefreshRequired (refresh token expired)
        | (ConnectionState::Connected, ConnectionState::TokenRefreshRequired)
        // TokenRefreshRequired → Connected (successful refresh)
        | (ConnectionState::TokenRefreshRequired, ConnectionState::Connected)
        // Connected → ReauthorizationRequired (scope/revocation)
        | (ConnectionState::Connected, ConnectionState::ReauthorizationRequired)
        // Connected → Disconnected (explicit disconnect, tokens revoked)
        | (ConnectionState::Connected, ConnectionState::Disconnected)
    );

    if allowed {
        Ok(to)
    } else {
        Err(TransitionError { from, to })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// T9: Valid transitions allowed (table-driven over all 9 allowed edges).
    #[test]
    fn test_valid_transitions_allowed() {
        let valid_transitions = vec![
            (ConnectionState::NotConnected, ConnectionState::AuthorizationPending),
            (ConnectionState::AuthorizationPending, ConnectionState::Connected),
            (ConnectionState::AuthorizationPending, ConnectionState::NotConnected),
            (ConnectionState::Connected, ConnectionState::Syncing),
            (ConnectionState::Syncing, ConnectionState::Connected),
            (ConnectionState::Connected, ConnectionState::TokenRefreshRequired),
            (ConnectionState::TokenRefreshRequired, ConnectionState::Connected),
            (ConnectionState::Connected, ConnectionState::ReauthorizationRequired),
            (ConnectionState::Connected, ConnectionState::Disconnected),
        ];

        for (from, to) in valid_transitions {
            let result = transition(from, to);
            assert!(
                result.is_ok(),
                "transition {:?} -> {:?} should be allowed",
                from,
                to
            );
            assert_eq!(result.unwrap(), to);
        }
    }

    /// T10: Invalid transitions rejected (e.g., skipping intermediate states).
    #[test]
    fn test_invalid_transition_rejected() {
        let invalid_transitions = vec![
            // Trying to jump directly from NotConnected to Connected
            (ConnectionState::NotConnected, ConnectionState::Connected),
            // Trying to go from Connected back to NotConnected (invalid)
            (ConnectionState::Connected, ConnectionState::NotConnected),
            // Trying to go from Syncing directly to AuthorizationPending
            (ConnectionState::Syncing, ConnectionState::AuthorizationPending),
            // Trying to reach Disconnected from NotConnected
            (ConnectionState::NotConnected, ConnectionState::Disconnected),
            // Trying to go from TokenRefreshRequired to AuthorizationPending
            (ConnectionState::TokenRefreshRequired, ConnectionState::AuthorizationPending),
        ];

        for (from, to) in invalid_transitions {
            let result = transition(from, to);
            assert!(
                result.is_err(),
                "transition {:?} -> {:?} should be rejected",
                from,
                to
            );
            if let Err(e) = result {
                assert_eq!(e.from, from);
                assert_eq!(e.to, to);
            }
        }
    }

    /// T11: Only Connected can reach Disconnected.
    ///
    /// Asserts that no edge into Disconnected exists except (Connected, Disconnected) —
    /// iterate all ConnectionState pairs, assert transition(x, Disconnected) is Err
    /// unless x == Connected.
    #[test]
    fn test_only_connected_can_reach_disconnected() {
        let all_states = vec![
            ConnectionState::NotConnected,
            ConnectionState::AuthorizationPending,
            ConnectionState::Connected,
            ConnectionState::Syncing,
            ConnectionState::TokenRefreshRequired,
            ConnectionState::ReauthorizationRequired,
            ConnectionState::Disconnected,
        ];

        for from_state in all_states {
            let result = transition(from_state, ConnectionState::Disconnected);

            if from_state == ConnectionState::Connected {
                assert!(
                    result.is_ok(),
                    "transition Connected -> Disconnected should be allowed"
                );
            } else {
                assert!(
                    result.is_err(),
                    "transition {:?} -> Disconnected should be rejected",
                    from_state
                );
            }
        }
    }
}
