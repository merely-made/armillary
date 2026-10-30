// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! A host-configured resident route: the value an app route grant names.
//!
//! Both halves need it. Admission ([`super::app_admission`]) maps a granted
//! app route to one; Graphshell's endpoint catalog selects the registered
//! endpoint it names after the carrier is admitted.

use std::time::Duration;

/// A host-configured catalog route for one browser or resident session.
///
/// The route is selected by the host after it admits the carrier. It is never
/// accepted from a browser request, so the browser cannot switch itself to an
/// endpoint the host did not choose.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResidentEndpointRoute {
    id: String,
    notice_poll_interval: Duration,
}

impl ResidentEndpointRoute {
    pub fn new(
        id: impl Into<String>,
        notice_poll_interval: Duration,
    ) -> Result<Self, ResidentEndpointRouteError> {
        let id = id.into();
        if id.is_empty() || id.chars().any(char::is_whitespace) {
            return Err(ResidentEndpointRouteError::InvalidId { id });
        }
        if notice_poll_interval.is_zero() {
            return Err(ResidentEndpointRouteError::ZeroNoticePollInterval);
        }
        Ok(Self {
            id,
            notice_poll_interval,
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn notice_poll_interval(&self) -> Duration {
        self.notice_poll_interval
    }
}

/// Why a host's configured resident route is unusable before admission.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ResidentEndpointRouteError {
    #[error("resident endpoint route id is empty or contains whitespace: {id:?}")]
    InvalidId { id: String },
    #[error("resident endpoint route notice poll interval must be non-zero")]
    ZeroNoticePollInterval,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_route_needs_an_id_without_whitespace_and_a_poll_interval() {
        assert!(matches!(
            ResidentEndpointRoute::new("not a route", Duration::from_millis(1)),
            Err(ResidentEndpointRouteError::InvalidId { .. })
        ));
        assert!(matches!(
            ResidentEndpointRoute::new("fixture", Duration::ZERO),
            Err(ResidentEndpointRouteError::ZeroNoticePollInterval)
        ));
        let route = ResidentEndpointRoute::new("fixture", Duration::from_millis(25)).unwrap();
        assert_eq!(route.id(), "fixture");
        assert_eq!(route.notice_poll_interval(), Duration::from_millis(25));
    }
}
