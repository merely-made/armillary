// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Live launches and the OS identity backing an application label.

use super::{AllowedAppRoutes, AppId, LaunchHandle};
#[cfg(feature = "door-serve")]
use super::{AppAdmissionError, AppRequest};
#[cfg(feature = "door-serve")]
use ostiary::declaration::IdentityBasis;

impl AllowedAppRoutes {
    /// Accept `handle` as `app`'s launch, until [`Self::end_launch`].
    pub fn begin_launch(&mut self, handle: LaunchHandle, app: AppId) {
        self.launches.insert(handle, app);
    }

    /// Stop accepting `handle`: its process exited.
    pub fn end_launch(&mut self, handle: &LaunchHandle) {
        self.launches.remove(handle);
    }

    /// The application a live launch handle names.
    pub fn identify_launch(&self, handle: &LaunchHandle) -> Option<&AppId> {
        self.launches.get(handle)
    }

    /// Accept connections from `process` as `app`'s launch, until
    /// [`Self::end_process`]. Djinn holds the process's handle meanwhile, so
    /// its id names no other process.
    #[cfg(feature = "door-serve")]
    pub fn begin_process(&mut self, process: peer_facts::ProcessKey, app: AppId) {
        self.processes.insert(process, app);
    }

    /// Stop accepting `process`: it exited.
    #[cfg(feature = "door-serve")]
    pub fn end_process(&mut self, process: &peer_facts::ProcessKey) {
        self.processes.remove(process);
    }

    /// How many launches are live: handles, and launched Windows processes.
    pub fn launch_count(&self) -> usize {
        #[cfg(feature = "door-serve")]
        let processes = self.processes.len();
        #[cfg(not(feature = "door-serve"))]
        let processes = 0;
        self.launches.len() + processes
    }

    /// What `request`'s label rests on, given what the OS said about the
    /// peer. Where the owner pinned an identity for this platform, a peer
    /// without it is refused; elsewhere the label stands as development mode.
    #[cfg(feature = "door-serve")]
    pub fn identify(
        &self,
        request: &AppRequest,
        connected: Option<&peer_facts::Connected>,
    ) -> Result<IdentityBasis, AppAdmissionError> {
        let Some(pinned) = self
            .grants
            .get(&request.app)
            .and_then(|grant| grant.identity.as_ref())
        else {
            return Ok(IdentityBasis::Development);
        };
        let mismatch = |expected: String| AppAdmissionError::IdentityMismatch {
            app: request.app.clone(),
            expected,
        };
        if cfg!(target_os = "macos") {
            if let Some(signed) = &pinned.macos {
                return match connected
                    .is_some_and(|c| c.signed_as(&signed.team, &signed.identifier))
                {
                    true => Ok(IdentityBasis::Signed {
                        team: signed.team.clone(),
                        identifier: signed.identifier.clone(),
                    }),
                    false => Err(mismatch(format!(
                        "code signed by {} as {}",
                        signed.team, signed.identifier
                    ))),
                };
            }
        }
        if cfg!(windows) {
            if let Some(windows) = &pinned.windows {
                let launched = connected
                    .and_then(|c| c.process())
                    .and_then(|process| self.processes.get(&process));
                if launched == Some(&request.app) {
                    return Ok(IdentityBasis::Launched);
                }
                let image = connected.and_then(|c| match &c.peer {
                    peer_facts::Peer::Windows { image, .. } => image.clone(),
                    _ => None,
                });
                return match image.filter(|image| windows.matches(image)) {
                    Some(image) => Ok(IdentityBasis::WindowsImage { image }),
                    None => Err(mismatch(format!(
                        "the executable {} or a process Djinn launched",
                        windows.image
                    ))),
                };
            }
        }
        if cfg!(target_os = "linux") {
            if pinned.linux.is_some() {
                let launched = request
                    .launch
                    .as_ref()
                    .and_then(|handle| self.launches.get(handle));
                return match launched == Some(&request.app) {
                    true => Ok(IdentityBasis::Launched),
                    false => Err(mismatch("a process Djinn launched".into())),
                };
            }
        }
        Ok(IdentityBasis::Development)
    }
}
