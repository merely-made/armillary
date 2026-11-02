// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! The serving side of the application door: the owner's grants, the
//! launcher, the listener and the server, plus the custody clients. The
//! contract applications speak is `ostiary`.

pub mod app_admission;
#[cfg(all(feature = "custody", any(unix, windows), not(target_arch = "wasm32")))]
pub mod custody;
#[cfg(all(
    feature = "custody-client",
    any(unix, windows),
    not(target_arch = "wasm32")
))]
pub mod custody_client;
#[cfg(all(
    feature = "custody-client",
    any(unix, windows),
    not(target_arch = "wasm32")
))]
pub mod custody_identity;
#[cfg(all(feature = "custody", any(unix, windows), not(target_arch = "wasm32")))]
pub mod custody_payload;
#[cfg(all(feature = "custody", any(unix, windows), not(target_arch = "wasm32")))]
pub mod quarantine;

#[cfg(all(feature = "door-serve", any(unix, windows), not(target_arch = "wasm32")))]
pub mod launch;
#[cfg(all(feature = "door-serve", any(unix, windows), not(target_arch = "wasm32")))]
pub mod link;
#[cfg(all(feature = "door-serve", any(unix, windows), not(target_arch = "wasm32")))]
pub mod local_endpoint;
#[cfg(all(feature = "door-serve", any(unix, windows), not(target_arch = "wasm32")))]
pub mod server;
