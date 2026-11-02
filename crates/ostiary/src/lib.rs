// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! The application door's contract: what an application says at Djinn's
//! door and how it says it. The hello and admission types, declarations,
//! framing and envelopes are portable; `native` adds the client, the dialer
//! and a launched application's handle. Djinn serves the other side.

pub mod app_admission;
pub mod declaration;
pub mod frame;
pub mod route;
pub mod wire;

#[cfg(all(feature = "native", any(unix, windows), not(target_arch = "wasm32")))]
pub mod app_client;
#[cfg(all(feature = "native", any(unix, windows), not(target_arch = "wasm32")))]
pub mod launch;
#[cfg(all(feature = "native", any(unix, windows), not(target_arch = "wasm32")))]
pub mod local_endpoint;
