// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Application door protocol and resident lifetime primitives.

#[cfg(feature = "door")]
pub mod door;

#[cfg(all(feature = "resident", not(target_arch = "wasm32"), any(unix, windows)))]
pub mod resident;
