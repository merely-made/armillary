// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Portable bounded observations and read-only inspection data.
//!
//! Producers supply redacted payloads and monotonic receipt times. Products own
//! execution results, authorization, retention/export policy and persistence.
//! The default core uses only `std`; optional Serde preserves the wire data.
//! No actor runtime, collector, exporter or renderer is installed.

mod observation;
pub use observation::*;
mod inspection;
pub use inspection::*;
