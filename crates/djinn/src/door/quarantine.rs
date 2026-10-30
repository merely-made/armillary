// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Public review requests. There is no consent assertion or secret payload.
use chatelaine::Item;
use personae::ProfileId;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuarantineCard {
    /// The resident store whose original sealing persona owns its keys.
    pub store: ProfileId,
    pub persona: Uuid,
    pub item: Item,
    pub revision: String,
    pub accept_blocked: Option<String>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewAction {
    Accept,
    Delete,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewRequest {
    /// The resident store whose original sealing persona owns its keys.
    pub store: ProfileId,
    pub profile: ProfileId,
    pub persona: Uuid,
    pub item: chatelaine::ItemId,
    pub revision: String,
    pub action: ReviewAction,
}

/// Public metadata for an older item namespace whose owner was not recorded.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnassignedImport {
    /// The resident store whose original sealing persona owns its keys.
    pub store: ProfileId,
    pub persona: Uuid,
    pub titles: Vec<String>,
    pub item_count: usize,
    pub revision: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssignImportRequest {
    /// The resident store whose original sealing persona owns its keys.
    pub store: ProfileId,
    pub profile: ProfileId,
    pub persona: Uuid,
    pub revision: String,
}
