// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Bounded, read-only inspection data over an independent reader's batch.
//! Products supply an already redacted borrowed payload label. This module
//! neither serializes arbitrary payload fields nor resolves causal references.

use crate::{Batch, RetentionLimits};
use std::hash::{Hash, Hasher};

/// Display policy, independent of retention. Zero hides the corresponding data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InspectionLimits {
    pub max_records: usize,
    pub max_gaps: usize,
    pub max_text_chars: usize,
}

/// A read-only row. Hosts own layout, navigation and any separately supplied actions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InspectionLine {
    pub id: String,
    pub text: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Inspection {
    pub lines: Vec<InspectionLine>,
}

fn capped(text: &str, limit: usize) -> String {
    let mut chars = text.chars();
    let mut result: String = chars.by_ref().take(limit).collect();
    if chars.next().is_some() && limit > 0 {
        result.pop();
        result.push('…');
    }
    result
}

fn identity(value: impl Hash) -> u64 {
    let mut hash = std::collections::hash_map::DefaultHasher::new();
    value.hash(&mut hash);
    hash.finish()
}

/// Project at most ten summary rows, one boundary row, `max_gaps` gap rows and
/// three rows per displayed record. Text lengths are capped at Unicode scalar
/// boundaries. IDs use scoped identities rather than mutable labels or row order.
///
/// `retention` must describe the store that supplied `batch`; the caller enforces
/// monotonic expiry before reading. Missing correlation is explicitly unavailable.
/// Display truncation is distinct from observation loss. No store/cursor is changed.
pub fn inspect_batch<P>(
    batch: &Batch<P>,
    retention: RetentionLimits,
    limits: InspectionLimits,
    label: impl for<'a> Fn(&'a P) -> &'a str,
) -> Inspection {
    let scope = identity((
        &batch.stats.run,
        &batch.stats.source,
        batch.stats.generation,
    ));
    let mut inspection = Inspection::default();
    let mut add = |key: String, text: String| {
        inspection.lines.push(InspectionLine {
            id: format!("apparatus/{scope:016x}/{key}"),
            text: capped(&text, limits.max_text_chars),
        });
    };
    add(
        "retention".into(),
        if retention.enabled() {
            format!(
                "Retention: {} records, {} accounted bytes, {}s",
                retention.max_records,
                retention.max_bytes,
                retention.max_age.as_secs()
            )
        } else {
            "Retention disabled".into()
        },
    );
    add(
        "retained".into(),
        format!(
            "Retained: {} records, {} accounted bytes",
            batch.stats.retained_records, batch.stats.retained_bytes
        ),
    );
    let loss = batch.stats.loss;
    for (name, count) in [
        ("disabled", loss.rejected_disabled),
        ("oversized", loss.rejected_oversized),
        ("accounting", loss.rejected_accounting),
        ("evicted", loss.evicted),
        ("expired", loss.expired),
        ("dropped", loss.dropped),
    ] {
        add(format!("loss/{name}"), format!("Loss {name}: {count}"));
    }
    add(
        "coverage".into(),
        "Coverage: producer-supplied observations; missing instrumentation is unknown".into(),
    );
    add(
        "display".into(),
        format!(
            "Displayed: {} of {} batch records; {} of {} gaps",
            batch.records.len().min(limits.max_records),
            batch.records.len(),
            batch.gaps.len().min(limits.max_gaps),
            batch.gaps.len()
        ),
    );
    if batch.boundary.is_some() {
        add("boundary".into(), "Reader crossed a run boundary".into());
    }
    for gap in batch.gaps.iter().take(limits.max_gaps) {
        add(
            format!("gap/{}", gap.first_sequence),
            format!(
                "Unavailable records: [{}, {})",
                gap.first_sequence, gap.next_sequence
            ),
        );
    }
    for record in batch.records.iter().rev().take(limits.max_records) {
        let reference = &record.envelope.reference;
        let metadata = &record.envelope.metadata;
        let sequence = reference.sequence;
        let operation = metadata
            .operation
            .as_ref()
            .map(|id| capped(&id.0, limits.max_text_chars))
            .unwrap_or_else(|| "unavailable".into());
        let cause = metadata
            .cause
            .as_ref()
            .map(|cause| {
                format!(
                    "run {} / source {} / #{}",
                    capped(&cause.run.0, limits.max_text_chars),
                    capped(&cause.source.0, limits.max_text_chars),
                    cause.sequence
                )
            })
            .unwrap_or_else(|| "unavailable".into());
        let revision = metadata
            .semantic_revision
            .map(|v| v.to_string())
            .unwrap_or_else(|| "unavailable".into());
        let frame = metadata
            .presented_frame
            .map(|v| v.to_string())
            .unwrap_or_else(|| "unavailable".into());
        add(
            format!("record/{sequence}"),
            format!(
                "#{sequence}: {}",
                capped(label(&record.payload), limits.max_text_chars)
            ),
        );
        add(
            format!("record/{sequence}/cause"),
            format!("Operation: {operation}; cause: {cause}"),
        );
        add(
            format!("record/{sequence}/frame"),
            format!("Semantic revision: {revision}; presented frame: {frame}"),
        );
    }
    inspection
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ObservationMetadata, ObservationStore, OperationId, RecordRef};
    use std::time::Duration;
    fn limits() -> RetentionLimits {
        RetentionLimits {
            max_records: 2,
            max_bytes: 4096,
            max_age: Duration::from_secs(5),
        }
    }
    fn view() -> InspectionLimits {
        InspectionLimits {
            max_records: 2,
            max_gaps: 2,
            max_text_chars: 256,
        }
    }
    #[test]
    fn inspection_reports_loss_and_unavailable_correlation_without_draining_receipt() {
        let mut store = ObservationStore::new("run".into(), "source".into(), limits());
        let mut receipt = store.cursor();
        for _ in 0..3 {
            store
                .record(
                    "redacted",
                    8,
                    ObservationMetadata::default(),
                    Duration::ZERO,
                )
                .unwrap();
        }
        let mut reader = store.cursor();
        let batch = store.read(&mut reader, Duration::ZERO, 2).unwrap();
        let rows = inspect_batch(&batch, limits(), view(), |payload| *payload);
        assert!(rows.lines.iter().any(|r| r.text == "Loss evicted: 1"));
        assert!(
            rows.lines
                .iter()
                .any(|r| r.text == "Unavailable records: [1, 2)")
        );
        assert!(rows.lines.iter().any(|r| {
            r.text
                .contains("Operation: unavailable; cause: unavailable")
        }));
        assert_eq!(store.read(&mut receipt, Duration::ZERO, 2).unwrap(), batch);
    }
    #[test]
    fn supplied_cause_retains_its_scope_and_record_identity_survives_label_changes() {
        let mut store = ObservationStore::new("run".into(), "source".into(), limits());
        store
            .record(
                "label",
                5,
                ObservationMetadata {
                    operation: Some(OperationId::from("save:1")),
                    cause: Some(RecordRef {
                        run: "other-run".into(),
                        source: "worker".into(),
                        sequence: 9,
                    }),
                    presented_frame: Some(4),
                    ..ObservationMetadata::default()
                },
                Duration::ZERO,
            )
            .unwrap();
        let batch = store.read(&mut store.cursor(), Duration::ZERO, 2).unwrap();
        let before = inspect_batch(&batch, limits(), view(), |payload| *payload);
        let after = inspect_batch(&batch, limits(), view(), |_| "renamed");
        assert_eq!(
            before.lines.iter().map(|r| &r.id).collect::<Vec<_>>(),
            after.lines.iter().map(|r| &r.id).collect::<Vec<_>>()
        );
        assert!(
            before
                .lines
                .iter()
                .any(|r| r.text.contains("run other-run / source worker / #9"))
        );
        assert!(
            before
                .lines
                .iter()
                .any(|r| r.text.contains("presented frame: 4"))
        );
    }
    #[test]
    fn display_budget_never_changes_observation_loss() {
        let mut store = ObservationStore::new("run".into(), "source".into(), limits());
        for _ in 0..2 {
            store
                .record("é琴𝄞", 9, ObservationMetadata::default(), Duration::ZERO)
                .unwrap();
        }
        let batch = store.read(&mut store.cursor(), Duration::ZERO, 2).unwrap();
        let inspection = inspect_batch(
            &batch,
            limits(),
            InspectionLimits {
                max_records: 1,
                max_gaps: 0,
                max_text_chars: 3,
            },
            |p| *p,
        );
        assert_eq!(inspection.lines.len(), 13);
        assert!(inspection.lines.iter().all(|r| r.text.chars().count() <= 3));
        assert_eq!(batch.stats.loss, crate::LossSummary::default());
        let hidden = inspect_batch(
            &batch,
            limits(),
            InspectionLimits {
                max_records: 0,
                max_gaps: 0,
                max_text_chars: 0,
            },
            |p| *p,
        );
        assert_eq!(hidden.lines.len(), 10);
        assert!(hidden.lines.iter().all(|r| r.text.is_empty()));
    }
    #[test]
    fn disabled_retention_is_not_reported_as_nothing_happened() {
        let disabled = RetentionLimits {
            max_records: 0,
            ..limits()
        };
        let mut store = ObservationStore::new("run".into(), "source".into(), disabled);
        store
            .record(
                "redacted",
                8,
                ObservationMetadata::default(),
                Duration::ZERO,
            )
            .unwrap();
        let batch = store.read(&mut store.cursor(), Duration::ZERO, 2).unwrap();
        let inspection = inspect_batch(&batch, disabled, view(), |p| *p);
        assert!(
            inspection
                .lines
                .iter()
                .any(|r| r.text == "Retention disabled")
        );
        assert!(
            inspection
                .lines
                .iter()
                .any(|r| r.text == "Loss disabled: 1")
        );
    }
}
