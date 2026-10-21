// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

fn limits() -> RetentionLimits {
    RetentionLimits {
        max_records: 3,
        max_bytes: 1000,
        max_age: Duration::from_secs(10),
    }
}
fn store(limits: RetentionLimits) -> ObservationStore<&'static str> {
    ObservationStore::new("run".into(), "source".into(), limits)
}
fn record(store: &mut ObservationStore<&'static str>, text: &'static str, at: u64) -> Admission {
    store
        .record(
            text,
            text.len(),
            ObservationMetadata::default(),
            Duration::from_secs(at),
        )
        .unwrap()
}
fn sequences(batch: &Batch<&str>) -> Vec<u64> {
    batch
        .records
        .iter()
        .map(|record| record.envelope.reference.sequence)
        .collect()
}
fn gap_ranges(batch: &Batch<&str>) -> Vec<(u64, u64)> {
    batch
        .gaps
        .iter()
        .map(|gap| (gap.first_sequence, gap.next_sequence))
        .collect()
}

#[test]
fn zero_of_any_limit_disables_retention_and_reports_loss() {
    let mut policies = [limits(); 3];
    policies[0].max_records = 0;
    policies[1].max_bytes = 0;
    policies[2].max_age = Duration::ZERO;
    for policy in policies {
        let mut store = store(policy);
        let mut cursor = store.cursor();
        for _ in 0..50 {
            assert!(matches!(
                record(&mut store, "redacted", 0),
                Admission::Rejected {
                    reason: RejectionReason::Disabled,
                    ..
                }
            ));
        }
        let batch = store.read(&mut cursor, Duration::ZERO, usize::MAX).unwrap();
        assert!(batch.records.is_empty());
        assert_eq!(batch.stats.retained_bytes, 0);
        assert_eq!(batch.stats.loss.rejected_disabled, 50);
        assert_eq!(gap_ranges(&batch), [(1, 51)]);
        assert_eq!(cursor.next_sequence(), 51);
    }
}

#[test]
fn count_eviction_and_slow_readers_are_independent() {
    let mut store = store(limits());
    let mut fast = store.cursor();
    let mut slow = store.cursor();
    record(&mut store, "one", 0);
    let earlier = store.read(&mut fast, Duration::ZERO, 1).unwrap();
    for text in ["two", "three", "four"] {
        record(&mut store, text, 0);
    }
    let fast_batch = store.read(&mut fast, Duration::ZERO, 99).unwrap();
    let slow_batch = store.read(&mut slow, Duration::ZERO, 99).unwrap();
    assert_eq!(sequences(&fast_batch), [2, 3, 4]);
    assert!(fast_batch.gaps.is_empty());
    assert_eq!(sequences(&slow_batch), [2, 3, 4]);
    assert_eq!(gap_ranges(&slow_batch), [(1, 2)]);
    assert_eq!(slow_batch.stats.loss.evicted, 1);
    assert_eq!(earlier.records[0].payload, "one"); // copied batch survives eviction
}

#[test]
fn byte_limit_accounts_envelope_and_payload_and_evicts_before_admission() {
    let mut store = store(limits());
    record(&mut store, "abc", 0);
    let bytes = store.stats().retained_bytes;
    // u16 schema + length-prefixed run/source + sequence + duration + seven tags + payload.
    assert_eq!(bytes, 2 + (8 + 3) + (8 + 6) + 8 + 12 + 7 + 3);
    store
        .set_limits(
            RetentionLimits {
                max_bytes: bytes,
                ..limits()
            },
            Duration::ZERO,
        )
        .unwrap();
    record(&mut store, "xyz", 0);
    assert_eq!(store.stats().retained_records, 1);
    assert_eq!(store.stats().retained_bytes, bytes);
    assert_eq!(store.stats().loss.evicted, 1);
    let mut cursor = store.cursor();
    let batch = store.read(&mut cursor, Duration::ZERO, 1).unwrap();
    assert_eq!(gap_ranges(&batch), [(1, 2)]);
    assert_eq!(sequences(&batch), [2]);
}

#[test]
fn oversize_rejection_preserves_retained_records_and_consumes_sequence() {
    let mut store = store(limits());
    record(&mut store, "one", 0);
    let admission = store
        .record("huge", 1000, ObservationMetadata::default(), Duration::ZERO)
        .unwrap();
    assert!(matches!(
        admission,
        Admission::Rejected {
            reason: RejectionReason::Oversized,
            ..
        }
    ));
    record(&mut store, "three", 0);
    let mut cursor = store.cursor();
    let batch = store.read(&mut cursor, Duration::ZERO, 99).unwrap();
    assert_eq!(sequences(&batch), [1, 3]);
    assert_eq!(gap_ranges(&batch), [(2, 3)]);
    assert_eq!(batch.stats.loss.rejected_oversized, 1);
    assert_eq!(batch.stats.loss.evicted, 0);
}

#[test]
fn envelope_metadata_is_included_in_admission_accounting() {
    let mut store = store(limits());
    let metadata = ObservationMetadata {
        subject: Some(SubjectRef {
            namespace: "object".into(),
            id: "x".repeat(1000),
        }),
        ..Default::default()
    };
    assert!(matches!(
        store.record("", 0, metadata, Duration::ZERO).unwrap(),
        Admission::Rejected {
            reason: RejectionReason::Oversized,
            ..
        }
    ));
    assert_eq!(store.stats().retained_bytes, 0);
}

#[test]
fn accounting_overflow_is_a_visible_rejection() {
    let mut store = store(limits());
    assert!(matches!(
        store
            .record(
                "",
                usize::MAX,
                ObservationMetadata::default(),
                Duration::ZERO
            )
            .unwrap(),
        Admission::Rejected {
            reason: RejectionReason::AccountingOverflow,
            ..
        }
    ));
    assert_eq!(store.stats().loss.rejected_accounting, 1);
    let mut cursor = store.cursor();
    assert_eq!(
        gap_ranges(&store.read(&mut cursor, Duration::ZERO, 1).unwrap()),
        [(1, 2)]
    );
}

#[test]
fn age_expires_at_equality_even_without_new_records() {
    let mut store = store(limits());
    record(&mut store, "one", 0);
    record(&mut store, "two", 1);
    let mut cursor = store.cursor();
    let batch = store
        .read(&mut cursor, Duration::from_secs(10), 99)
        .unwrap();
    assert_eq!(sequences(&batch), [2]);
    assert_eq!(gap_ranges(&batch), [(1, 2)]);
    assert_eq!(batch.stats.loss.expired, 1);
    let batch = store
        .read(&mut cursor, Duration::from_secs(11), 99)
        .unwrap();
    assert!(batch.records.is_empty());
    assert_eq!(batch.stats.loss.expired, 2);
    assert_eq!(batch.stats.retained_bytes, 0);
}

#[test]
fn bounded_batches_keep_gaps_and_never_skip_retained_successors() {
    let mut store = store(limits());
    record(&mut store, "one", 0);
    store.note_dropped(2, Duration::ZERO).unwrap();
    record(&mut store, "four", 0);
    store.note_dropped(1, Duration::ZERO).unwrap();
    let mut cursor = store.cursor();
    let first = store.read(&mut cursor, Duration::ZERO, 1).unwrap();
    assert_eq!(sequences(&first), [1]);
    assert_eq!(first.next_sequence, 2);
    let second = store.read(&mut cursor, Duration::ZERO, 1).unwrap();
    assert_eq!(sequences(&second), [4]);
    assert_eq!(gap_ranges(&second), [(2, 4), (5, 6)]);
    assert_eq!(second.stats.loss.dropped, 3);
    let empty = store.read(&mut cursor, Duration::ZERO, 1).unwrap();
    assert!(empty.records.is_empty() && empty.gaps.is_empty());
}

#[test]
fn zero_read_is_nondestructive_and_tail_is_explicit() {
    let mut store = store(limits());
    record(&mut store, "one", 0);
    let mut cursor = store.cursor();
    let before = cursor.clone();
    let batch = store.read(&mut cursor, Duration::ZERO, 0).unwrap();
    assert!(batch.records.is_empty() && batch.gaps.is_empty());
    assert_eq!(cursor, before);
    let mut tail = store.tail_cursor();
    assert!(
        store
            .read(&mut tail, Duration::ZERO, 99)
            .unwrap()
            .records
            .is_empty()
    );
    record(&mut store, "two", 0);
    assert_eq!(
        sequences(&store.read(&mut tail, Duration::ZERO, 99).unwrap()),
        [2]
    );
    assert_eq!(
        sequences(&store.read(&mut cursor, Duration::ZERO, 99).unwrap()),
        [1, 2]
    );
}

#[test]
fn reset_reports_old_run_and_old_readers_receive_a_boundary() {
    let mut store = store(limits());
    record(&mut store, "old", 100);
    let mut cursor = store.tail_cursor();
    let reset = store.reset("next-run".into(), Duration::ZERO).unwrap();
    assert_eq!(reset.discarded_records, 1);
    assert_eq!(reset.previous.retained_records, 1);
    record(&mut store, "new", 0);
    let previous_cursor = cursor.clone();
    let no_read = store.read(&mut cursor, Duration::ZERO, 0).unwrap();
    assert!(no_read.boundary.is_some());
    assert_eq!(cursor, previous_cursor);
    let batch = store.read(&mut cursor, Duration::ZERO, 99).unwrap();
    assert_eq!(sequences(&batch), [1]);
    let boundary = batch.boundary.unwrap();
    assert_eq!(boundary.previous_run, RunId::from("run"));
    assert_eq!(boundary.current_run, RunId::from("next-run"));
    assert_eq!(batch.stats.loss, LossSummary::default());
    assert!(
        store
            .read(&mut cursor, Duration::ZERO, 99)
            .unwrap()
            .boundary
            .is_none()
    );
    assert_eq!(
        store.reset("next-run".into(), Duration::ZERO),
        Err(StoreError::RunNotChanged)
    );
}

#[test]
fn backward_receipt_time_rejects_without_changing_sequence_or_cursor() {
    let mut store = store(limits());
    record(&mut store, "one", 2);
    let mut cursor = store.cursor();
    let original = cursor.clone();
    assert_eq!(
        store.record("bad", 3, ObservationMetadata::default(), Duration::ZERO),
        Err(StoreError::TimeWentBackwards)
    );
    assert_eq!(
        store.note_dropped(1, Duration::ZERO),
        Err(StoreError::TimeWentBackwards)
    );
    assert_eq!(
        store.read(&mut cursor, Duration::ZERO, 99),
        Err(StoreError::TimeWentBackwards)
    );
    assert_eq!(cursor, original);
    assert_eq!(store.stats().next_sequence, 2);
}

#[test]
fn correlation_and_source_time_preserved_without_inferring_order() {
    let mut store = store(limits());
    let metadata = ObservationMetadata {
        source_boot: Some("device-boot".into()),
        source_time: Some(Duration::from_secs(900)),
        operation: Some("operation-B".into()),
        cause: Some(RecordRef {
            run: "foreign-run".into(),
            source: "worker".into(),
            sequence: 80,
        }),
        semantic_revision: Some(3),
        presented_frame: Some(9),
        ..Default::default()
    };
    store
        .record(
            "worker B completed first",
            24,
            metadata.clone(),
            Duration::ZERO,
        )
        .unwrap();
    record(&mut store, "worker A completed later", 1);
    let mut cursor = store.cursor();
    let batch = store.read(&mut cursor, Duration::from_secs(1), 99).unwrap();
    assert_eq!(sequences(&batch), [1, 2]);
    assert_eq!(batch.records[0].envelope.metadata, metadata);
    assert_eq!(batch.records[0].envelope.receipt_time, Duration::ZERO);
    assert!(batch.records[1].envelope.metadata.operation.is_none());
    let mapped = batch.clone().map_payload(|text| text.len());
    assert_eq!(mapped.records[0].envelope, batch.records[0].envelope);
    assert_eq!(mapped.stats, batch.stats);
    assert_eq!(mapped.records[0].payload, 24);
}

#[test]
fn reducing_limits_enforces_bounds_immediately() {
    let mut store = store(limits());
    for _ in 0..3 {
        record(&mut store, "one", 0);
    }
    store
        .set_limits(
            RetentionLimits {
                max_records: 1,
                ..limits()
            },
            Duration::ZERO,
        )
        .unwrap();
    assert_eq!(store.stats().retained_records, 1);
    assert_eq!(store.stats().loss.evicted, 2);
    store
        .set_limits(
            RetentionLimits {
                max_bytes: 0,
                ..limits()
            },
            Duration::ZERO,
        )
        .unwrap();
    assert_eq!(store.stats().retained_records, 0);
    assert_eq!(store.stats().retained_bytes, 0);
    assert_eq!(store.stats().loss.evicted, 3);
}

#[test]
fn sequence_exhaustion_is_transactional() {
    let mut store = store(limits());
    store.next_sequence = u64::MAX;
    assert_eq!(
        store.record("", 0, ObservationMetadata::default(), Duration::ZERO),
        Err(StoreError::SequenceExhausted)
    );
    assert_eq!(
        store.note_dropped(1, Duration::ZERO),
        Err(StoreError::SequenceExhausted)
    );
    assert_eq!(store.stats().loss, LossSummary::default());
    assert!(store.last_time.is_none());
}
