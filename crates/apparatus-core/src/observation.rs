// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use std::{collections::VecDeque, fmt, time::Duration};

macro_rules! identity {
    ($name:ident) => {
        #[derive(Clone, Debug, PartialEq, Eq, Hash)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        pub struct $name(pub String);
        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                Self(value.to_owned())
            }
        }
        impl From<String> for $name {
            fn from(value: String) -> Self {
                Self(value)
            }
        }
    };
}

identity!(RunId);
identity!(SourceId);
identity!(SourceBootId);
identity!(OperationId);

/// A record identity. Sequence numbers have meaning only within this run/source.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RecordRef {
    pub run: RunId,
    pub source: SourceId,
    pub sequence: u64,
}

/// A product-defined subject. Apparatus neither resolves nor controls it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SubjectRef {
    pub namespace: String,
    pub id: String,
}

/// Producer-supplied correlation. Missing information remains absent.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ObservationMetadata {
    pub source_boot: Option<SourceBootId>,
    /// Producer clock elapsed time; never compared with host receipt time.
    pub source_time: Option<Duration>,
    pub operation: Option<OperationId>,
    pub cause: Option<RecordRef>,
    pub subject: Option<SubjectRef>,
    pub semantic_revision: Option<u64>,
    pub presented_frame: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Envelope {
    pub schema_version: u16,
    pub reference: RecordRef,
    /// Elapsed host monotonic time, supplied by the collecting product.
    pub receipt_time: Duration,
    pub metadata: ObservationMetadata,
}

/// A product-owned, already redacted payload and its diagnostic context.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Observation<P> {
    pub envelope: Envelope,
    pub payload: P,
    /// Original admission accounting: canonical envelope plus producer-declared
    /// encoded payload bytes. Mapping a batch does not recompute this field.
    pub accounted_bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RetentionLimits {
    pub max_records: usize,
    pub max_bytes: usize,
    /// Expire at this age. A zero in any field disables retention.
    pub max_age: Duration,
}

impl RetentionLimits {
    pub fn enabled(self) -> bool {
        self.max_records > 0 && self.max_bytes > 0 && !self.max_age.is_zero()
    }
}

/// Counters are cumulative within a store run and saturate at u64::MAX.
/// They describe observed loss, never inferred missing producer coverage.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LossSummary {
    pub rejected_disabled: u64,
    pub rejected_oversized: u64,
    pub rejected_accounting: u64,
    pub evicted: u64,
    pub expired: u64,
    pub dropped: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct StoreStats {
    pub run: RunId,
    pub source: SourceId,
    pub generation: u64,
    pub retained_records: usize,
    pub retained_bytes: usize,
    pub first_retained_sequence: Option<u64>,
    pub last_retained_sequence: Option<u64>,
    pub next_sequence: u64,
    pub loss: LossSummary,
}

/// Independent reader position. Fields are private so arbitrary cursor jumps
/// cannot disguise omitted records. Serialize a cursor for inspection, not reuse
/// against a separately constructed store.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Cursor {
    run: RunId,
    source: SourceId,
    generation: u64,
    next_sequence: u64,
}

impl Cursor {
    pub fn next_sequence(&self) -> u64 {
        self.next_sequence
    }
}

/// Unavailable records in the half-open range [first_sequence, next_sequence).
/// Cumulative loss counters describe why the store lost records; a gap does not
/// guess an individual reason after the record itself has been discarded.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Gap {
    pub run: RunId,
    pub source: SourceId,
    pub first_sequence: u64,
    pub next_sequence: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RunBoundary {
    pub previous_run: RunId,
    pub previous_source: SourceId,
    pub previous_generation: u64,
    pub previous_next_sequence: u64,
    pub current_run: RunId,
    pub current_source: SourceId,
    pub current_generation: u64,
}

/// Immutable copied records. Reading does not remove records for other readers.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Batch<P> {
    pub records: Vec<Observation<P>>,
    pub gaps: Vec<Gap>,
    pub boundary: Option<RunBoundary>,
    pub stats: StoreStats,
    pub next_sequence: u64,
}

impl<P> Batch<P> {
    /// Change a product's receipt payload without losing envelope or loss data.
    pub fn map_payload<Q>(self, mut map: impl FnMut(P) -> Q) -> Batch<Q> {
        Batch {
            records: self
                .records
                .into_iter()
                .map(|record| Observation {
                    envelope: record.envelope,
                    accounted_bytes: record.accounted_bytes,
                    payload: map(record.payload),
                })
                .collect(),
            gaps: self.gaps,
            boundary: self.boundary,
            stats: self.stats,
            next_sequence: self.next_sequence,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectionReason {
    Disabled,
    Oversized,
    AccountingOverflow,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Admission {
    Retained(RecordRef),
    Rejected {
        reference: RecordRef,
        reason: RejectionReason,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreError {
    TimeWentBackwards,
    SequenceExhausted,
    GenerationExhausted,
    RunNotChanged,
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TimeWentBackwards => "host monotonic time went backwards",
            Self::SequenceExhausted => "observation sequence exhausted",
            Self::GenerationExhausted => "observation store generation exhausted",
            Self::RunNotChanged => "a reset requires a new unique run identity",
        })
    }
}
impl std::error::Error for StoreError {}

/// Reset returns the old run's final statistics and explicitly discarded count.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResetReport {
    pub previous: StoreStats,
    pub discarded_records: usize,
}

/// A bounded observation copy, not a durable journal or operation authority.
///
/// Products bound and redact payload construction before calling `record`.
/// The caller supplies the length of its chosen encoded payload. Apparatus
/// cannot validate that length for generic P; false accounting defeats byte
/// bounds. This limits accounted encoded bytes, not allocator memory or JSON
/// export size. Envelope accounting is deterministic: u16 version, u64 sequence,
/// durations as u64 seconds + u32 nanos, strings as u64 length + UTF-8 bytes,
/// u64 revisions/frames, and a one-byte tag for every optional field.
/// No queue, exporter, wall clock or runtime is installed by this store.
pub struct ObservationStore<P> {
    run: RunId,
    source: SourceId,
    generation: u64,
    limits: RetentionLimits,
    records: VecDeque<Observation<P>>,
    bytes: usize,
    next_sequence: u64,
    last_time: Option<Duration>,
    loss: LossSummary,
}

impl<P> ObservationStore<P> {
    pub fn new(run: RunId, source: SourceId, limits: RetentionLimits) -> Self {
        Self {
            run,
            source,
            generation: 0,
            limits,
            records: VecDeque::new(),
            bytes: 0,
            next_sequence: 1,
            last_time: None,
            loss: LossSummary::default(),
        }
    }

    pub fn limits(&self) -> RetentionLimits {
        self.limits
    }

    /// Does not advance time; call `expire` for a current-time inspection.
    pub fn stats(&self) -> StoreStats {
        StoreStats {
            run: self.run.clone(),
            source: self.source.clone(),
            generation: self.generation,
            retained_records: self.records.len(),
            retained_bytes: self.bytes,
            first_retained_sequence: self.records.front().map(|r| r.envelope.reference.sequence),
            last_retained_sequence: self.records.back().map(|r| r.envelope.reference.sequence),
            next_sequence: self.next_sequence,
            loss: self.loss,
        }
    }

    /// Starts at the run beginning, so preexisting loss is visible as a gap.
    pub fn cursor(&self) -> Cursor {
        self.cursor_at(1)
    }
    /// Explicitly starts after existing records; earlier coverage is not requested.
    pub fn tail_cursor(&self) -> Cursor {
        self.cursor_at(self.next_sequence)
    }

    fn cursor_at(&self, next_sequence: u64) -> Cursor {
        Cursor {
            run: self.run.clone(),
            source: self.source.clone(),
            generation: self.generation,
            next_sequence,
        }
    }

    fn validate_time(&self, now: Duration) -> Result<(), StoreError> {
        if self.last_time.is_some_and(|previous| now < previous) {
            Err(StoreError::TimeWentBackwards)
        } else {
            Ok(())
        }
    }

    fn pop(&mut self) {
        if let Some(record) = self.records.pop_front() {
            self.bytes -= record.accounted_bytes;
        }
    }

    fn prune(&mut self, now: Duration) {
        while self
            .records
            .front()
            .is_some_and(|record| now - record.envelope.receipt_time >= self.limits.max_age)
        {
            self.pop();
            self.loss.expired = self.loss.expired.saturating_add(1);
        }
        while !self.records.is_empty()
            && (!self.limits.enabled()
                || self.records.len() > self.limits.max_records
                || self.bytes > self.limits.max_bytes)
        {
            self.pop();
            self.loss.evicted = self.loss.evicted.saturating_add(1);
        }
    }

    pub fn expire(&mut self, now: Duration) -> Result<StoreStats, StoreError> {
        self.validate_time(now)?;
        self.last_time = Some(now);
        self.prune(now);
        Ok(self.stats())
    }

    /// Reconfiguration immediately enforces the new bounds.
    pub fn set_limits(&mut self, limits: RetentionLimits, now: Duration) -> Result<(), StoreError> {
        self.validate_time(now)?;
        self.limits = limits;
        self.last_time = Some(now);
        self.prune(now);
        Ok(())
    }

    pub fn record(
        &mut self,
        payload: P,
        payload_encoded_bytes: usize,
        metadata: ObservationMetadata,
        now: Duration,
    ) -> Result<Admission, StoreError> {
        self.validate_time(now)?;
        let following = self
            .next_sequence
            .checked_add(1)
            .ok_or(StoreError::SequenceExhausted)?;
        let reference = RecordRef {
            run: self.run.clone(),
            source: self.source.clone(),
            sequence: self.next_sequence,
        };
        let envelope = Envelope {
            schema_version: 1,
            reference: reference.clone(),
            receipt_time: now,
            metadata,
        };
        let accounted =
            envelope_bytes(&envelope).and_then(|n| n.checked_add(payload_encoded_bytes));
        self.last_time = Some(now);
        self.next_sequence = following;
        self.prune(now);
        let reason = if !self.limits.enabled() {
            self.loss.rejected_disabled = self.loss.rejected_disabled.saturating_add(1);
            Some(RejectionReason::Disabled)
        } else if accounted.is_none() {
            self.loss.rejected_accounting = self.loss.rejected_accounting.saturating_add(1);
            Some(RejectionReason::AccountingOverflow)
        } else if accounted.unwrap() > self.limits.max_bytes {
            self.loss.rejected_oversized = self.loss.rejected_oversized.saturating_add(1);
            Some(RejectionReason::Oversized)
        } else {
            None
        };
        if let Some(reason) = reason {
            return Ok(Admission::Rejected { reference, reason });
        }
        let accounted_bytes = accounted.unwrap();
        // Evict before insertion, including arithmetic overflow avoidance.
        while self.records.len() >= self.limits.max_records
            || self.bytes > self.limits.max_bytes - accounted_bytes
        {
            self.pop();
            self.loss.evicted = self.loss.evicted.saturating_add(1);
        }
        self.bytes += accounted_bytes;
        self.records.push_back(Observation {
            envelope,
            payload,
            accounted_bytes,
        });
        Ok(Admission::Retained(reference))
    }

    /// Records a known count lost before admission (for example at bounded ingress).
    /// The caller supplies actual loss; unavailable instrumentation is not a drop.
    pub fn note_dropped(&mut self, count: u64, now: Duration) -> Result<(), StoreError> {
        self.validate_time(now)?;
        let following = self
            .next_sequence
            .checked_add(count)
            .ok_or(StoreError::SequenceExhausted)?;
        self.last_time = Some(now);
        self.prune(now);
        self.next_sequence = following;
        self.loss.dropped = self.loss.dropped.saturating_add(count);
        Ok(())
    }

    /// Clears storage and per-run counters. Products must supply a unique run
    /// identity, never reusing an earlier run identity. The immediately previous
    /// identity is rejected; retaining an unbounded history of IDs is avoided.
    /// `now` starts the new run's independent monotonic clock.
    pub fn reset(&mut self, run: RunId, now: Duration) -> Result<ResetReport, StoreError> {
        if run == self.run {
            return Err(StoreError::RunNotChanged);
        }
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(StoreError::GenerationExhausted)?;
        let previous = self.stats();
        let discarded_records = self.records.len();
        self.records.clear();
        self.bytes = 0;
        self.run = run;
        self.generation = generation;
        self.next_sequence = 1;
        self.last_time = Some(now);
        self.loss = LossSummary::default();
        Ok(ResetReport {
            previous,
            discarded_records,
        })
    }

    /// Returns at most min(max_records, retained count) copied records. Gaps may
    /// occur between records; stopping at the batch limit never skips a retained
    /// record. Zero returns statistics/boundary but leaves the cursor unchanged.
    pub fn read(
        &mut self,
        cursor: &mut Cursor,
        now: Duration,
        max_records: usize,
    ) -> Result<Batch<P>, StoreError>
    where
        P: Clone,
    {
        self.expire(now)?;
        let boundary = (cursor.run != self.run
            || cursor.source != self.source
            || cursor.generation != self.generation)
            .then(|| RunBoundary {
                previous_run: cursor.run.clone(),
                previous_source: cursor.source.clone(),
                previous_generation: cursor.generation,
                previous_next_sequence: cursor.next_sequence,
                current_run: self.run.clone(),
                current_source: self.source.clone(),
                current_generation: self.generation,
            });
        let mut next = if boundary.is_some() {
            1
        } else {
            cursor.next_sequence
        };
        let mut records = Vec::new();
        let mut gaps = Vec::new();
        if max_records > 0 {
            let starting_sequence = next;
            for record in self
                .records
                .iter()
                .filter(|record| record.envelope.reference.sequence >= starting_sequence)
            {
                if records.len() == max_records {
                    break;
                }
                let sequence = record.envelope.reference.sequence;
                if sequence > next {
                    gaps.push(self.gap(next, sequence));
                }
                next = sequence + 1;
                records.push(record.clone());
            }
            // Advance past trailing unavailable sequences only if every remaining
            // retained record was returned. A full batch leaves its successor for
            // the next read, where any preceding gap is reported.
            let unread_retained = self
                .records
                .back()
                .is_some_and(|record| record.envelope.reference.sequence >= next);
            if !unread_retained && next < self.next_sequence {
                gaps.push(self.gap(next, self.next_sequence));
                next = self.next_sequence;
            }
            *cursor = self.cursor_at(next);
        }
        Ok(Batch {
            records,
            gaps,
            boundary,
            stats: self.stats(),
            next_sequence: next,
        })
    }

    fn gap(&self, first_sequence: u64, next_sequence: u64) -> Gap {
        Gap {
            run: self.run.clone(),
            source: self.source.clone(),
            first_sequence,
            next_sequence,
        }
    }
}

fn envelope_bytes(envelope: &Envelope) -> Option<usize> {
    fn text(value: &str) -> Option<usize> {
        8usize.checked_add(value.len())
    }
    fn reference(value: &RecordRef) -> Option<usize> {
        text(&value.run.0)?
            .checked_add(text(&value.source.0)?)?
            .checked_add(8)
    }
    let metadata = &envelope.metadata;
    // version, reference, receipt duration and seven presence tags.
    let mut bytes = 2usize
        .checked_add(reference(&envelope.reference)?)?
        .checked_add(12 + 7)?;
    if let Some(value) = &metadata.source_boot {
        bytes = bytes.checked_add(text(&value.0)?)?;
    }
    if metadata.source_time.is_some() {
        bytes = bytes.checked_add(12)?;
    }
    if let Some(value) = &metadata.operation {
        bytes = bytes.checked_add(text(&value.0)?)?;
    }
    if let Some(value) = &metadata.cause {
        bytes = bytes.checked_add(reference(value)?)?;
    }
    if let Some(value) = &metadata.subject {
        bytes = bytes
            .checked_add(text(&value.namespace)?)?
            .checked_add(text(&value.id)?)?;
    }
    if metadata.semantic_revision.is_some() {
        bytes = bytes.checked_add(8)?;
    }
    if metadata.presented_frame.is_some() {
        bytes = bytes.checked_add(8)?;
    }
    Some(bytes)
}

#[cfg(test)]
mod tests;
