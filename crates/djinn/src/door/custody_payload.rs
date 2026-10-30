// Copyright 2026 Mark Alan Boykin
// SPDX-License-Identifier: MPL-2.0

//! Bounded retained-content operations. Keys and store paths stay in custody.
use eidetic::{Hash, SealedBlobRef};
use personae::ProfileId;
use serde::{Deserialize, Serialize};

/// Independent from an application's selected inventory budget.
pub const MAX_PAYLOAD_BYTES: usize = 512 * 1024;

/// Never include retained text, ciphertext or audio in debug diagnostics.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayloadBytes(#[serde(with = "super::custody::b64")] pub Vec<u8>);

impl std::fmt::Debug for PayloadBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PayloadBytes")
            .field("length", &self.0.len())
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum PayloadOperation {
    Seal {
        bytes: PayloadBytes,
    },
    Unseal {
        bytes: PayloadBytes,
        marker: SealedBlobRef,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayloadRequest {
    pub profile: ProfileId,
    pub master: [u8; 32],
    pub content_hash: Hash,
    pub operation: PayloadOperation,
    /// A private binding names the exact custodian lifetime/generation. None
    /// preserves legacy wire decoding; qualified private hosts require Some.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custody_epoch: Option<super::custody::CustodyEpoch>,
}

impl PayloadRequest {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self
            .custody_epoch
            .as_ref()
            .is_some_and(|epoch| !epoch.valid())
        {
            return Err("invalid retained payload custody generation");
        }
        let (bytes, limit) = match &self.operation {
            PayloadOperation::Seal { bytes } => {
                if Hash::of(&bytes.0) != self.content_hash {
                    return Err("retained payload hash differs");
                }
                (bytes, MAX_PAYLOAD_BYTES)
            }
            PayloadOperation::Unseal { bytes, marker } => {
                if marker.format != eidetic::seal::SEAL_FORMAT_V1 {
                    return Err("unsupported retained payload seal");
                }
                // The standard seal adds a 24-byte nonce and 16-byte tag.
                (bytes, MAX_PAYLOAD_BYTES + 40)
            }
        };
        if bytes.0.len() > limit {
            return Err("retained payload exceeds custody budget");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum PayloadResult {
    Sealed {
        bytes: PayloadBytes,
        marker: SealedBlobRef,
    },
    Clear {
        bytes: PayloadBytes,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retained_material_is_redacted_and_hash_checked_on_the_wire() {
        let request = PayloadRequest {
            custody_epoch: None,
            profile: ProfileId("family".into()),
            master: [7; 32],
            content_hash: Hash::of(b"private retained passage"),
            operation: PayloadOperation::Seal {
                bytes: PayloadBytes(b"private retained passage".to_vec()),
            },
        };
        assert!(!format!("{request:?}").contains("private retained passage"));
        let wire = serde_json::to_vec(&super::super::custody::CustodyCall::Payload(
            request.clone(),
        ))
        .unwrap();
        let decoded: super::super::custody::CustodyCall = serde_json::from_slice(&wire).unwrap();
        assert_eq!(
            decoded,
            super::super::custody::CustodyCall::Payload(request.clone())
        );
        assert!(request.validate().is_ok());
        assert!(
            PayloadRequest {
                custody_epoch: None,
                content_hash: Hash::of(b"changed"),
                ..request
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn the_payload_budget_fits_the_existing_transport_and_roundtrips_seal_overhead() {
        let request = PayloadRequest {
            custody_epoch: None,
            profile: ProfileId("family".into()),
            master: [7; 32],
            content_hash: Hash::of(&vec![0; MAX_PAYLOAD_BYTES]),
            operation: PayloadOperation::Seal {
                bytes: PayloadBytes(vec![0; MAX_PAYLOAD_BYTES]),
            },
        };
        request.validate().unwrap();
        let mut framed = Vec::new();
        super::super::frame::write_native_message(
            &mut framed,
            &super::super::custody::CustodyCall::Payload(request.clone()),
        )
        .unwrap();
        assert!(framed.len() < super::super::frame::MAX_NATIVE_MESSAGE_BYTES as usize);
        let marker = SealedBlobRef {
            epoch: eidetic::SealEpochId([0; 16]),
            format: eidetic::seal::SEAL_FORMAT_V1.into(),
        };
        let mut read = PayloadRequest {
            custody_epoch: None,
            operation: PayloadOperation::Unseal {
                bytes: PayloadBytes(vec![0; MAX_PAYLOAD_BYTES + 40]),
                marker,
            },
            ..request
        };
        read.validate().unwrap();
        if let PayloadOperation::Unseal { bytes, .. } = &mut read.operation {
            bytes.0.push(0);
        }
        assert!(read.validate().is_err());
    }
}
