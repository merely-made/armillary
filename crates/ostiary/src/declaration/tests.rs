// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

fn declaration() -> AppDeclaration {
    AppDeclaration {
        routes: vec![NamePattern::exact("custody"), NamePattern::prefix("mere/")],
        offers: vec![OfferedProjection {
            route: AppRouteId::new("app-documents").unwrap(),
            label: "Documents".into(),
        }],
        custody: CustodyUse {
            operations: [CustodyOperation::Status, CustodyOperation::ReleaseEpochKeys].into(),
            epoch: vec![
                EpochUse::secret("app.vault.v1", false),
                EpochUse::public("app.writer.v1", false),
            ],
            ..CustodyUse::default()
        },
    }
}

fn grant() -> AppGrant {
    AppGrant {
        app: AppId::new("app"),
        routes: vec![NamePattern::prefix("mere/"), NamePattern::exact("custody")],
        custody: CustodyGrant {
            operations: [
                CustodyOperation::Status,
                CustodyOperation::ReleaseEpochKeys,
                CustodyOperation::Sign,
            ]
            .into(),
            epoch: vec![NamePattern::prefix("app.")],
            ..CustodyGrant::default()
        },
        identity: None,
        agent: false,
    }
}

#[test]
fn a_seal_scope_is_declared_and_pinned_by_the_grant() {
    let mut declaration = declaration();
    let mut grant = grant();
    let unsealed = AppAuthority::new(declaration.clone(), grant.clone());
    assert!(matches!(
        unsealed.payload_scope(),
        Err(AuthorityRefusal::Undeclared { .. })
    ));
    declaration.custody.payload_scope = Some("app.retained/custody-v1".into());
    let ungranted = AppAuthority::new(declaration.clone(), grant.clone());
    assert!(matches!(
        ungranted.payload_scope(),
        Err(AuthorityRefusal::NotGranted { .. })
    ));
    grant.custody.payload_scope = Some("app.other/custody-v1".into());
    let other = AppAuthority::new(declaration.clone(), grant.clone());
    assert!(
        matches!(
            other.payload_scope(),
            Err(AuthorityRefusal::NotGranted { .. })
        ),
        "the grant pins the scope; a different one is not granted"
    );
    grant.custody.payload_scope = declaration.custody.payload_scope.clone();
    let sealed = AppAuthority::new(declaration.clone(), grant.clone());
    assert_eq!(sealed.payload_scope(), Ok("app.retained/custody-v1"));
    declaration.custody.payload_scope = Some("has space".into());
    assert!(declaration.validate().is_err());
}

#[test]
fn the_agent_mark_round_trips_and_is_absent_by_default() {
    let mut grant = grant();
    assert!(!serde_json::to_string(&grant).unwrap().contains("agent"));
    grant.agent = true;
    let text = serde_json::to_string(&grant).unwrap();
    assert_eq!(serde_json::from_str::<AppGrant>(&text).unwrap(), grant);
}

#[test]
fn a_prefix_needs_a_name_beyond_it() {
    let mere = NamePattern::prefix("mere/");
    assert!(mere.matches("mere/notes"));
    assert!(!mere.matches("mere/"));
    assert!(!mere.matches("ambient/mere/notes"));
    assert!(NamePattern::exact("custody").matches("custody"));
    assert!(!NamePattern::exact("custody").matches("custody2"));
}

#[test]
fn custody_needs_both_declaration_and_grant() {
    let authority = AppAuthority::new(declaration(), grant());
    assert!(
        authority
            .custody_operation(CustodyOperation::Status)
            .is_ok()
    );
    assert!(matches!(
        authority.custody_operation(CustodyOperation::Sign),
        Err(AuthorityRefusal::Undeclared { .. })
    ));
    let mut narrow = grant();
    narrow
        .custody
        .operations
        .remove(&CustodyOperation::ReleaseEpochKeys);
    assert!(matches!(
        AppAuthority::new(declaration(), narrow)
            .custody_operation(CustodyOperation::ReleaseEpochKeys),
        Err(AuthorityRefusal::NotGranted { .. })
    ));
}

#[test]
fn epoch_releases_match_the_declared_derivation_exactly() {
    let authority = AppAuthority::new(declaration(), grant());
    assert!(authority.epoch("app.vault.v1", false, false).is_ok());
    assert!(
        authority.epoch("app.vault.v1", false, true).is_ok(),
        "a secret use covers its public key"
    );
    assert!(authority.epoch("app.writer.v1", false, true).is_ok());
    assert!(matches!(
        authority.epoch("app.writer.v1", false, false),
        Err(AuthorityRefusal::Undeclared { .. })
    ));
    assert!(matches!(
        authority.epoch("app.vault.v1", true, false),
        Err(AuthorityRefusal::Undeclared { .. })
    ));
    let mut other = grant();
    other.custody.epoch = vec![NamePattern::prefix("other.")];
    assert!(matches!(
        AppAuthority::new(declaration(), other).epoch("app.vault.v1", false, false),
        Err(AuthorityRefusal::NotGranted { .. })
    ));
}

#[test]
fn salts_match_text_prefixes_over_bytes_and_acts_never_release() {
    let mut declaration = declaration();
    declaration.custody.salts = vec![SaltUse::persona(SaltPattern::Prefix("app.place.".into()))];
    declaration.custody.acts = vec![SaltUse::persona(SaltPattern::Prefix(
        "app/delegation/".into(),
    ))];
    let mut wide = grant();
    wide.custody.salts = vec![SaltUse::persona(SaltPattern::Prefix("app.".into()))];
    wide.custody.acts = vec![SaltUse::persona(SaltPattern::Prefix("app/".into()))];
    let authority = AppAuthority::new(declaration, wide);
    assert!(
        authority
            .salt(SaltSource::Persona, b"app.place.p1", true)
            .is_ok()
    );
    assert!(
        authority
            .salt(SaltSource::Persona, b"app.place.p1", false)
            .is_ok(),
        "released covers acts"
    );
    let binary = [b"app/delegation/".as_slice(), &[0xff, 0x00, 0x9c]].concat();
    assert!(
        authority.salt(SaltSource::Persona, &binary, false).is_ok(),
        "a binary suffix after a text prefix"
    );
    assert!(
        matches!(
            authority.salt(SaltSource::Persona, &binary, true),
            Err(AuthorityRefusal::Undeclared { .. })
        ),
        "an act never releases"
    );
    assert!(
        matches!(
            authority.salt(SaltSource::Wallet, b"app.place.p1", true),
            Err(AuthorityRefusal::Undeclared { .. })
        ),
        "the root matters"
    );
    assert!(
        matches!(
            authority.salt(SaltSource::Persona, b"app.place.", true),
            Err(AuthorityRefusal::Undeclared { .. })
        ),
        "a prefix needs more"
    );
    assert!(
        matches!(
            authority.salt(SaltSource::Persona, b"", false),
            Err(AuthorityRefusal::Undeclared { .. })
        ),
        "never the master's place"
    );

    let mut narrow = grant();
    narrow.custody.acts = vec![SaltUse::persona(SaltPattern::Prefix("app/".into()))];
    let mut declaration = super::tests::declaration();
    declaration.custody.salts = vec![SaltUse::persona(SaltPattern::Prefix("app.place.".into()))];
    let authority = AppAuthority::new(declaration, narrow);
    assert!(matches!(
        authority.salt(SaltSource::Persona, b"app.place.p1", true),
        Err(AuthorityRefusal::NotGranted { .. })
    ));
}

#[test]
fn a_delegation_scope_names_every_resource_in_its_domain() {
    let mut declaration = AppDeclaration::default();
    declaration.custody.salts = vec![SaltUse::persona(SaltPattern::DelegationScope(
        "mere.knot".into(),
    ))];
    let mut wide = grant();
    wide.custody.salts = declaration.custody.salts.clone();
    assert!(
        declaration.validate().is_ok(),
        "the domain is text even though the salt is not"
    );
    let authority = AppAuthority::new(declaration, wide);
    let salt = [
        delegation_scope_prefix("mere.knot"),
        vec![32, 0, 0, 0, 0, 0, 0, 0, 0xab],
    ]
    .concat();
    assert!(authority.salt(SaltSource::Persona, &salt, true).is_ok());
    let other = [delegation_scope_prefix("mere.knots"), vec![1]].concat();
    assert!(
        authority.salt(SaltSource::Persona, &other, true).is_err(),
        "the domain is length-framed"
    );
    assert!(
        authority
            .salt(
                SaltSource::Persona,
                &delegation_scope_prefix("mere.knot"),
                true
            )
            .is_err()
    );
    let json = serde_json::to_value(SaltUse::persona(SaltPattern::DelegationScope(
        "moot".into(),
    )))
    .unwrap();
    assert_eq!(
        json,
        serde_json::json!({"source": "persona", "name": {"delegation_scope": "moot"}})
    );
}

#[test]
fn offers_are_named_by_route() {
    let authority = AppAuthority::new(declaration(), grant());
    assert_eq!(
        authority
            .offer(&AppRouteId::new("app-documents").unwrap())
            .unwrap()
            .label,
        "Documents"
    );
    assert!(
        authority
            .offer(&AppRouteId::new("app-other").unwrap())
            .is_err()
    );
}

#[test]
fn the_wire_shape_is_compact_and_strict() {
    let json = serde_json::to_value(declaration()).unwrap();
    assert_eq!(json["routes"][1], serde_json::json!({"prefix": "mere/"}));
    assert_eq!(
        json["custody"]["operations"],
        serde_json::json!(["status", "release_epoch_keys"])
    );
    assert_eq!(
        serde_json::to_string(&AppDeclaration::default()).unwrap(),
        "{}"
    );
    assert!(serde_json::from_str::<AppDeclaration>(r#"{"routes":[],"extra":1}"#).is_err());
    let back: AppDeclaration = serde_json::from_value(json).unwrap();
    assert_eq!(back, declaration());
}

#[test]
fn malformed_declarations_and_grants_are_rejected() {
    assert!(declaration().validate().is_ok());
    assert!(grant().validate().is_ok());
    let mut spaced = declaration();
    spaced.routes.push(NamePattern::prefix("mere /"));
    assert!(spaced.validate().is_err());
    let mut empty = grant();
    empty.routes.push(NamePattern::exact(""));
    assert!(empty.validate().is_err());
    let mut many = declaration();
    many.routes = (0..=MAX_DECLARED_ENTRIES)
        .map(|i| NamePattern::exact(format!("r{i}")))
        .collect();
    assert_eq!(many.validate(), Err(DeclarationError::TooLarge));
}
