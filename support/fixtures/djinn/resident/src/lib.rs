use djinn::resident::RunFailure;
#[test] fn failure_keeps_source() { let f = RunFailure::new("fixture", "failed"); assert!(format!("{f:?}").contains("fixture")); }
