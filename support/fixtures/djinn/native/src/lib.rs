use djinn::door::{app_admission::default_app_endpoint,app_client::AppConnection};
#[test] fn discovery_and_connection_are_exposed() { assert!(!default_app_endpoint().is_empty()); assert!(std::mem::size_of::<AppConnection>() > 0); }
