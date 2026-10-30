use djinn::door::app_admission::{AppHello, AppId};
#[test] fn hello_accepts_identity() { assert!(AppHello::new(AppId::new("fixture")).accept().is_ok()); }
