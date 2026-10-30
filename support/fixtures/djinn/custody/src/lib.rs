use djinn::door::custody_client::CustodyClientError;
#[test] fn client_error_is_exposed() { assert!(std::mem::size_of::<CustodyClientError>() > 0); }
