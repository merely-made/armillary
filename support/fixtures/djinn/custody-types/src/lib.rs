use djinn::door::custody::CustodyEpoch;
#[test] fn zero_epoch_is_invalid() { assert!(!CustodyEpoch { generation: 0, instance: String::new() }.valid()); }
