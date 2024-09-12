use selfie_records_sdk::SelfieRecordsSDK;

#[test]
fn test_get_records() {
    let sdk = SelfieRecordsSDK::new(true);
    let records = sdk.get_records("example.com", None, Some("8.8.8.8"));
    assert!(!records.is_empty());
}
