// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::io::Write;
use std::path::Path;

use lore_server::util::cert_metrics::*;

// Self-signed test certificate (CN=localhost:8443, expires 2025-09-07)
const TEST_CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIDWTCCAkGgAwIBAgIUIjsbV4maoFQusbqM5oaXqwznp/kwDQYJKoZIhvcNAQEL
BQAwPDEXMBUGA1UEAwwObG9jYWxob3N0Ojg0NDMxFDASBgNVBAoMC1NlbGYgc2ln
bmVkMQswCQYDVQQGEwJDSDAeFw0yNDA5MDcxMTU2NDVaFw0yNTA5MDcxMTU2NDVa
MDwxFzAVBgNVBAMMDmxvY2FsaG9zdDo4NDQzMRQwEgYDVQQKDAtTZWxmIHNpZ25l
ZDELMAkGA1UEBhMCQ0gwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCS
qRG3I7I6lswb1uFc3vukOAJo0XK3wvf35/rr1n+yEI0gTtRmDe57MW9PZ5NdWD2P
04xMOjdvBT3Ih+QOQ3MViKc0bXtXDfxy+P0s/2qqw8wdk1Vjt23G/1ARO88NHib2
YdPg4dUsfsLOUxb7yZYdiTEBLbuUQWYs7C7sTs8ARYukbpBlWICCR1ujJT59CwcU
Pfz6Web//aLk9cfDp3mETU2fr9i0FecSm8lkrsSSJ0d6X49PKwKHBNM1puKPjh0Z
CIeuCWb/PF0YC/tylcRbWkRMdw4yhUZjj2QLa89uInxbQE2mym6pvkj/NwCwPNxI
yBNH5ovgdk7xlPK4RTBLAgMBAAGjUzBRMB0GA1UdDgQWBBQ8LECO5fTmnDZ6rx/W
+fXfHfdHOTAfBgNVHSMEGDAWgBQ8LECO5fTmnDZ6rx/W+fXfHfdHOTAPBgNVHRMB
Af8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCLlFJfM6KXSg1lTk6GRjN5lV2Z
J4ckc89Z2UUUzaWl3w9UzRVJWZeR57OUiBBoiLAZhetIrbYO2nx5YwKJmmDomtfI
OXCWoqRrur4i2mSNot70H4rNWzkbT9dA1x96GRyYZXr8NiXqqcwnRmDi7PCCkweV
z1OZyZH2WV+gXsVSIyGc9OkeB54aXQVLcq1hvqrqPgcN+Lz0/t9kCO/GuFgVdSYd
qDaypyqy8YAKigKSgU5Xs2gfL28Nq0bTGOTy9/fqls8ueMblEm+e5i/4FowvsINa
eFIZ7GeXtWFz+ftM1FrUvXA5XESE0H9iNZklf0dnJXwheUXRpn06bXysEyk4
-----END CERTIFICATE-----
"#;

#[test]
fn test_parse_valid_certificate() {
    let temp_dir = lore_base::test_util::TempDir::new("cert-metrics-test-");
    let cert_path = temp_dir.child("cert.pem");

    let mut file = std::fs::File::create(&cert_path).unwrap();
    file.write_all(TEST_CERT_PEM.as_bytes()).unwrap();

    let result = parse_certificate_info(&cert_path);

    let info = result.expect("should parse valid certificate");
    assert_eq!(info.cert_path, cert_path);
    assert!(info.subject.contains("localhost:8443"));
    assert!(!info.serial.is_empty());
    // Expires 2025-09-07 11:56:45 UTC
    assert_eq!(info.expiry_timestamp, 1757246205);
}

#[test]
fn test_parse_missing_certificate() {
    let result = parse_certificate_info(Path::new("/nonexistent/path/cert.pem"));
    assert!(result.is_none());
}
