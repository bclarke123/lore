// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_server::grpc::server::*;
use tonic::transport::server::Server;

/// Every service's table key paired with its settings block.
fn all_service_blocks(
    settings: &GrpcPublicServicesSettings,
) -> [(&'static str, &dyn GrpcServiceSettings); 8] {
    [
        ("admin_service", &settings.admin_service),
        ("storage_service", &settings.storage_service),
        ("revision_service", &settings.revision_service),
        ("repository_service", &settings.repository_service),
        ("environment_service", &settings.environment_service),
        ("thin_client_service", &settings.thin_client_service),
        ("lock_service", &settings.lock_service),
        ("notification_service", &settings.notification_service),
    ]
}

/// An absent block means enabled.
#[test]
fn an_absent_block_enables_the_service() {
    let settings: GrpcPublicServicesSettings =
        serde_json::from_str("{}").expect("an empty table is valid");

    for (name, service) in all_service_blocks(&settings) {
        assert!(
            service.enabled(),
            "{name} must register when its block is absent"
        );
    }
}

/// A present block with an absent `enabled` key means enabled.
#[test]
fn an_absent_enabled_key_enables_the_service() {
    let settings: GrpcPublicServicesSettings =
        serde_json::from_str(r#"{"lock_service": {"general": {}}}"#)
            .expect("a block without `enabled` is valid");

    assert!(settings.lock_service.enabled());
}

#[test]
fn a_disabled_service_reports_disabled_and_leaves_the_rest_alone() {
    let settings: GrpcPublicServicesSettings =
        serde_json::from_str(r#"{"storage_service": {"enabled": false}}"#)
            .expect("a disabled block is valid");

    assert!(!settings.storage_service.enabled());
    assert!(settings.thin_client_service.enabled());
}

#[test]
fn general_settings_nest_under_the_service_block() {
    let settings: GrpcPublicServicesSettings = serde_json::from_str(
        r#"{"lock_service": {"general": {"max_encoding_message_size": 16777216}}}"#,
    )
    .expect("a nested general block is valid");

    assert_eq!(
        settings.lock_service.general().max_encoding_message_size,
        Some(16_777_216)
    );
}

/// Unknown keys are ignored, so a misspelled disable leaves the service
/// registered.
#[test]
fn a_misspelled_disable_leaves_the_service_registered() {
    let misspelled_block: GrpcPublicServicesSettings =
        serde_json::from_str(r#"{"storage_servce": {"enabled": false}}"#)
            .expect("an unknown block is ignored");
    let misspelled_key: GrpcPublicServicesSettings =
        serde_json::from_str(r#"{"storage_service": {"enabld": false}}"#)
            .expect("an unknown key is ignored");

    assert!(misspelled_block.storage_service.enabled());
    assert!(misspelled_key.storage_service.enabled());
}

/// Every service's table key is distinct and addresses its own block.
#[test]
fn every_service_has_its_own_block_under_the_key_it_renders() {
    let default_settings = GrpcPublicServicesSettings::default();
    let all = all_service_blocks(&default_settings);
    let mut names: Vec<&str> = all.iter().map(|(name, _)| *name).collect();
    names.sort_unstable();
    names.dedup();

    assert_eq!(names.len(), all.len(), "{names:?}");

    for (key, _) in all {
        let settings: GrpcPublicServicesSettings =
            serde_json::from_str(&format!(r#"{{"{key}": {{"enabled": false}}}}"#))
                .unwrap_or_else(|error| panic!("{key} must be a settings key: {error}"));

        let (_, disabled_service) = all_service_blocks(&settings)
            .into_iter()
            .find(|(name, _)| *name == key)
            .expect("every rendered key must resolve back to its own block");

        assert!(
            !disabled_service.enabled(),
            "{key} must address its own block"
        );
    }
}

/// A configuration disabling every service still deserializes.
#[test]
fn all_disabled_still_deserializes() {
    let disabled = all_service_blocks(&GrpcPublicServicesSettings::default())
        .iter()
        .map(|(name, _)| format!(r#""{name}": {{"enabled": false}}"#))
        .collect::<Vec<_>>()
        .join(", ");
    let settings: GrpcPublicServicesSettings =
        serde_json::from_str(&format!("{{{disabled}}}")).expect("must still deserialize");

    for (name, service) in all_service_blocks(&settings) {
        assert!(!service.enabled(), "{name} must read as disabled");
    }
}

/// Generate a CA and a matching server cert+key using rcgen, writing the cert
/// and key to a tempdir (the server takes file paths, not PEM bytes).
///
/// Returns `(ca_pem, cert_path, key_path, _dir)`.  The caller must keep
/// `_dir` alive for as long as the paths are needed; dropping it removes the
/// files.
fn generate_test_certs() -> (
    String,
    std::path::PathBuf,
    std::path::PathBuf,
    lore_base::test_util::TempDir,
) {
    use rcgen::BasicConstraints;
    use rcgen::CertificateParams;
    use rcgen::IsCa;
    use rcgen::Issuer;
    use rcgen::KeyPair;
    use rcgen::KeyUsagePurpose;

    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca_pem = ca_cert.pem();
    let issuer = Issuer::new(ca_params, ca_key);

    let server_key = KeyPair::generate().unwrap();
    let server_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let server_cert = server_params.signed_by(&server_key, &issuer).unwrap();

    let dir = lore_base::test_util::TempDir::new("lore-server-tls-test-");
    let cert_path = dir.path().join("server.crt");
    let key_path = dir.path().join("server.key");
    std::fs::write(&cert_path, server_cert.pem()).unwrap();
    std::fs::write(&key_path, server_key.serialize_pem()).unwrap();

    (ca_pem, cert_path, key_path, dir)
}

#[test]
fn build_server_tls_config_valid_cert_and_key_succeeds() {
    let (_ca_pem, cert_path, key_path, _dir) = generate_test_certs();
    let config = build_server_tls_config(cert_path, key_path, None)
        .expect("build_server_tls_config should not fail for a matched cert+key");

    // Applying to a server builder is what actually validates the cert+key pair —
    // rustls rejects a mismatch here with KeyMismatch.
    Server::builder()
        .tls_config(config)
        .expect("server builder should accept a matched cert+key");
}

#[test]
fn build_server_tls_config_with_ca_cert_succeeds() {
    let (ca_pem, cert_path, key_path, dir) = generate_test_certs();
    let ca_path = dir.path().join("ca.crt");
    std::fs::write(&ca_path, &ca_pem).unwrap();

    let config = build_server_tls_config(cert_path, key_path, Some(ca_path))
        .expect("build_server_tls_config should not fail for a matched cert+key with CA");

    // Applying to a server builder validates both the cert+key pair and that
    // the CA cert is valid PEM accepted by the TLS stack.
    Server::builder()
        .tls_config(config)
        .expect("server builder should accept a matched cert+key with a valid CA cert");
}

#[test]
fn build_server_tls_config_mismatched_cert_and_key_is_rejected_by_server_builder() {
    // Generate two independent chains; their certs and keys are not interchangeable.
    let (_ca_a, cert_path_a, _key_a, _dir_a) = generate_test_certs();
    let (_ca_b, _cert_b, key_path_b, _dir_b) = generate_test_certs();

    // build_server_tls_config itself succeeds — it only reads bytes.
    let config = build_server_tls_config(cert_path_a, key_path_b, None)
        .expect("build_server_tls_config should not fail reading files");

    // The mismatch is caught when the config is applied to a server builder;
    // rustls validates that the cert and key form a consistent pair at this point.
    let result = Server::builder().tls_config(config);
    assert!(
        result.is_err(),
        "expected Err when applying a mismatched cert+key to a server builder"
    );
    let err = format!("{:?}", result.unwrap_err());
    assert!(
        err.contains("KeyMismatch") || err.contains("key"),
        "expected a key-mismatch error, got: {err}"
    );
}
