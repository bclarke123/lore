// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::path::Path;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use lore_base::lore_spawn;
use lore_telemetry::InstrumentProvider;
use opentelemetry::KeyValue;
use opentelemetry::metrics::Gauge;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use tokio::time::MissedTickBehavior;
use tracing::debug;
use tracing::warn;
use x509_parser::prelude::*;

/// Information extracted from a TLS certificate for metrics reporting.
#[derive(Debug, Clone)]
pub struct CertificateInfo {
    /// Path to the certificate file.
    pub cert_path: PathBuf,
    /// Certificate subject (e.g., CN=example.com).
    pub subject: String,
    /// Certificate serial number in hex format.
    pub serial: String,
    /// Unix timestamp when the certificate expires.
    pub expiry_timestamp: i64,
}

struct CertificateMetricsInstrumentProvider;

impl InstrumentProvider for CertificateMetricsInstrumentProvider {
    fn namespace(&self) -> &'static str {
        "urc.certs"
    }
}

struct CertificateMetricsInstruments {
    expiry_seconds: Gauge<i64>,
}

impl CertificateMetricsInstruments {
    fn new() -> Self {
        let instrument_provider = CertificateMetricsInstrumentProvider;
        let meter = instrument_provider.meter();

        Self {
            expiry_seconds: meter
                .i64_gauge(instrument_provider.scope_name("expiry_seconds"))
                .with_unit("seconds")
                .with_description("Seconds until certificate expires (negative if expired)")
                .build(),
        }
    }

    pub fn instance() -> &'static CertificateMetricsInstruments {
        static INSTANCE: OnceLock<CertificateMetricsInstruments> = OnceLock::new();
        INSTANCE.get_or_init(CertificateMetricsInstruments::new)
    }
}

/// Parse a certificate file and extract metadata for metrics reporting.
///
/// When the certificate file contains a chain (multiple certificates), only the leaf certificate
/// (first in the file) is parsed and reported. This is the server's identity certificate and the
/// most relevant for operational monitoring.
pub fn parse_certificate_info(cert_path: &Path) -> Option<CertificateInfo> {
    let certs: Vec<CertificateDer<'static>> = match CertificateDer::pem_file_iter(cert_path) {
        Ok(iter) => iter.filter_map(|r| r.ok()).collect(),
        Err(e) => {
            warn!(
                cert_path = %cert_path.display(),
                error = %e,
                "Failed to read certificate file for metrics"
            );
            return None;
        }
    };

    // The first certificate should be the leaf cert, so that's what we care about.
    let cert_der = certs.first()?;

    let (_, cert) = match X509Certificate::from_der(cert_der.as_ref()) {
        Ok(parsed) => parsed,
        Err(e) => {
            warn!(
                cert_path = %cert_path.display(),
                error = %e,
                "Failed to parse certificate"
            );
            return None;
        }
    };

    let subject = cert.subject().to_string();
    let serial = cert.serial.to_str_radix(16).to_lowercase();
    let expiry_timestamp = cert.validity().not_after.timestamp();

    Some(CertificateInfo {
        cert_path: cert_path.to_path_buf(),
        subject,
        serial,
        expiry_timestamp,
    })
}

fn record_certificate_expiry(expiry_timestamp: i64, labels: &[KeyValue]) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    let seconds_until_expiry = expiry_timestamp - now;

    debug!(seconds_until_expiry, "Recording certificate expiry metric");

    CertificateMetricsInstruments::instance()
        .expiry_seconds
        .record(seconds_until_expiry, labels);
}

/// Start periodic certificate expiry metric reporting.
///
/// Spawns a background task that records the time remaining (in seconds) until the certificate
/// expires. The metric can go negative if the certificate has already expired.
pub fn start_certificate_metrics(cert_info: CertificateInfo, interval: Duration) {
    // Pre-compute labels once since certificate info never changes
    let labels = [
        KeyValue::new("cert_path", cert_info.cert_path.display().to_string()),
        KeyValue::new("subject", cert_info.subject),
        KeyValue::new("serial", cert_info.serial),
        KeyValue::new("expiry_timestamp", cert_info.expiry_timestamp),
    ];
    let expiry_timestamp = cert_info.expiry_timestamp;

    // Record immediately on startup
    record_certificate_expiry(expiry_timestamp, &labels);

    lore_spawn!(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            ticker.tick().await;
            record_certificate_expiry(expiry_timestamp, &labels);
        }
    });
}
