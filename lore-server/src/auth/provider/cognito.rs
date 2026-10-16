// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! Amazon Cognito identity provider: a preset over the generic
//! [`OidcProvider`].
//!
//! Uses the user pool's OIDC discovery document
//! (`https://cognito-idp.<region>.amazonaws.com/<pool>/.well-known/openid-configuration`).
//! Cognito ID tokens carry `aud` = app client id and standard OIDC claims,
//! which the generic core already validates.

use std::sync::Arc;

use super::google::OidcProviderSettings;
use super::google::OidcSettingsError;
use super::google::read_client_secret;
use super::google::scopes;
use super::oidc::OidcBackend;
use super::oidc::OidcConfig;
use super::oidc::OidcProvider;

pub const COGNITO_PROVIDER_NAME: &str = "cognito";

#[lore_macro::test_pub]
fn discovery_url(settings: &OidcProviderSettings) -> Result<String, OidcSettingsError> {
    if let Some(url) = settings.discovery_url.clone() {
        return Ok(url);
    }
    match (settings.region.as_deref(), settings.user_pool_id.as_deref()) {
        (Some(region), Some(pool)) => Ok(format!(
            "https://cognito-idp.{region}.amazonaws.com/{pool}/.well-known/openid-configuration"
        )),
        _ => Err(OidcSettingsError::MissingCognitoPool),
    }
}

/// Build the Cognito provider.
pub fn cognito_provider(
    settings: &OidcProviderSettings,
    callback_url: &str,
    backend: Arc<dyn OidcBackend>,
) -> Result<OidcProvider, OidcSettingsError> {
    Ok(OidcProvider::new(
        OidcConfig {
            idp: COGNITO_PROVIDER_NAME,
            discovery_url: discovery_url(settings)?,
            client_id: settings.client_id.clone(),
            client_secret: read_client_secret(&settings.client_secret_path)?,
            redirect_uri: callback_url.to_string(),
            scopes: scopes(settings),
            extra_auth_params: Vec::new(),
            // Cognito sets `email_verified` on verified pool accounts.
            require_verified_email: true,
            hosted_domain: None,
            trusted_external_audiences: settings.trusted_external_audiences.clone(),
        },
        backend,
    ))
}
