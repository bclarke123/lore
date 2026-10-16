// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! Content-type allowlisting and security headers for served content.
//!
//! Stored bytes are attacker-controlled, so serving them with a caller-chosen
//! `Content-Type` (`text/html`, `image/svg+xml`, ...) is a stored-XSS vector on
//! the Lore origin.

use std::collections::HashSet;

use axum::http::HeaderMap;
use axum::http::HeaderValue;
use axum::http::header::CONTENT_SECURITY_POLICY;
use axum::http::header::X_CONTENT_TYPE_OPTIONS;
use thiserror::Error;

/// Served when the caller's `Content-Type` is not allowlisted.
const DEFAULT_SERVED_CONTENT_TYPE: &str = "application/octet-stream";

/// Built-in allowlist. Config adjusts it through [`ContentTypePolicy`] rather than
/// restating it.
pub const DEFAULT_ALLOWED_CONTENT_TYPES: &[&str] = &[
    "application/octet-stream",
    // S3 sets this on objects uploaded without a Content-Type, so callers that
    // forward S3 metadata send it here. It is not a registered type but means the
    // same as application/octet-stream. Kept as-is, not rewritten, so callers read
    // back what they sent. Browsers do not render it, and every response sets
    // nosniff.
    "binary/octet-stream",
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    "application/pdf",
    "text/plain",
];

/// Types config may never allow: a browser executes these as a document, making
/// redeemed content a stored-XSS vector on the Lore origin.
#[lore_macro::test_pub]
const NEVER_ALLOWED_CONTENT_TYPES: &[&str] = &[
    "text/html",
    "application/xhtml+xml",
    "image/svg+xml",
    "text/xml",
    "application/xml",
    "application/xslt+xml",
    "text/javascript",
    "application/javascript",
    "application/ecmascript",
];

/// Configured adjustments to [`DEFAULT_ALLOWED_CONTENT_TYPES`].
#[derive(Clone, Debug, Default)]
pub struct ContentTypePolicy {
    pub extra: Vec<String>,
    /// Applied after `extra`, so deny wins.
    pub denied: Vec<String>,
}

/// Which list a rejected entry came from. The caller maps this to a config field
/// name, keeping this module independent of the config schema.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyField {
    Extra,
    Denied,
}

#[derive(Debug, Error)]
pub enum ContentTypePolicyError {
    #[error("entry {entry:?} is empty")]
    Empty { field: PolicyField, entry: String },
    #[error(
        "entry {entry:?} must be a single media type with no parameters; list each type on its own"
    )]
    HasParameterOrList { field: PolicyField, entry: String },
    #[error("entry {entry:?} must not contain a wildcard; list each type explicitly")]
    Wildcard { field: PolicyField, entry: String },
    #[error("entry {entry:?} is not a type/subtype media type")]
    NotTypeSubtype { field: PolicyField, entry: String },
    #[error("entry {entry:?} is not permitted: a browser can execute it as a document")]
    NeverAllowed { field: PolicyField, entry: String },
}

impl ContentTypePolicyError {
    /// Returns the list the rejected entry came from.
    pub fn field(&self) -> PolicyField {
        match self {
            Self::Empty { field, .. }
            | Self::HasParameterOrList { field, .. }
            | Self::Wildcard { field, .. }
            | Self::NotTypeSubtype { field, .. }
            | Self::NeverAllowed { field, .. } => *field,
        }
    }
}

/// Deny-by-default allowlist of `Content-Type` values safe to serve verbatim.
///
/// Configurable in code via [`ContentTypeAllowlist::new`]; [`Default`] is the
/// safe built-in set.
#[derive(Clone, Debug)]
pub struct ContentTypeAllowlist {
    allowed: HashSet<String>,
}

impl ContentTypeAllowlist {
    pub fn new(types: impl IntoIterator<Item = String>) -> Self {
        Self {
            allowed: types.into_iter().map(|t| normalize(&t)).collect(),
        }
    }

    pub fn try_from_policy(policy: &ContentTypePolicy) -> Result<Self, ContentTypePolicyError> {
        for entry in &policy.extra {
            validate_shape(PolicyField::Extra, entry)?;

            if is_never_allowed(entry) {
                return Err(ContentTypePolicyError::NeverAllowed {
                    field: PolicyField::Extra,
                    entry: entry.clone(),
                });
            }
        }
        // A floor type here is a redundant no-op, not an error: it is already absent.
        for entry in &policy.denied {
            validate_shape(PolicyField::Denied, entry)?;
        }

        let denied: HashSet<String> = policy.denied.iter().map(|d| normalize(d)).collect();

        Ok(Self::new(
            DEFAULT_ALLOWED_CONTENT_TYPES
                .iter()
                .map(|content_type| (*content_type).to_string())
                .chain(policy.extra.iter().cloned())
                .filter(|content_type| !denied.contains(&normalize(content_type))),
        ))
    }

    /// The resolved set, sorted. Logged at startup.
    pub fn allowed_types(&self) -> Vec<String> {
        let mut types: Vec<String> = self.allowed.iter().cloned().collect();
        types.sort_unstable();
        types
    }

    /// Matching is case- and parameter-insensitive: `text/plain; charset=utf-8`
    /// matches an allowlisted `text/plain`.
    pub fn is_allowed(&self, content_type: &str) -> bool {
        self.allowed.contains(&normalize(content_type))
    }

    /// The `Content-Type` to serve: the caller's value when allowlisted and a
    /// valid header, else `application/octet-stream`.
    pub fn coerce(&self, content_type: Option<String>) -> HeaderValue {
        match content_type {
            Some(ct) if self.is_allowed(&ct) => HeaderValue::try_from(ct)
                .unwrap_or_else(|_| HeaderValue::from_static(DEFAULT_SERVED_CONTENT_TYPE)),
            Some(ct) => {
                tracing::warn!(
                    requested = %ct,
                    served = DEFAULT_SERVED_CONTENT_TYPE,
                    "coerced disallowed content-type"
                );
                HeaderValue::from_static(DEFAULT_SERVED_CONTENT_TYPE)
            }
            None => HeaderValue::from_static(DEFAULT_SERVED_CONTENT_TYPE),
        }
    }
}

impl Default for ContentTypeAllowlist {
    fn default() -> Self {
        Self::new(
            DEFAULT_ALLOWED_CONTENT_TYPES
                .iter()
                .map(|content_type| (*content_type).to_string()),
        )
    }
}

fn is_never_allowed(content_type: &str) -> bool {
    NEVER_ALLOWED_CONTENT_TYPES.contains(&normalize(content_type).as_str())
}

/// Rejects anything [`normalize`] would not reduce to a canonical `type/subtype`.
fn validate_shape(field: PolicyField, entry: &str) -> Result<(), ContentTypePolicyError> {
    let trimmed = entry.trim();

    if trimmed.is_empty() {
        return Err(ContentTypePolicyError::Empty {
            field,
            entry: entry.to_string(),
        });
    }
    if trimmed.contains(';') || trimmed.contains(',') {
        return Err(ContentTypePolicyError::HasParameterOrList {
            field,
            entry: entry.to_string(),
        });
    }
    if trimmed.contains('*') {
        return Err(ContentTypePolicyError::Wildcard {
            field,
            entry: entry.to_string(),
        });
    }

    let Some((media_type, subtype)) = trimmed.split_once('/') else {
        return Err(ContentTypePolicyError::NotTypeSubtype {
            field,
            entry: entry.to_string(),
        });
    };
    if !is_token(media_type) || !is_token(subtype) {
        return Err(ContentTypePolicyError::NotTypeSubtype {
            field,
            entry: entry.to_string(),
        });
    }

    Ok(())
}

/// RFC 9110 `token`, the character set a media type and subtype are drawn from.
/// Excludes whitespace, control characters, and everything non-ASCII.
fn is_token(part: &str) -> bool {
    !part.is_empty() && part.bytes().all(is_tchar)
}

fn is_tchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

#[lore_macro::test_pub]
fn normalize(content_type: &str) -> String {
    content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
}

/// `nosniff` stops MIME sniffing; the sandboxed CSP blocks script execution
/// even if a bad type slips through.
pub fn apply_security_headers(headers: &mut HeaderMap) {
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(
        CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; sandbox"),
    );
}
