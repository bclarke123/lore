// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use bytes::Bytes;
use lore_revision::lore::RepositoryId;
use lore_server::protocol::storage::authorize::*;
use lore_server::protocol::storage::messages::MessageParseError;
use rand::random;
use zerocopy::IntoBytes;

fn build_start_payload(repo: RepositoryId, corr: &str, token: &[u8]) -> Bytes {
    let mut buf = Vec::new();
    buf.push(ACTION_START);
    buf.extend_from_slice(repo.as_bytes());
    buf.push(corr.len() as u8);
    buf.extend_from_slice(corr.as_bytes());
    buf.extend_from_slice(&(token.len() as u16).to_le_bytes());
    buf.extend_from_slice(token);
    Bytes::from(buf)
}

#[test]
fn parse_start_valid() {
    let repo = random::<RepositoryId>();
    let payload = build_start_payload(repo, "my-corr", b"my-token");
    let result = AuthorizeStart::parse(payload).unwrap();
    assert_eq!(result.repository, repo);
    assert_eq!(result.correlation_id, "my-corr");
    assert_eq!(result.auth_token, b"my-token");
}

#[test]
fn parse_start_empty_correlation() {
    let repo = random::<RepositoryId>();
    let payload = build_start_payload(repo, "", b"tok");
    let result = AuthorizeStart::parse(payload).unwrap();
    assert_eq!(result.correlation_id, "");
}

#[test]
fn parse_start_empty_token() {
    let repo = random::<RepositoryId>();
    let payload = build_start_payload(repo, "corr", b"");
    let result = AuthorizeStart::parse(payload).unwrap();
    assert!(result.auth_token.is_empty());
}

#[test]
fn parse_start_too_short() {
    let payload = Bytes::from(vec![0u8; 19]);
    assert_eq!(
        AuthorizeStart::parse(payload),
        Err(MessageParseError::InvalidFieldLength)
    );
}

#[test]
fn parse_start_bad_action() {
    let mut buf = vec![0u8; 20];
    buf[0] = 99; // bad action
    assert!(AuthorizeStart::parse(Bytes::from(buf)).is_err());
}

#[test]
fn parse_start_invalid_utf8_correlation() {
    let repo = random::<RepositoryId>();
    let mut buf = Vec::new();
    buf.push(ACTION_START);
    buf.extend_from_slice(repo.as_bytes());
    buf.push(2); // corr_len = 2
    buf.extend_from_slice(&[0xFF, 0xFE]); // invalid UTF-8
    buf.extend_from_slice(&0u16.to_le_bytes()); // token_len = 0
    let result = AuthorizeStart::parse(Bytes::from(buf));
    assert!(result.is_err());
}

#[test]
fn parse_start_corr_len_exceeds_payload() {
    let repo = random::<RepositoryId>();
    let mut buf = Vec::new();
    buf.push(ACTION_START);
    buf.extend_from_slice(repo.as_bytes());
    buf.push(200); // corr_len = 200 but only a few bytes follow
    buf.extend_from_slice(b"short");
    let result = AuthorizeStart::parse(Bytes::from(buf));
    assert_eq!(result, Err(MessageParseError::InvalidFieldLength));
}

#[test]
fn parse_start_token_len_exceeds_payload() {
    let repo = random::<RepositoryId>();
    let mut buf = Vec::new();
    buf.push(ACTION_START);
    buf.extend_from_slice(repo.as_bytes());
    buf.push(1); // corr_len = 1
    buf.push(b'c');
    buf.extend_from_slice(&100u16.to_le_bytes()); // token_len = 100 but no bytes follow
    let result = AuthorizeStart::parse(Bytes::from(buf));
    assert_eq!(result, Err(MessageParseError::InvalidFieldLength));
}

#[test]
fn parse_stop_valid() {
    let payload = Bytes::from(vec![ACTION_STOP]);
    let result = AuthorizeStop::parse(42, payload).unwrap();
    assert_eq!(result.session_id, 42);
}

#[test]
fn parse_stop_session_id_zero() {
    let payload = Bytes::from(vec![ACTION_STOP]);
    assert!(AuthorizeStop::parse(0, payload).is_err());
}

#[test]
fn parse_stop_wrong_size() {
    let payload = Bytes::from(vec![ACTION_STOP, 0]);
    assert_eq!(
        AuthorizeStop::parse(1, payload),
        Err(MessageParseError::InvalidFieldLength)
    );
}

#[test]
fn parse_stop_bad_action() {
    let payload = Bytes::from(vec![99]);
    assert!(AuthorizeStop::parse(1, payload).is_err());
}

#[test]
fn parse_authorize_start() {
    let repo = random::<RepositoryId>();
    let payload = build_start_payload(repo, "corr", b"tok");
    match parse_authorize(0, payload).unwrap() {
        AuthorizeAction::Start(s) => {
            assert_eq!(s.repository, repo);
            assert_eq!(s.correlation_id, "corr");
        }
        AuthorizeAction::Stop(_) => panic!("expected Start"),
    }
}

#[test]
fn parse_authorize_stop() {
    let payload = Bytes::from(vec![ACTION_STOP]);
    match parse_authorize(7, payload).unwrap() {
        AuthorizeAction::Stop(s) => assert_eq!(s.session_id, 7),
        AuthorizeAction::Start(_) => panic!("expected Stop"),
    }
}

#[test]
fn parse_authorize_start_nonzero_session_id() {
    let repo = random::<RepositoryId>();
    let payload = build_start_payload(repo, "corr", b"tok");
    assert!(parse_authorize(5, payload).is_err());
}

#[test]
fn parse_authorize_empty_payload() {
    assert_eq!(
        parse_authorize(0, Bytes::new()),
        Err(MessageParseError::InvalidFieldLength)
    );
}
