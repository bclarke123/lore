// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use anyhow::Error;
use lore_server::authnz::common::create_request_with_authorization;

#[test]
fn can_create_request_with_authorization() -> Result<(), Error> {
    let payload = (4, 20);
    let request = create_request_with_authorization(payload, Some("my-auth".into()))?;
    assert_eq!(request.get_ref(), &payload);

    let auth_metadata = request.metadata().get("authorization").unwrap();
    assert_eq!(auth_metadata.to_str()?, "my-auth");

    Ok(())
}

#[test]
fn can_create_request_without_authorization() -> Result<(), Error> {
    let payload = (4, 20);
    let request = create_request_with_authorization(payload, None)?;
    assert_eq!(request.get_ref(), &payload);

    let auth_metadata = request.metadata().get("authorization").unwrap();
    // looks dodgy to me but this was the original code.
    // to reduce the surface area we will keep this - providing None to `authorization`
    // results in an empty authorization metadata. If you come across this and think
    // it is strange then you are right and it could probably be changed; something
    // we don't have time/risk to investigate right
    assert_eq!(auth_metadata.to_str()?, "");

    Ok(())
}
