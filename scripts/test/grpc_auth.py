# SPDX-FileCopyrightText: 2026 Epic Games, Inc.
# SPDX-License-Identifier: MIT
"""Minimal gRPC client for the server-local UrcAuthApi service.

Like grpc_admin.py, this avoids generated protobuf stubs: the auth-session
messages only contain strings (and the nested UserToken message), so requests
are hand-encoded and responses hand-parsed. The auth service is registered
without an interceptor (it is the login door) and the test server runs gRPC
in plaintext, so an insecure channel works.
"""

import logging
from dataclasses import dataclass

import grpc

logger = logging.getLogger(__name__)

_START_AUTH_SESSION = "/epic_urc.UrcAuthApi/StartAuthSession"
_GET_AUTH_SESSION = "/epic_urc.UrcAuthApi/GetAuthSession"
_EXCHANGE_MULTIRESOURCE = "/epic_urc.UrcAuthApi/ExchangeUserTokenForMultiresourceToken"


def _encode_varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _encode_string_field(field_number: int, value: str) -> bytes:
    data = value.encode("utf-8")
    return _encode_varint(field_number << 3 | 2) + _encode_varint(len(data)) + data


def _read_varint(data: bytes, pos: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7


def _parse_fields(data: bytes) -> dict[int, list[bytes | int]]:
    """Parse a protobuf message into {field_number: [values]}, keeping
    length-delimited fields as bytes and varints as ints."""
    fields: dict[int, list[bytes | int]] = {}
    pos = 0
    while pos < len(data):
        tag, pos = _read_varint(data, pos)
        field_number = tag >> 3
        wire_type = tag & 0x07
        if wire_type == 0:
            value, pos = _read_varint(data, pos)
            fields.setdefault(field_number, []).append(value)
        elif wire_type == 1:
            fields.setdefault(field_number, []).append(data[pos : pos + 8])
            pos += 8
        elif wire_type == 2:
            length, pos = _read_varint(data, pos)
            fields.setdefault(field_number, []).append(data[pos : pos + length])
            pos += length
        elif wire_type == 5:
            fields.setdefault(field_number, []).append(data[pos : pos + 4])
            pos += 4
        else:
            raise ValueError(f"Unsupported protobuf wire type {wire_type}")
    return fields


def _first_string(fields: dict, field_number: int) -> str:
    values = fields.get(field_number)
    if not values:
        return ""
    return values[0].decode("utf-8")


@dataclass
class UserToken:
    user_token: str
    expires_at: int
    user_id: str
    user_name: str


def _parse_user_token(data: bytes) -> UserToken:
    fields = _parse_fields(data)
    expires = fields.get(2, [0])[0]
    return UserToken(
        user_token=_first_string(fields, 1),
        expires_at=expires if isinstance(expires, int) else 0,
        user_id=_first_string(fields, 3),
        user_name=_first_string(fields, 4),
    )


def _call(grpc_target: str, method: str, request: bytes, timeout: float) -> bytes:
    with grpc.insecure_channel(grpc_target) as channel:
        call = channel.unary_unary(
            method,
            request_serializer=lambda payload: payload,
            response_deserializer=lambda response: response,
        )
        return call(request, timeout=timeout)


def start_auth_session(
    grpc_target: str, client_state: str, timeout: float = 10.0
) -> tuple[str, str]:
    """Returns (session_code, login_url)."""
    request = _encode_string_field(1, client_state)
    fields = _parse_fields(_call(grpc_target, _START_AUTH_SESSION, request, timeout))
    return _first_string(fields, 1), _first_string(fields, 2)


def get_auth_session(
    grpc_target: str, session_code: str, client_state: str, timeout: float = 10.0
) -> UserToken | None:
    """Returns the minted token, or None while the login is still pending."""
    request = _encode_string_field(1, session_code) + _encode_string_field(
        2, client_state
    )
    fields = _parse_fields(_call(grpc_target, _GET_AUTH_SESSION, request, timeout))
    token_bytes = fields.get(1)
    if not token_bytes:
        return None
    return _parse_user_token(token_bytes[0])


def exchange_for_resources(
    grpc_target: str, user_token: str, resource_ids: list[str], timeout: float = 10.0
) -> UserToken:
    """Exchange a user token for a multi-resource authorization token."""
    request = b"".join(
        _encode_string_field(1, resource_id) for resource_id in resource_ids
    )
    with grpc.insecure_channel(grpc_target) as channel:
        call = channel.unary_unary(
            _EXCHANGE_MULTIRESOURCE,
            request_serializer=lambda payload: payload,
            response_deserializer=lambda response: response,
        )
        response = call(
            request,
            timeout=timeout,
            metadata=(("authorization", f"Bearer {user_token}"),),
        )
    fields = _parse_fields(response)
    token_bytes = fields.get(1)
    if not token_bytes:
        raise ValueError("exchange response missing token")
    return _parse_user_token(token_bytes[0])
