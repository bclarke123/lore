// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::fmt;

#[derive(Copy, Clone, Debug)]
pub enum StorageProtocol {
    StorageV0,
    StorageV1,
    StorageV4,
    Replication,
}

impl StorageProtocol {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StorageV0 => "storage.v0",
            Self::StorageV1 => "storage.v1",
            Self::StorageV4 => "storage.v4",
            Self::Replication => "replication",
        }
    }
}

impl fmt::Display for StorageProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Copy, Clone, Debug)]
pub enum Transport {
    Grpc,
    Quic,
}

impl Transport {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Grpc => "grpc",
            Self::Quic => "quic",
        }
    }
}

impl fmt::Display for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
