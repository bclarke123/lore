// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::env;

use opentelemetry::KeyValue;
use opentelemetry_sdk::resource::Resource;
use opentelemetry_sdk::resource::ResourceDetector;

/// Resource detector for Nomad orchestration environment.
///
/// Detects Nomad-specific resource attributes like allocation ID and job ID
/// from environment variables set by Nomad.
pub struct NomadResourceDetector;

impl ResourceDetector for NomadResourceDetector {
    fn detect(&self) -> Resource {
        let alloc_id = env::var("NOMAD_ALLOC_ID").ok();
        let job_id = env::var("NOMAD_JOB_ID").ok();

        Resource::builder_empty()
            .with_attributes(
                [
                    alloc_id.map(|name| KeyValue::new("nomad.alloc.id", name)),
                    job_id.map(|name| KeyValue::new("nomad.job.id", name)),
                ]
                .into_iter()
                .flatten(),
            )
            .build()
    }
}
