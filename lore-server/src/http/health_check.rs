// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;
use std::sync::atomic::Ordering;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;

use crate::http::server::ServerHealth;

pub async fn handler(State(state): State<Arc<ServerHealth>>) -> impl IntoResponse {
    if state.store_health_check && !state.available.load(Ordering::Relaxed) {
        return StatusCode::SERVICE_UNAVAILABLE;
    }
    StatusCode::OK
}
