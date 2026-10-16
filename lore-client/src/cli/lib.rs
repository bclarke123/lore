// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
#![allow(clippy::needless_return)]
#[cfg(not(feature = "test-util"))]
mod cli;
#[cfg(feature = "test-util")]
pub mod cli;
#[cfg(not(feature = "test-util"))]
mod client_main;
#[cfg(feature = "test-util")]
pub mod client_main;
#[cfg(not(feature = "test-util"))]
mod commands;
#[cfg(feature = "test-util")]
pub mod commands;
mod config;
mod logging;
mod pager;
mod print_macros;
mod progress_bar;
#[cfg(not(feature = "test-util"))]
mod stats_display;
#[cfg(feature = "test-util")]
pub mod stats_display;
mod styling;
mod terminal_size;
#[cfg(not(feature = "test-util"))]
mod util;
#[cfg(feature = "test-util")]
pub mod util;

pub use client_main::client_main;
