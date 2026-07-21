// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! `lore access` — per-repository access-control administration.
//!
//! Requires a server running server-local authentication and a stored
//! login (`lore auth login`). Callers must hold the admin role on the
//! target repository, or be server administrators.

use std::future::Future;

use clap::Args;
use clap::Subcommand;
use clap::ValueEnum;
use lore::interface::LoreGlobalArgs;
use lore::runtime;
use lore_base::runtime::LORE_CONTEXT;
use lore_revision::auth::access_admin;
use lore_revision::auth::access_admin::AccessRepositoryRef;

use crate::println;
use crate::styling::CommonStyles;

#[derive(Args)]
pub struct AccessArgs {
    #[command(subcommand)]
    pub command: AccessCommands,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum AccessRoleArg {
    /// Clone and read.
    Read,
    /// Read plus push, branch, and lock.
    Write,
    /// Write plus grant management and repository deletion.
    Admin,
}

impl AccessRoleArg {
    fn as_str(self) -> &'static str {
        match self {
            AccessRoleArg::Read => "read",
            AccessRoleArg::Write => "write",
            AccessRoleArg::Admin => "admin",
        }
    }
}

#[derive(Args)]
struct TargetArgs {
    /// Repository name or id. Omit with --global for server-level grants.
    #[clap(value_name = "repository", required_unless_present = "global")]
    repository: Option<String>,
    /// Manage server-level grants (an admin grant confers server
    /// administrator).
    #[clap(long, conflicts_with = "repository")]
    global: bool,
    /// Server URL; defaults to the current repository's remote.
    #[clap(long = "remote-url", value_name = "remote-url")]
    remote_url: Option<String>,
}

impl TargetArgs {
    fn repository_ref(&self) -> AccessRepositoryRef {
        if self.global {
            AccessRepositoryRef::Global
        } else {
            access_admin::repository_ref(self.repository.as_deref().unwrap_or_default())
        }
    }
}

#[derive(Args)]
pub struct AccessGrantArgs {
    /// User to grant to: canonical id (`<idp>:<subject>`) or email.
    #[clap(value_name = "user")]
    principal: String,
    /// Role to grant.
    #[clap(value_name = "role")]
    role: AccessRoleArg,
    #[command(flatten)]
    target: TargetArgs,
}

#[derive(Args)]
pub struct AccessRevokeArgs {
    /// User whose grant to remove.
    #[clap(value_name = "user")]
    principal: String,
    #[command(flatten)]
    target: TargetArgs,
}

#[derive(Args)]
pub struct AccessListArgs {
    #[command(flatten)]
    target: TargetArgs,
    /// Emit machine-readable JSON.
    #[clap(long)]
    json: bool,
}

#[derive(Subcommand)]
pub enum AccessCommands {
    /// Grant a user a role on a repository
    Grant(AccessGrantArgs),
    /// Remove a user's grant from a repository
    Revoke(AccessRevokeArgs),
    /// List the grants on a repository
    List(AccessListArgs),
}

/// Resolve the remote URL from `--remote` or the enclosing repository's
/// configuration.
fn resolve_remote(globals: &LoreGlobalArgs, remote_url: &Option<String>) -> Option<String> {
    if let Some(remote) = remote_url {
        return Some(remote.clone());
    }
    lore_revision::repository::load_repository_config(globals.repository_path.as_str())
        .ok()
        .and_then(|config| config.remote_url)
}

fn run<T>(
    globals: LoreGlobalArgs,
    operation: impl Future<Output = Result<T, lore_revision::auth::login::LoginError>>,
    on_success: impl FnOnce(T),
) -> u8 {
    let execution = std::sync::Arc::new(lore_revision::interface::ExecutionContext::new_server(
        globals,
        lore_revision::relay::EventDispatcher::no_dispatch(),
        String::default(),
    ));
    match runtime().block_on(LORE_CONTEXT.scope(execution, operation)) {
        Ok(value) => {
            on_success(value);
            0
        }
        Err(error) => {
            crate::eprintln!("{}Error:{} {error}", CommonStyles::FAILURE, anstyle::Reset);
            1
        }
    }
}

pub fn handle_access_commands(cmd: &AccessCommands, globals: LoreGlobalArgs) -> u8 {
    let target = match cmd {
        AccessCommands::Grant(args) => &args.target,
        AccessCommands::Revoke(args) => &args.target,
        AccessCommands::List(args) => &args.target,
    };
    let Some(remote_url) = resolve_remote(&globals, &target.remote_url) else {
        crate::eprintln!(
            "No remote configured; pass --remote or run inside a repository with a remote"
        );
        return 1;
    };
    let repository = target.repository_ref();

    match cmd {
        AccessCommands::Grant(args) => {
            let role = args.role;
            let principal = args.principal.clone();
            run(
                globals,
                access_admin::grant(&remote_url, repository, &args.principal, role.as_str()),
                move |()| {
                    println!(
                        "{}Granted{} {} to {}",
                        CommonStyles::SUCCESS,
                        anstyle::Reset,
                        role.as_str(),
                        principal,
                    );
                },
            )
        }
        AccessCommands::Revoke(args) => {
            let principal = args.principal.clone();
            run(
                globals,
                access_admin::revoke(&remote_url, repository, &args.principal),
                move |existed| {
                    if existed {
                        println!(
                            "{}Revoked{} access for {}",
                            CommonStyles::SUCCESS,
                            anstyle::Reset,
                            principal,
                        );
                    } else {
                        println!("No grant existed for {principal}");
                    }
                },
            )
        }
        AccessCommands::List(args) => {
            let json = args.json;
            run(
                globals,
                access_admin::list(&remote_url, repository),
                move |grants| {
                    if json {
                        let entries: Vec<_> = grants
                            .iter()
                            .map(|(principal, role)| {
                                serde_json::json!({ "principal": principal, "role": role })
                            })
                            .collect();
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&entries).unwrap_or_default()
                        );
                    } else if grants.is_empty() {
                        println!("No grants");
                    } else {
                        for (principal, role) in grants {
                            println!("{role:<8}{principal}");
                        }
                    }
                },
            )
        }
    }
}
