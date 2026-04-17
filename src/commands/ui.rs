//! Local browser-console bridge.
//!
//! The browser surface must remain downstream of the Rust core. This command
//! exposes a localhost-only web server that serves the Astro console shell and
//! a narrow JSON bridge over existing machine-readable Wolfence surfaces.

use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::app::{AppError, AppResult};
use crate::cli::UiCommand;
use crate::core::git;

use super::protected::{self, PushEvaluation, PushEvaluationProgress};

const DEFAULT_UI_HOST: &str = "127.0.0.1";
const DEFAULT_UI_PORT: u16 = 4318;
const DEFAULT_UI_AUTO_REFRESH_SECS: u64 = 300;

#[derive(Debug, Clone)]
pub(super) struct UiSurfaceCheck {
    pub label: &'static str,
    pub ok: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct UiWorkspaceFile {
    repositories: Vec<String>,
    selected_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct UiWorkspaceCacheFile {
    #[serde(default)]
    entries: std::collections::BTreeMap<String, UiWorkspaceCacheEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct UiComparisonSetsFile {
    #[serde(default)]
    sets: std::collections::BTreeMap<String, Vec<String>>,
    selected_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(super) struct UiVerificationStatusFile {
    #[serde(default)]
    pub surface: Option<UiVerificationRecord>,
    #[serde(default)]
    pub browser: Option<UiVerificationRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct UiVerificationRecord {
    pub ok: bool,
    pub command: String,
    pub detail: String,
    pub checked_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UiWorkspaceCacheEntry {
    branch: Option<String>,
    upstream: Option<String>,
    tone: String,
    verdict_label: String,
    summary: String,
    doctor_summary: String,
    last_refreshed_unix: u64,
}

#[derive(Debug, Clone)]
struct UiWorkspaceState {
    file_path: PathBuf,
    repositories: Vec<PathBuf>,
    selected_path: PathBuf,
}

#[derive(Debug, Deserialize)]
struct WorkspaceMutationRequest {
    path: String,
}

#[derive(Debug, Deserialize)]
struct WorkspaceRefreshRequest {
    path: String,
}

#[derive(Debug, Deserialize)]
struct ComparisonSetSaveRequest {
    name: String,
    #[serde(default)]
    paths: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ComparisonSetNameRequest {
    name: String,
}

#[derive(Debug, Deserialize, Default)]
struct PushActionRequest {
    #[serde(default)]
    dry_run: bool,
}

pub fn run(command: UiCommand) -> AppResult<ExitCode> {
    match command {
        UiCommand::Serve => serve(),
        UiCommand::Verify => verify(),
        UiCommand::VerifyBrowser => verify_browser(),
        UiCommand::Help => {
            print_help();
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn verify() -> AppResult<ExitCode> {
    let repo_root = git::discover_repo_root()?;
    let selected_repo = load_workspace_state(&repo_root)?.selected_path;
    let result = (|| -> AppResult<(bool, String)> {
        let mut failed = false;
        let mut failed_labels = Vec::new();
        let mut total_checks = 0usize;

        println!("Wolfence Web Console Verify");
        println!("  repo root: {}", repo_root.display());
        println!("  selected repo: {}", selected_repo.display());

        for check in verify_local_console_surface(&repo_root)? {
            total_checks += 1;
            if !verify_check(check.label, check.ok, check.detail) {
                failed = true;
                failed_labels.push(check.label.to_string());
            }
        }

        for check in verify_live_bridge_surface(&repo_root)? {
            total_checks += 1;
            if !verify_check(check.label, check.ok, check.detail) {
                failed = true;
                failed_labels.push(check.label.to_string());
            }
        }

        let doctor = run_wolf_json(&selected_repo, &["doctor", "--json"]);
        total_checks += 1;
        if !verify_check(
            "doctor surface",
            !value_has_error(&doctor),
            json_status_detail(&doctor),
        ) {
            failed = true;
            failed_labels.push("doctor surface".to_string());
        }

        let push_preview = run_wolf_json(&selected_repo, &["scan", "push", "--json"]);
        total_checks += 1;
        if !verify_check(
            "push preview surface",
            !value_has_error(&push_preview),
            json_status_detail(&push_preview),
        ) {
            failed = true;
            failed_labels.push("push preview surface".to_string());
        }

        let audit = run_wolf_json(&selected_repo, &["audit", "list", "--json"]);
        total_checks += 1;
        if !verify_check(
            "audit surface",
            !value_has_error(&audit),
            json_status_detail(&audit),
        ) {
            failed = true;
            failed_labels.push("audit surface".to_string());
        }

        let detail = if failed {
            format!(
                "{} of {} browser-console verification checks failed: {}.",
                failed_labels.len(),
                total_checks,
                failed_labels.join(", ")
            )
        } else {
            format!(
                "all {} browser-console verification checks passed.",
                total_checks
            )
        };

        Ok((failed, detail))
    })();

    match result {
        Ok((failed, detail)) => {
            save_verification_record(
                &repo_root,
                VerificationTarget::Surface,
                !failed,
                "wolf ui verify".to_string(),
                detail,
            )?;
            if failed {
                println!("  result: verification failed");
                Ok(ExitCode::FAILURE)
            } else {
                println!("  result: verification passed");
                Ok(ExitCode::SUCCESS)
            }
        }
        Err(error) => {
            let _ = save_verification_record(
                &repo_root,
                VerificationTarget::Surface,
                false,
                "wolf ui verify".to_string(),
                format!("verification aborted: {error}"),
            );
            Err(error)
        }
    }
}

fn serve() -> AppResult<ExitCode> {
    let repo_root = git::discover_repo_root()?;
    let host = std::env::var("WOLFENCE_UI_HOST").unwrap_or_else(|_| DEFAULT_UI_HOST.to_string());
    let port = std::env::var("WOLFENCE_UI_PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(DEFAULT_UI_PORT);
    let auto_refresh_secs = std::env::var("WOLFENCE_UI_AUTO_REFRESH_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(DEFAULT_UI_AUTO_REFRESH_SECS);
    let static_root = repo_root.join("apps/web-console/dist");

    let listener = TcpListener::bind((host.as_str(), port))?;
    spawn_workspace_refresh_scheduler(repo_root.clone(), auto_refresh_secs);

    println!("Wolfence Web Console");
    println!("  repo root: {}", repo_root.display());
    println!("  listening on http://{host}:{port}");
    println!("  static bundle: {}", static_root.display());
    println!("  api: /api/health, /api/console");
    println!("  workspace auto-refresh: every {auto_refresh_secs}s");
    if !static_root.exists() {
        println!("  note: build the Astro app with `cd apps/web-console && npm install && npm run build`");
    }
    println!("  stop: Ctrl-C");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let repo_root = repo_root.clone();
                let static_root = static_root.clone();
                thread::spawn(move || {
                    if let Err(error) = handle_connection(stream, &repo_root, &static_root) {
                        eprintln!("wolf ui: {error}");
                    }
                });
            }
            Err(error) => eprintln!("wolf ui: failed to accept connection: {error}"),
        }
    }

    Ok(ExitCode::SUCCESS)
}

fn verify_browser() -> AppResult<ExitCode> {
    let repo_root = git::discover_repo_root()?;
    let web_console_root = repo_root.join("apps/web-console");

    if !web_console_root.exists() {
        return Err(AppError::Config(format!(
            "browser verifier expected a web console at {}, but that directory does not exist",
            web_console_root.display()
        )));
    }

    println!("Wolfence Web Console Browser Verify");
    println!("  repo root: {}", repo_root.display());
    println!("  web console: {}", web_console_root.display());

    let status = Command::new("npm")
        .args(["run", "verify:browser"])
        .current_dir(&web_console_root)
        .status()
        .map_err(|error| {
            AppError::Config(format!(
                "failed to execute `npm run verify:browser` in {}: {error}",
                web_console_root.display()
            ))
        });

    match status {
        Ok(status) => {
            let ok = status.success();
            let detail = if ok {
                "browser-driven localhost verification passed.".to_string()
            } else {
                format!(
                    "browser-driven localhost verification exited with status {:?}.",
                    status.code()
                )
            };
            save_verification_record(
                &repo_root,
                VerificationTarget::Browser,
                ok,
                "wolf ui verify-browser".to_string(),
                detail,
            )?;
            Ok(exit_code_from_status(status))
        }
        Err(error) => {
            let _ = save_verification_record(
                &repo_root,
                VerificationTarget::Browser,
                false,
                "wolf ui verify-browser".to_string(),
                format!("browser verification aborted: {error}"),
            );
            Err(error)
        }
    }
}

fn handle_connection(
    mut stream: TcpStream,
    repo_root: &Path,
    static_root: &Path,
) -> AppResult<()> {
    let mut buffer = [0_u8; 16 * 1024];
    let bytes_read = stream.read(&mut buffer)?;
    if bytes_read == 0 {
        return Ok(());
    }

    let request = String::from_utf8_lossy(&buffer[..bytes_read]);
    let first_line = request
        .lines()
        .next()
        .ok_or_else(|| AppError::Config("received an empty HTTP request".to_string()))?;
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let raw_target = parts.next().unwrap_or("/");
    let target = raw_target.split('?').next().unwrap_or("/");

    if handle_repository_route(method, target, &request, repo_root, &mut stream)? {
        return Ok(());
    }

    match target {
        "/api/health" if method == "GET" => write_json(
            &mut stream,
            &json!({
                "status": "ok",
                "bridge": "wolf-ui",
                "repo_root": repo_root.display().to_string()
            }),
        ),
        "/api/scan/push/stream" if method == "GET" => stream_push_scan(&mut stream, repo_root),
        "/api/console" if method == "GET" => {
            let payload = build_console_payload(repo_root, static_root);
            write_json(&mut stream, &payload)
        }
        "/api/workspaces" if method == "GET" => {
            write_json(&mut stream, &workspace_state_payload(repo_root))
        }
        "/api/workspaces" if method == "POST" => {
            let request = parse_json_body::<WorkspaceMutationRequest>(&request)?;
            add_workspace(repo_root, &request.path)?;
            write_json(&mut stream, &workspace_state_payload(repo_root))
        }
        "/api/workspaces/select" if method == "POST" => {
            let request = parse_json_body::<WorkspaceMutationRequest>(&request)?;
            select_workspace(repo_root, &request.path)?;
            write_json(&mut stream, &workspace_state_payload(repo_root))
        }
        "/api/workspaces/remove" if method == "POST" => {
            let request = parse_json_body::<WorkspaceMutationRequest>(&request)?;
            remove_workspace(repo_root, &request.path)?;
            write_json(&mut stream, &workspace_state_payload(repo_root))
        }
        "/api/workspaces/refresh" if method == "POST" => {
            let request = parse_json_body::<WorkspaceRefreshRequest>(&request)?;
            refresh_workspace(repo_root, &request.path)?;
            write_json(&mut stream, &workspace_state_payload(repo_root))
        }
        "/api/workspaces/refresh-all" if method == "POST" => {
            refresh_all_workspaces(repo_root)?;
            write_json(&mut stream, &workspace_state_payload(repo_root))
        }
        "/api/comparison-sets" if method == "GET" => {
            write_json(&mut stream, &comparison_sets_payload(repo_root))
        }
        "/api/comparison-sets" if method == "POST" => {
            let request = parse_json_body::<ComparisonSetSaveRequest>(&request)?;
            save_comparison_set(repo_root, &request.name, &request.paths)?;
            write_json(&mut stream, &comparison_sets_payload(repo_root))
        }
        "/api/comparison-sets/select" if method == "POST" => {
            let request = parse_json_body::<ComparisonSetNameRequest>(&request)?;
            select_comparison_set(repo_root, &request.name)?;
            write_json(&mut stream, &comparison_sets_payload(repo_root))
        }
        "/api/comparison-sets/clear" if method == "POST" => {
            clear_comparison_set_selection(repo_root)?;
            write_json(&mut stream, &comparison_sets_payload(repo_root))
        }
        "/api/comparison-sets/remove" if method == "POST" => {
            let request = parse_json_body::<ComparisonSetNameRequest>(&request)?;
            remove_comparison_set(repo_root, &request.name)?;
            write_json(&mut stream, &comparison_sets_payload(repo_root))
        }
        "/api/verify/surface" if method == "POST" => {
            write_json(
                &mut stream,
                &run_ui_verification_command(repo_root, &["ui", "verify"]),
            )?;
            Ok(())
        }
        "/api/verify/browser" if method == "POST" => {
            write_json(
                &mut stream,
                &run_ui_verification_command(repo_root, &["ui", "verify-browser"]),
            )?;
            Ok(())
        }
        _ if method == "GET" => serve_static(&mut stream, target, repo_root, static_root),
        _ => write_response(
            &mut stream,
            405,
            "text/plain; charset=utf-8",
            b"Method Not Allowed",
        ),
    }
}

fn handle_repository_route(
    method: &str,
    target: &str,
    request: &str,
    repo_root: &Path,
    stream: &mut TcpStream,
) -> AppResult<bool> {
    let Some(remainder) = target.strip_prefix("/api/repositories/") else {
        return Ok(false);
    };

    let mut parts = remainder.splitn(2, '/');
    let identifier = parts.next().unwrap_or_default();
    let resource = parts.next().unwrap_or_default();
    if identifier.is_empty() || resource.is_empty() {
        return Ok(false);
    }

    let repository = resolve_repository_identifier(repo_root, identifier)?;
    match (method, resource) {
        ("GET", "doctor") => {
            write_json(stream, &run_wolf_json(&repository, &["doctor", "--json"]))?;
            Ok(true)
        }
        ("GET", "push-preview") => {
            write_json(stream, &run_wolf_json(&repository, &["scan", "push", "--json"]))?;
            Ok(true)
        }
        ("GET", "audit") => {
            write_json(stream, &run_wolf_json(&repository, &["audit", "list", "--json"]))?;
            Ok(true)
        }
        ("POST", "scan") => {
            let payload = run_wolf_json(&repository, &["scan", "push", "--json"]);
            let _ = refresh_workspace_cache_entry(repo_root, &repository);
            write_json(stream, &payload)?;
            Ok(true)
        }
        ("POST", "push") => {
            let push_request = parse_json_body::<PushActionRequest>(request)?;
            let payload = run_repo_push(repo_root, &repository, push_request.dry_run);
            write_json(stream, &payload)?;
            Ok(true)
        }
        ("POST", "verify/surface") => {
            write_json(
                stream,
                &run_ui_verification_command(&repository, &["ui", "verify"]),
            )?;
            Ok(true)
        }
        ("POST", "verify/browser") => {
            write_json(
                stream,
                &run_ui_verification_command(&repository, &["ui", "verify-browser"]),
            )?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

fn stream_push_scan(stream: &mut TcpStream, repo_root: &Path) -> AppResult<()> {
    write_sse_headers(stream)?;
    write_sse_event(
        stream,
        "bridge",
        &json!({
            "status": "connected",
            "action": "push-preview"
        }),
    )?;

    let mut stream_error: Option<AppError> = None;
    let selected_repo = load_workspace_state(repo_root)?.selected_path;
    let evaluation =
        protected::evaluate_push_action_for_repo_with_progress(&selected_repo, |progress| {
            if stream_error.is_some() {
                return;
            }

            if let Err(error) = write_sse_event(stream, "progress", &push_progress_payload(&progress))
            {
                stream_error = Some(error);
            }
        })?;
    if let Some(error) = stream_error {
        return Err(error);
    }

    let _ = refresh_workspace_cache_entry(repo_root, &selected_repo);
    write_sse_event(stream, "done", &push_evaluation_payload(&evaluation, &selected_repo))?;
    Ok(())
}

fn build_console_payload(repo_root: &Path, static_root: &Path) -> Value {
    let workspace_state = match load_workspace_state(repo_root) {
        Ok(state) => state,
        Err(error) => {
            return json!({
                "error": {
                    "message": error.to_string()
                }
            });
        }
    };
    let selected_repo = workspace_state.selected_path.clone();
    let repo_name = selected_repo
        .file_name()
        .map(|value| value.to_string_lossy().to_string())
        .unwrap_or_else(|| selected_repo.display().to_string());
    let selected_workspace_entry =
        load_cached_workspace_entry(repo_root, &selected_repo).unwrap_or_else(uncached_workspace_entry);
    let verification_status = workspace_verification_value(repo_root);

    json!({
        "repository": {
            "id": selected_repo.display().to_string(),
            "name": repo_name,
            "path": selected_repo.display().to_string(),
            "branch": selected_workspace_entry.branch,
            "upstream": selected_workspace_entry.upstream,
        },
        "workspaces": workspace_entries(
            repo_root,
            &workspace_state,
            Some((&selected_repo, &selected_workspace_entry))
        ),
        "bridge": {
            "host": std::env::var("WOLFENCE_UI_HOST").unwrap_or_else(|_| DEFAULT_UI_HOST.to_string()),
            "port": std::env::var("WOLFENCE_UI_PORT").ok().and_then(|value| value.parse::<u16>().ok()).unwrap_or(DEFAULT_UI_PORT),
            "auto_refresh_seconds": bridge_auto_refresh_seconds(),
            "static_ready": static_root.exists(),
            "static_root": static_root.display().to_string(),
            "verification": verification_status
        },
        "comparison_sets": comparison_sets_payload(repo_root),
        "config": load_repo_configuration(&selected_repo),
        "receipt_policy": load_receipt_policy(&selected_repo)
    })
}

fn run_wolf_json(repo_root: &Path, arguments: &[&str]) -> Value {
    let current_exe = match std::env::current_exe() {
        Ok(path) => path,
        Err(error) => {
            return command_error_value(arguments, &format!("failed to locate current executable: {error}"));
        }
    };

    let output = match Command::new(&current_exe)
        .args(arguments)
        .current_dir(repo_root)
        .output()
    {
        Ok(output) => output,
        Err(error) => {
            return command_error_value(
                arguments,
                &format!("failed to execute {}: {error}", current_exe.display()),
            );
        }
    };

    if output.stdout.is_empty() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return command_error_value(
            arguments,
            &if stderr.is_empty() {
                "command returned no JSON output".to_string()
            } else {
                stderr
            },
        );
    }

    match serde_json::from_slice::<Value>(&output.stdout) {
        Ok(value) => value,
        Err(error) => command_error_value(
            arguments,
            &format!("failed to decode JSON response: {error}"),
        ),
    }
}

fn run_ui_verification_command(repo_root: &Path, arguments: &[&str]) -> Value {
    if !repository_supports_browser_console(repo_root) {
        let detail =
            "this repository does not contain a Wolfence browser console surface.".to_string();
        return json!({
            "status": "unsupported",
            "ok": false,
            "command": arguments.join(" "),
            "detail": detail,
            "error": {
                "message": "repository does not contain apps/web-console"
            }
        });
    }

    let current_exe = match std::env::current_exe() {
        Ok(path) => path,
        Err(error) => {
            return json!({
                "status": "error",
                "command": arguments.join(" "),
                "error": {
                    "message": format!("failed to locate current executable: {error}")
                }
            });
        }
    };

    let output = match Command::new(&current_exe)
        .args(arguments)
        .current_dir(repo_root)
        .output()
    {
        Ok(output) => output,
        Err(error) => {
            return json!({
                "status": "error",
                "command": arguments.join(" "),
                "error": {
                    "message": format!(
                        "failed to execute {}: {error}",
                        current_exe.display()
                    )
                }
            });
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let detail = stdout
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .map(|line| line.trim().to_string())
        .or_else(|| {
            stderr
                .lines()
                .rev()
                .find(|line| !line.trim().is_empty())
                .map(|line| line.trim().to_string())
        })
        .unwrap_or_else(|| "verification command completed without output.".to_string());

    json!({
        "status": if output.status.success() { "ok" } else { "error" },
        "ok": output.status.success(),
        "command": arguments.join(" "),
        "detail": detail,
        "exit_code": output.status.code(),
        "stdout": stdout,
        "stderr": stderr
    })
}

fn command_error_value(arguments: &[&str], message: &str) -> Value {
    json!({
        "status": "error",
        "command": arguments.join(" "),
        "error": {
            "message": message
        }
    })
}

fn verify_check(label: &str, ok: bool, detail: String) -> bool {
    let marker = if ok { "ok" } else { "fail" };
    println!("  {label}: {marker}");
    println!("    {detail}");
    ok
}

pub(super) fn verify_local_console_surface(repo_root: &Path) -> AppResult<Vec<UiSurfaceCheck>> {
    let static_root = repo_root.join("apps/web-console/dist");
    let mut checks = Vec::new();

    checks.push(UiSurfaceCheck {
        label: "static bundle",
        ok: static_root.exists(),
        detail: if static_root.exists() {
            format!("found {}", static_root.display())
        } else {
            format!("missing {}", static_root.display())
        },
    });

    let index_path = static_root.join("index.html");
    checks.push(UiSurfaceCheck {
        label: "index route",
        ok: index_path.exists(),
        detail: if index_path.exists() {
            index_path.display().to_string()
        } else {
            format!("missing {}", index_path.display())
        },
    });

    let history_path = static_root.join("history/index.html");
    checks.push(UiSurfaceCheck {
        label: "history route",
        ok: history_path.exists(),
        detail: if history_path.exists() {
            history_path.display().to_string()
        } else {
            format!("missing {}", history_path.display())
        },
    });

    let console_payload = build_console_payload(repo_root, &static_root);
    checks.push(UiSurfaceCheck {
        label: "console payload",
        ok: value_has_required_fields(
            &console_payload,
            &["repository", "workspaces", "bridge", "config", "receipt_policy"],
        ) && !value_has_error(&console_payload),
        detail: "build_console_payload returned the expected top-level shape".to_string(),
    });

    let workspace_payload = workspace_state_payload(repo_root);
    checks.push(UiSurfaceCheck {
        label: "workspace state",
        ok: value_has_required_fields(&workspace_payload, &["selected_path", "workspaces"])
            && !value_has_error(&workspace_payload),
        detail: "workspace rail state loaded".to_string(),
    });

    let comparison_sets = comparison_sets_payload(repo_root);
    checks.push(UiSurfaceCheck {
        label: "comparison sets",
        ok: value_has_required_fields(&comparison_sets, &["selected_name", "sets"]),
        detail: "saved comparison metadata loaded".to_string(),
    });

    Ok(checks)
}

fn verify_live_bridge_surface(repo_root: &Path) -> AppResult<Vec<UiSurfaceCheck>> {
    let static_root = repo_root.join("apps/web-console/dist");
    let (base_url, stop, handle) = spawn_verify_server(repo_root.to_path_buf(), static_root)?;
    let result = verify_live_bridge_surface_inner(&base_url);
    stop.store(true, Ordering::Relaxed);
    let _ = handle.join();
    result
}

fn verify_live_bridge_surface_inner(base_url: &str) -> AppResult<Vec<UiSurfaceCheck>> {
    let mut checks = Vec::new();

    let health = fetch_http_response(base_url, "/api/health")?;
    checks.push(UiSurfaceCheck {
        label: "live health route",
        ok: health.status_code == 200
            && health.content_type.starts_with("application/json")
            && health.body.contains("\"status\": \"ok\""),
        detail: format!(
            "{} {}",
            health.status_code,
            if health.content_type.is_empty() {
                "<no content type>"
            } else {
                health.content_type.as_str()
            }
        ),
    });

    let console = fetch_http_response(base_url, "/api/console")?;
    checks.push(UiSurfaceCheck {
        label: "live console route",
        ok: console.status_code == 200
            && console.content_type.starts_with("application/json")
            && console.body.contains("\"repository\"")
            && console.body.contains("\"workspaces\""),
        detail: format!(
            "{} {}",
            console.status_code,
            if console.content_type.is_empty() {
                "<no content type>"
            } else {
                console.content_type.as_str()
            }
        ),
    });

    let index = fetch_http_response(base_url, "/")?;
    checks.push(UiSurfaceCheck {
        label: "live index route",
        ok: index.status_code == 200
            && index.content_type.starts_with("text/html")
            && index.body.contains("Wolfence Web Console"),
        detail: format!(
            "{} {}",
            index.status_code,
            if index.content_type.is_empty() {
                "<no content type>"
            } else {
                index.content_type.as_str()
            }
        ),
    });

    let history = fetch_http_response(base_url, "/history")?;
    checks.push(UiSurfaceCheck {
        label: "live history route",
        ok: history.status_code == 200
            && history.content_type.starts_with("text/html")
            && history.body.contains("Wolfence Repo History"),
        detail: format!(
            "{} {}",
            history.status_code,
            if history.content_type.is_empty() {
                "<no content type>"
            } else {
                history.content_type.as_str()
            }
        ),
    });

    let asset_route = extract_first_static_asset(&index.body);
    let asset_check = if let Some(asset_route) = asset_route {
        let asset = fetch_http_response(base_url, &asset_route)?;
        UiSurfaceCheck {
            label: "live static asset",
            ok: asset.status_code == 200 && !asset.body.is_empty(),
            detail: format!(
                "{} {} ({})",
                asset.status_code,
                if asset.content_type.is_empty() {
                    "<no content type>"
                } else {
                    asset.content_type.as_str()
                },
                asset_route
            ),
        }
    } else {
        UiSurfaceCheck {
            label: "live static asset",
            ok: false,
            detail: "failed to locate a built asset reference in the index route".to_string(),
        }
    };
    checks.push(asset_check);

    Ok(checks)
}

fn spawn_verify_server(
    repo_root: PathBuf,
    static_root: PathBuf,
) -> AppResult<(String, Arc<AtomicBool>, thread::JoinHandle<()>)> {
    let listener = TcpListener::bind((DEFAULT_UI_HOST, 0))?;
    listener.set_nonblocking(true)?;
    let address = listener.local_addr()?;
    let stop = Arc::new(AtomicBool::new(false));
    let stop_flag = Arc::clone(&stop);

    let handle = thread::spawn(move || {
        while !stop_flag.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let _ = handle_connection(stream, &repo_root, &static_root);
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(25));
                }
                Err(_) => break,
            }
        }
    });

    Ok((format!("http://{}:{}", address.ip(), address.port()), stop, handle))
}

#[derive(Debug)]
struct HttpResponse {
    status_code: u16,
    content_type: String,
    body: String,
}

fn fetch_http_response(base_url: &str, path: &str) -> AppResult<HttpResponse> {
    let address = base_url
        .strip_prefix("http://")
        .ok_or_else(|| AppError::Config(format!("unsupported verification URL: {base_url}")))?;
    let mut stream = TcpStream::connect(address)?;
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        path, address
    );
    stream.write_all(request.as_bytes())?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    parse_http_response(&response)
}

fn parse_http_response(response: &str) -> AppResult<HttpResponse> {
    let (header_text, body) = response.split_once("\r\n\r\n").ok_or_else(|| {
        AppError::Config("failed to split HTTP response into headers and body".to_string())
    })?;

    let mut lines = header_text.lines();
    let status_line = lines.next().ok_or_else(|| {
        AppError::Config("failed to read HTTP response status line".to_string())
    })?;
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| AppError::Config(format!("invalid HTTP status line: {status_line}")))?;

    let content_type = lines
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("content-type") {
                Some(value.trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_default();

    Ok(HttpResponse {
        status_code,
        content_type,
        body: body.to_string(),
    })
}

fn extract_first_static_asset(html: &str) -> Option<String> {
    ["/_astro/", "/favicon", "/assets/"]
        .iter()
        .find_map(|needle| extract_quoted_path_containing(html, needle))
}

fn extract_quoted_path_containing(text: &str, needle: &str) -> Option<String> {
    let start = text.find(needle)?;
    let prefix = &text[..start];
    let quote_start = prefix.rfind('"').or_else(|| prefix.rfind('\''))?;
    let quote = prefix[quote_start..].chars().next()?;
    let suffix = &text[quote_start + 1..];
    let quote_end = suffix.find(quote)?;
    let path = &suffix[..quote_end];
    if path.starts_with('/') {
        Some(path.to_string())
    } else {
        None
    }
}

fn value_has_required_fields(value: &Value, keys: &[&str]) -> bool {
    keys.iter().all(|key| value.get(key).is_some())
}

fn value_has_error(value: &Value) -> bool {
    value
        .get("error")
        .and_then(|error| error.get("message"))
        .and_then(Value::as_str)
        .is_some()
        || value.get("status").and_then(Value::as_str) == Some("error")
}

fn json_status_detail(value: &Value) -> String {
    if let Some(message) = value
        .get("error")
        .and_then(|error| error.get("message"))
        .and_then(Value::as_str)
    {
        return message.to_string();
    }

    let status = value
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("ok");
    format!("status: {status}")
}

fn serve_static(
    stream: &mut TcpStream,
    target: &str,
    repo_root: &Path,
    static_root: &Path,
) -> AppResult<()> {
    if !static_root.exists() {
        return write_response(
            stream,
            503,
            "text/html; charset=utf-8",
            build_missing_static_html(repo_root).as_bytes(),
        );
    }

    let relative_path = match sanitize_static_target(target) {
        Some(path) => path,
        None => {
            return write_response(
                stream,
                404,
                "text/plain; charset=utf-8",
                b"Not Found",
            )
        }
    };
    let file_path = static_root.join(relative_path);
    let file_path = if file_path.is_dir() {
        file_path.join("index.html")
    } else {
        file_path
    };

    if !file_path.exists() {
        if target == "/" {
            return write_response(
                stream,
                404,
                "text/plain; charset=utf-8",
                b"Static entrypoint not found",
            );
        }

        return write_response(
            stream,
            404,
            "text/plain; charset=utf-8",
            b"Not Found",
        );
    }

    let body = fs::read(&file_path)?;
    write_response(
        stream,
        200,
        content_type_for_path(&file_path),
        &body,
    )
}

fn sanitize_static_target(target: &str) -> Option<PathBuf> {
    let trimmed = target.trim_start_matches('/');
    if trimmed.is_empty() {
        return Some(PathBuf::from("index.html"));
    }

    if trimmed.split('/').any(|segment| segment == "..") {
        return None;
    }

    Some(PathBuf::from(trimmed))
}

fn content_type_for_path(path: &Path) -> &'static str {
    match path.extension().and_then(|value| value.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js" | "mjs") => "application/javascript; charset=utf-8",
        Some("json") => "application/json; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("webp") => "image/webp",
        Some("ico") => "image/x-icon",
        _ => "application/octet-stream",
    }
}

fn write_json(stream: &mut TcpStream, value: &Value) -> AppResult<()> {
    let body = serde_json::to_vec_pretty(value)
        .map_err(|error| AppError::Config(format!("failed to encode JSON response: {error}")))?;
    write_response(stream, 200, "application/json; charset=utf-8", &body)
}

fn write_response(
    stream: &mut TcpStream,
    status_code: u16,
    content_type: &str,
    body: &[u8],
) -> AppResult<()> {
    let status_text = match status_code {
        200 => "OK",
        404 => "Not Found",
        405 => "Method Not Allowed",
        503 => "Service Unavailable",
        _ => "OK",
    };

    let header = format!(
        "HTTP/1.1 {status_code} {status_text}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );

    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    Ok(())
}

fn write_sse_headers(stream: &mut TcpStream) -> AppResult<()> {
    let header = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-store\r\nConnection: close\r\nX-Accel-Buffering: no\r\n\r\n";
    stream.write_all(header.as_bytes())?;
    stream.flush()?;
    Ok(())
}

fn write_sse_event(stream: &mut TcpStream, event: &str, payload: &Value) -> AppResult<()> {
    let data = serde_json::to_string(payload)
        .map_err(|error| AppError::Config(format!("failed to encode SSE payload: {error}")))?;
    let frame = format!("event: {event}\ndata: {data}\n\n");
    stream.write_all(frame.as_bytes())?;
    stream.flush()?;
    Ok(())
}

fn push_progress_payload(progress: &PushEvaluationProgress) -> Value {
    match progress {
        PushEvaluationProgress::SnapshotLoaded {
            current_branch,
            upstream_branch,
            commits_ahead,
            discovered_files,
            scanned_files,
            ignored_files,
        } => json!({
            "kind": "snapshot",
            "current_branch": current_branch,
            "upstream_branch": upstream_branch,
            "commits_ahead": commits_ahead,
            "discovered_files": discovered_files,
            "scanned_files": scanned_files,
            "ignored_files": ignored_files
        }),
        PushEvaluationProgress::ScannerStarted { name, index, total } => json!({
            "kind": "scanner-started",
            "name": name,
            "label": scanner_progress_label(name),
            "index": index,
            "total": total
        }),
        PushEvaluationProgress::ScannerFinished {
            name,
            index,
            total,
            findings,
        } => json!({
            "kind": "scanner-finished",
            "name": name,
            "label": scanner_progress_label(name),
            "index": index,
            "total": total,
            "findings": findings
        }),
        PushEvaluationProgress::FileStarted {
            scanner,
            file,
            current,
            total,
        } => json!({
            "kind": "file-started",
            "scanner": scanner,
            "label": scanner_progress_label(scanner),
            "file": display_scan_file(file),
            "current": current,
            "total": total
        }),
        PushEvaluationProgress::GovernanceCheck => json!({
            "kind": "phase",
            "label": "Checking live repository governance"
        }),
        PushEvaluationProgress::FindingHistory => json!({
            "kind": "phase",
            "label": "Comparing findings against recent history"
        }),
        PushEvaluationProgress::FindingBaseline => json!({
            "kind": "phase",
            "label": "Comparing findings against the accepted baseline"
        }),
        PushEvaluationProgress::PolicyEvaluation => json!({
            "kind": "phase",
            "label": "Applying local push policy"
        }),
    }
}

fn push_evaluation_payload(evaluation: &PushEvaluation, repo_root: &Path) -> Value {
    match evaluation {
        PushEvaluation::NoCommits { context } => json!({
            "status": "no-commits",
            "repo_root": repo_root.display().to_string(),
            "evaluated_repo_root": context.repo_root.display().to_string()
        }),
        PushEvaluation::UpToDate { context } => json!({
            "status": "up-to-date",
            "repo_root": repo_root.display().to_string(),
            "evaluated_repo_root": context.repo_root.display().to_string()
        }),
        PushEvaluation::Ready {
            context,
            report,
            decision,
            current_branch,
            upstream_branch,
            commits_ahead,
            ..
        } => json!({
            "status": "ready",
            "repo_root": repo_root.display().to_string(),
            "evaluated_repo_root": context.repo_root.display().to_string(),
            "branch": current_branch,
            "upstream": upstream_branch,
            "commits_ahead": commits_ahead,
            "verdict": decision.verdict,
            "findings": report.findings.len(),
            "warnings": decision.warning_findings.len(),
            "blocks": decision.blocking_findings.len(),
            "scanned_files": report.scanned_files,
            "discovered_files": report.discovered_files,
            "ignored_files": report.ignored_files
        }),
    }
}

fn scanner_progress_label(name: &str) -> &'static str {
    match name {
        "secret-scanner" => "Checking secrets",
        "basic-sast" => "Checking risky code patterns",
        "artifact-scanner" => "Inspecting generated and packaged artifacts",
        "dependency-scanner" => "Checking dependency and provenance risks",
        "config-scanner" => "Checking infrastructure and workflow config",
        "policy-scanner" => "Checking Wolfence policy integrity",
        _ => "Running scanner",
    }
}

fn display_scan_file(path: &Path) -> String {
    let text = path.display().to_string();
    const MAX_LEN: usize = 56;
    if text.len() <= MAX_LEN {
        return text;
    }

    let suffix_len = MAX_LEN.saturating_sub(3);
    format!("...{}", &text[text.len() - suffix_len..])
}

fn build_missing_static_html(repo_root: &Path) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>Wolfence Web Console</title><style>body{{margin:0;background:#f3f4ed;color:#11161f;font-family:Avenir Next,Segoe UI,sans-serif;padding:32px}}main{{max-width:760px;margin:0 auto;background:rgba(255,255,255,.92);padding:28px;border:1px solid rgba(17,22,31,.08)}}code{{font-family:SFMono-Regular,Menlo,monospace}}</style></head><body><main><h1>Wolfence Web Console</h1><p>The local bridge is running, but the Astro static bundle is not built yet.</p><p>From <code>{}</code>, run:</p><pre><code>cd apps/web-console\nnpm install\nnpm run build</code></pre><p>Then refresh this page.</p></main></body></html>",
        repo_root.display()
    )
}

fn load_repo_configuration(repo_root: &Path) -> Value {
    let file_path = repo_root.join(".wolfence/config.toml");
    let text = match fs::read_to_string(&file_path) {
        Ok(text) => text,
        Err(_) => {
            return json!({
                "path": file_path.display().to_string(),
                "mode": Value::Null,
                "ignore_paths": [],
                "exists": false
            });
        }
    };

    json!({
        "path": file_path.display().to_string(),
        "mode": match_value(&text, "mode"),
        "ignore_paths": match_array(&text, "ignore_paths"),
        "exists": true
    })
}

fn load_receipt_policy(repo_root: &Path) -> Value {
    let file_path = repo_root.join(".wolfence/policy/receipts.toml");
    let text = match fs::read_to_string(&file_path) {
        Ok(text) => text,
        Err(_) => {
            return json!({
                "path": file_path.display().to_string(),
                "exists": false
            });
        }
    };

    json!({
        "path": file_path.display().to_string(),
        "exists": true,
        "require_explicit_category": match_bool(&text, "require_explicit_category").unwrap_or(false),
        "require_signed_receipts": match_bool(&text, "require_signed_receipts").unwrap_or(false),
        "require_reviewer_metadata": match_bool(&text, "require_reviewer_metadata").unwrap_or(false),
        "allowed_reviewers": match_array(&text, "allowed_reviewers"),
        "allowed_approvers": match_array(&text, "allowed_approvers"),
        "allowed_key_ids": match_array(&text, "allowed_key_ids")
    })
}

fn match_value(text: &str, key: &str) -> Option<String> {
    text.split('\n')
        .find(|line| line.trim_start().starts_with(&format!("{key} =")))
        .and_then(|line| line.split_once('='))
        .map(|(_, value)| value.trim().trim_matches('"').to_string())
}

fn match_bool(text: &str, key: &str) -> Option<bool> {
    match_value(text, key).and_then(|value| match value.as_str() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    })
}

fn match_array(text: &str, key: &str) -> Vec<String> {
    let Some(value) = match_value(text, key) else {
        return Vec::new();
    };

    value
        .trim_matches('[')
        .trim_matches(']')
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.trim_matches('"').to_string())
        .collect()
}

fn print_help() {
    println!("Wolfence UI Commands:");
    println!("  wolf ui");
    println!("  wolf ui serve");
    println!("  wolf ui verify");
    println!("  wolf ui verify-browser");
    println!("  wolf ui open");
    println!("  wolf ui help");
    println!();
    println!("`wolf ui` binds a localhost-only browser console on 127.0.0.1:4318 by default.");
}

fn exit_code_from_status(status: std::process::ExitStatus) -> ExitCode {
    match status.code() {
        Some(code) if code == 0 => ExitCode::SUCCESS,
        Some(_) | None => ExitCode::FAILURE,
    }
}

fn parse_json_body<T>(request: &str) -> AppResult<T>
where
    T: for<'de> Deserialize<'de>,
{
    let body = request.split("\r\n\r\n").nth(1).unwrap_or("");
    serde_json::from_str(body).map_err(|error| {
        AppError::Config(format!("failed to decode request body as JSON: {error}"))
    })
}

fn ui_workspace_file_path(repo_root: &Path) -> PathBuf {
    repo_root.join(".wolfence/ui/workspaces.json")
}

fn ui_workspace_cache_file_path(repo_root: &Path) -> PathBuf {
    repo_root.join(".wolfence/ui/workspace-cache.json")
}

fn ui_comparison_sets_file_path(repo_root: &Path) -> PathBuf {
    repo_root.join(".wolfence/ui/comparison-sets.json")
}

fn ui_verification_status_file_path(repo_root: &Path) -> PathBuf {
    repo_root.join(".wolfence/ui/verification-status.json")
}

fn browser_console_root(repo_root: &Path) -> PathBuf {
    repo_root.join("apps/web-console")
}

fn repository_supports_browser_console(repo_root: &Path) -> bool {
    let root = browser_console_root(repo_root);
    root.join("package.json").exists() && root.join("src/pages/index.astro").exists()
}

fn workspace_verification_value(repo_root: &Path) -> Value {
    json!({
        "supported": repository_supports_browser_console(repo_root),
        "surface": load_verification_status(repo_root).ok().and_then(|status| status.surface),
        "browser": load_verification_status(repo_root).ok().and_then(|status| status.browser)
    })
}

#[derive(Debug, Clone, Copy)]
enum VerificationTarget {
    Surface,
    Browser,
}

pub(super) fn load_verification_status(repo_root: &Path) -> AppResult<UiVerificationStatusFile> {
    let file_path = ui_verification_status_file_path(repo_root);
    if !file_path.exists() {
        return Ok(UiVerificationStatusFile::default());
    }

    let text = fs::read_to_string(&file_path)?;
    serde_json::from_str::<UiVerificationStatusFile>(&text).map_err(|error| {
        AppError::Config(format!(
            "failed to decode UI verification status at {}: {error}",
            file_path.display()
        ))
    })
}

fn save_verification_status(
    repo_root: &Path,
    status: &UiVerificationStatusFile,
) -> AppResult<()> {
    let file_path = ui_verification_status_file_path(repo_root);
    if let Some(parent) = file_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let body = serde_json::to_string_pretty(status).map_err(|error| {
        AppError::Config(format!(
            "failed to encode UI verification status at {}: {error}",
            file_path.display()
        ))
    })?;
    fs::write(&file_path, body)?;
    Ok(())
}

fn save_verification_record(
    repo_root: &Path,
    target: VerificationTarget,
    ok: bool,
    command: String,
    detail: String,
) -> AppResult<()> {
    let mut status = load_verification_status(repo_root)?;
    let record = UiVerificationRecord {
        ok,
        command,
        detail,
        checked_at_unix: current_unix_timestamp(),
    };

    match target {
        VerificationTarget::Surface => status.surface = Some(record),
        VerificationTarget::Browser => status.browser = Some(record),
    }

    save_verification_status(repo_root, &status)
}

fn load_workspace_state(repo_root: &Path) -> AppResult<UiWorkspaceState> {
    let file_path = ui_workspace_file_path(repo_root);
    let mut file = if file_path.exists() {
        let text = fs::read_to_string(&file_path)?;
        serde_json::from_str::<UiWorkspaceFile>(&text).map_err(|error| {
            AppError::Config(format!(
                "failed to decode UI workspace state at {}: {error}",
                file_path.display()
            ))
        })?
    } else {
        UiWorkspaceFile::default()
    };

    let current_repo = git::discover_repo_root_from(repo_root)?;
    let mut repositories = file
        .repositories
        .into_iter()
        .map(PathBuf::from)
        .collect::<Vec<_>>();

    if !repositories.iter().any(|path| path == &current_repo) {
        repositories.insert(0, current_repo.clone());
    }

    repositories.sort();
    repositories.dedup();

    let selected_path = file
        .selected_path
        .take()
        .map(PathBuf::from)
        .filter(|path| repositories.iter().any(|candidate| candidate == path))
        .unwrap_or_else(|| current_repo.clone());

    Ok(UiWorkspaceState {
        file_path,
        repositories,
        selected_path,
    })
}

fn save_workspace_state(state: &UiWorkspaceState) -> AppResult<()> {
    if let Some(parent) = state.file_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let file = UiWorkspaceFile {
        repositories: state
            .repositories
            .iter()
            .map(|path| path.display().to_string())
            .collect(),
        selected_path: Some(state.selected_path.display().to_string()),
    };
    let encoded = serde_json::to_string_pretty(&file).map_err(|error| {
        AppError::Config(format!("failed to encode UI workspace state: {error}"))
    })?;
    atomic_write(&state.file_path, encoded.as_bytes())?;
    Ok(())
}

fn load_workspace_cache(repo_root: &Path) -> AppResult<UiWorkspaceCacheFile> {
    let file_path = ui_workspace_cache_file_path(repo_root);
    if !file_path.exists() {
        return Ok(UiWorkspaceCacheFile::default());
    }

    let text = fs::read_to_string(&file_path)?;
    serde_json::from_str::<UiWorkspaceCacheFile>(&text).map_err(|error| {
        AppError::Config(format!(
            "failed to decode UI workspace cache at {}: {error}",
            file_path.display()
        ))
    })
}

fn load_cached_workspace_entry(repo_root: &Path, workspace_root: &Path) -> Option<UiWorkspaceCacheEntry> {
    load_workspace_cache(repo_root)
        .ok()
        .and_then(|cache| cache.entries.get(&workspace_root.display().to_string()).cloned())
}

fn save_workspace_cache(repo_root: &Path, cache: &UiWorkspaceCacheFile) -> AppResult<()> {
    let file_path = ui_workspace_cache_file_path(repo_root);
    if let Some(parent) = file_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let encoded = serde_json::to_string_pretty(cache).map_err(|error| {
        AppError::Config(format!("failed to encode UI workspace cache: {error}"))
    })?;
    atomic_write(&file_path, encoded.as_bytes())?;
    Ok(())
}

fn load_comparison_sets(repo_root: &Path) -> AppResult<UiComparisonSetsFile> {
    let file_path = ui_comparison_sets_file_path(repo_root);
    if !file_path.exists() {
        return Ok(UiComparisonSetsFile::default());
    }

    let text = fs::read_to_string(&file_path)?;
    serde_json::from_str::<UiComparisonSetsFile>(&text).map_err(|error| {
        AppError::Config(format!(
            "failed to decode UI comparison sets at {}: {error}",
            file_path.display()
        ))
    })
}

fn save_comparison_sets(repo_root: &Path, comparison_sets: &UiComparisonSetsFile) -> AppResult<()> {
    let file_path = ui_comparison_sets_file_path(repo_root);
    if let Some(parent) = file_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let encoded = serde_json::to_string_pretty(comparison_sets).map_err(|error| {
        AppError::Config(format!("failed to encode UI comparison sets: {error}"))
    })?;
    atomic_write(&file_path, encoded.as_bytes())?;
    Ok(())
}

fn reconcile_workspace_cache(state: &UiWorkspaceState, cache: &mut UiWorkspaceCacheFile) {
    cache.entries.retain(|path, _| {
        state.repositories.iter().any(|candidate| candidate.display().to_string() == *path)
    });
}

fn reconcile_comparison_sets(state: &UiWorkspaceState, comparison_sets: &mut UiComparisonSetsFile) {
    let pinned = state
        .repositories
        .iter()
        .map(|path| path.display().to_string())
        .collect::<std::collections::BTreeSet<_>>();

    comparison_sets.sets.retain(|_, paths| {
        paths.retain(|path| pinned.contains(path));
        paths.sort();
        paths.dedup();
        !paths.is_empty()
    });

    if comparison_sets
        .selected_name
        .as_ref()
        .is_some_and(|name| !comparison_sets.sets.contains_key(name))
    {
        comparison_sets.selected_name = None;
    }
}

fn workspace_state_payload(repo_root: &Path) -> Value {
    match load_workspace_state(repo_root) {
        Ok(state) => json!({
            "selected_path": state.selected_path.display().to_string(),
            "workspaces": workspace_entries(repo_root, &state, None),
            "comparison_sets": comparison_sets_payload(repo_root)
        }),
        Err(error) => json!({
            "error": {
                "message": error.to_string()
            }
        }),
    }
}

fn comparison_sets_payload(repo_root: &Path) -> Value {
    let Ok(state) = load_workspace_state(repo_root) else {
        return json!({
            "selected_name": Value::Null,
            "sets": []
        });
    };
    let mut comparison_sets = load_comparison_sets(repo_root).unwrap_or_default();
    reconcile_comparison_sets(&state, &mut comparison_sets);
    json!({
        "selected_name": comparison_sets.selected_name,
        "sets": comparison_sets
            .sets
            .iter()
            .map(|(name, paths)| {
                json!({
                    "name": name,
                    "paths": paths,
                    "count": paths.len(),
                    "selected": comparison_sets.selected_name.as_deref() == Some(name.as_str())
                })
            })
            .collect::<Vec<_>>()
    })
}

fn workspace_entries(
    repo_root: &Path,
    state: &UiWorkspaceState,
    selected_override: Option<(&Path, &UiWorkspaceCacheEntry)>,
) -> Vec<Value> {
    let mut cache = load_workspace_cache(repo_root).unwrap_or_default();
    reconcile_workspace_cache(state, &mut cache);

    state
        .repositories
        .iter()
        .map(|path| {
            let cached = selected_override
                .filter(|(selected_path, _)| *selected_path == path)
                .map(|(_, entry)| entry.clone())
                .or_else(|| cache.entries.get(&path.display().to_string()).cloned());
            let fallback = uncached_workspace_entry();
            let entry = cached.as_ref().unwrap_or(&fallback);
            json!({
                "id": path.display().to_string(),
                "name": path.file_name().map(|value| value.to_string_lossy().to_string()).unwrap_or_else(|| path.display().to_string()),
                "path": path.display().to_string(),
                "selected": *path == state.selected_path,
                "branch": entry.branch,
                "upstream": entry.upstream,
                "tone": entry.tone,
                "verdict_label": entry.verdict_label,
                "summary": entry.summary,
                "doctor_summary": entry.doctor_summary,
                "last_refreshed_unix": entry.last_refreshed_unix,
                "cached": cached.is_some(),
                "verification": workspace_verification_value(path)
            })
        })
        .collect()
}

fn add_workspace(repo_root: &Path, path: &str) -> AppResult<()> {
    let mut state = load_workspace_state(repo_root)?;
    let workspace_root = git::discover_repo_root_from(Path::new(path))?;
    if !state.repositories.iter().any(|candidate| candidate == &workspace_root) {
        state.repositories.push(workspace_root.clone());
        state.repositories.sort();
        state.repositories.dedup();
    }
    state.selected_path = workspace_root;
    save_workspace_state(&state)?;
    let _ = refresh_workspace_cache_entry(repo_root, &state.selected_path)?;
    Ok(())
}

fn select_workspace(repo_root: &Path, path: &str) -> AppResult<()> {
    let mut state = load_workspace_state(repo_root)?;
    let selected = PathBuf::from(path);
    if !state.repositories.iter().any(|candidate| candidate == &selected) {
        return Err(AppError::Config(format!(
            "workspace `{}` is not currently pinned",
            selected.display()
        )));
    }
    state.selected_path = selected;
    save_workspace_state(&state)?;
    let _ = refresh_workspace_cache_entry(repo_root, &state.selected_path)?;
    Ok(())
}

fn remove_workspace(repo_root: &Path, path: &str) -> AppResult<()> {
    let mut state = load_workspace_state(repo_root)?;
    let target = PathBuf::from(path);
    if !state.repositories.iter().any(|candidate| candidate == &target) {
        return Err(AppError::Config(format!(
            "workspace `{}` is not currently pinned",
            target.display()
        )));
    }
    if state.repositories.len() == 1 {
        return Err(AppError::Config(
            "cannot remove the last pinned workspace".to_string(),
        ));
    }

    state.repositories.retain(|candidate| candidate != &target);
    if state.selected_path == target {
        state.selected_path = state
            .repositories
            .first()
            .cloned()
            .ok_or_else(|| AppError::Config("no workspace remains after removal".to_string()))?;
    }
    save_workspace_state(&state)?;

    let mut cache = load_workspace_cache(repo_root).unwrap_or_default();
    reconcile_workspace_cache(&state, &mut cache);
    save_workspace_cache(repo_root, &cache)?;

    let mut comparison_sets = load_comparison_sets(repo_root).unwrap_or_default();
    reconcile_comparison_sets(&state, &mut comparison_sets);
    save_comparison_sets(repo_root, &comparison_sets)
}

fn refresh_workspace(repo_root: &Path, path: &str) -> AppResult<()> {
    let state = load_workspace_state(repo_root)?;
    let workspace_root = PathBuf::from(path);
    if !state
        .repositories
        .iter()
        .any(|candidate| candidate == &workspace_root)
    {
        return Err(AppError::Config(format!(
            "workspace `{}` is not currently pinned",
            workspace_root.display()
        )));
    }

    let _ = refresh_workspace_cache_entry(repo_root, &workspace_root)?;
    Ok(())
}

fn refresh_all_workspaces(repo_root: &Path) -> AppResult<()> {
    let state = load_workspace_state(repo_root)?;
    for workspace in &state.repositories {
        let _ = refresh_workspace_cache_entry(repo_root, workspace)?;
    }
    Ok(())
}

fn save_comparison_set(repo_root: &Path, name: &str, paths: &[String]) -> AppResult<()> {
    let state = load_workspace_state(repo_root)?;
    let trimmed_name = name.trim();
    if trimmed_name.is_empty() {
        return Err(AppError::Config(
            "comparison set name cannot be empty".to_string(),
        ));
    }

    let valid_paths = paths
        .iter()
        .map(PathBuf::from)
        .filter(|path| state.repositories.iter().any(|candidate| candidate == path))
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>();

    if valid_paths.is_empty() {
        return Err(AppError::Config(
            "comparison set must include at least one pinned repository".to_string(),
        ));
    }

    let mut comparison_sets = load_comparison_sets(repo_root).unwrap_or_default();
    reconcile_comparison_sets(&state, &mut comparison_sets);
    comparison_sets
        .sets
        .insert(trimmed_name.to_string(), valid_paths);
    comparison_sets.selected_name = Some(trimmed_name.to_string());
    reconcile_comparison_sets(&state, &mut comparison_sets);
    save_comparison_sets(repo_root, &comparison_sets)
}

fn select_comparison_set(repo_root: &Path, name: &str) -> AppResult<()> {
    let state = load_workspace_state(repo_root)?;
    let mut comparison_sets = load_comparison_sets(repo_root).unwrap_or_default();
    reconcile_comparison_sets(&state, &mut comparison_sets);
    if !comparison_sets.sets.contains_key(name) {
        return Err(AppError::Config(format!(
            "comparison set `{name}` does not exist"
        )));
    }
    comparison_sets.selected_name = Some(name.to_string());
    save_comparison_sets(repo_root, &comparison_sets)
}

fn clear_comparison_set_selection(repo_root: &Path) -> AppResult<()> {
    let state = load_workspace_state(repo_root)?;
    let mut comparison_sets = load_comparison_sets(repo_root).unwrap_or_default();
    reconcile_comparison_sets(&state, &mut comparison_sets);
    comparison_sets.selected_name = None;
    save_comparison_sets(repo_root, &comparison_sets)
}

fn remove_comparison_set(repo_root: &Path, name: &str) -> AppResult<()> {
    let state = load_workspace_state(repo_root)?;
    let mut comparison_sets = load_comparison_sets(repo_root).unwrap_or_default();
    reconcile_comparison_sets(&state, &mut comparison_sets);
    if comparison_sets.sets.remove(name).is_none() {
        return Err(AppError::Config(format!(
            "comparison set `{name}` does not exist"
        )));
    }
    if comparison_sets.selected_name.as_deref() == Some(name) {
        comparison_sets.selected_name = None;
    }
    save_comparison_sets(repo_root, &comparison_sets)
}

fn refresh_workspace_cache_entry(
    repo_root: &Path,
    workspace_root: &Path,
) -> AppResult<UiWorkspaceCacheEntry> {
    let state = load_workspace_state(repo_root)?;
    let mut cache = load_workspace_cache(repo_root).unwrap_or_default();
    reconcile_workspace_cache(&state, &mut cache);
    let entry = build_workspace_cache_entry(workspace_root);
    cache
        .entries
        .insert(workspace_root.display().to_string(), entry.clone());
    save_workspace_cache(repo_root, &cache)?;
    Ok(entry)
}

fn run_repo_push(repo_root: &Path, repository: &Path, dry_run: bool) -> Value {
    let payload = run_wolf_json_with_env(
        repository,
        &["push", "--json"],
        &[("WOLFENCE_DRY_RUN", if dry_run { Some("1") } else { None })],
    );
    let _ = refresh_workspace_cache_entry(repo_root, repository);
    payload
}

fn workspace_tone(verdict: Option<&str>, status: Option<&str>) -> &'static str {
    match (verdict, status) {
        (Some("block"), _) => "blocked",
        (Some("warn"), _) => "review",
        (_, Some("up-to-date" | "no-commits")) => "safe",
        (Some("allow"), _) => "safe",
        _ => "safe",
    }
}

fn workspace_verdict_label(verdict: Option<&str>, status: Option<&str>) -> String {
    match (verdict, status) {
        (_, Some("up-to-date")) => "Up to date".to_string(),
        (_, Some("no-commits")) => "No commits".to_string(),
        (Some("block"), _) => "Blocked".to_string(),
        (Some("warn"), _) => "Warnings".to_string(),
        (Some("allow"), _) => "Push Ready".to_string(),
        _ => "Unknown".to_string(),
    }
}

fn workspace_summary(push_preview: &Value) -> String {
    let status = push_preview.get("status").and_then(Value::as_str).unwrap_or("unknown");
    match status {
        "up-to-date" => "No outbound scope right now".to_string(),
        "no-commits" => "No commits ahead of upstream".to_string(),
        "ready" | "completed" => {
            let blocks = push_preview
                .get("decision")
                .and_then(|value| value.get("blocking_findings"))
                .and_then(Value::as_array)
                .map(Vec::len)
                .unwrap_or(0);
            let warnings = push_preview
                .get("decision")
                .and_then(|value| value.get("warning_findings"))
                .and_then(Value::as_array)
                .map(Vec::len)
                .unwrap_or(0);
            let commits_ahead = push_preview
                .get("commits_ahead")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let scanned_files = push_preview
                .get("report")
                .and_then(|value| value.get("scanned_files"))
                .and_then(Value::as_u64)
                .unwrap_or(0);

            if blocks > 0 || warnings > 0 {
                format!("{blocks} blockers • {warnings} warnings")
            } else {
                format!("{commits_ahead} commits ahead • {scanned_files} files in scope")
            }
        }
        _ => "State unavailable".to_string(),
    }
}

fn build_workspace_cache_entry(workspace_root: &Path) -> UiWorkspaceCacheEntry {
    let push_preview = run_wolf_json(workspace_root, &["scan", "push", "--json"]);
    let doctor = run_wolf_json(workspace_root, &["doctor", "--json"]);
    workspace_cache_entry_from_values(&push_preview, &doctor)
}

fn workspace_cache_entry_from_values(push_preview: &Value, doctor: &Value) -> UiWorkspaceCacheEntry {
    let verdict = push_preview
        .get("decision")
        .and_then(|value| value.get("verdict"))
        .and_then(Value::as_str);
    let status = push_preview.get("status").and_then(Value::as_str);

    UiWorkspaceCacheEntry {
        branch: push_preview
            .get("branch")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        upstream: push_preview
            .get("upstream")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        tone: workspace_tone(verdict, status).to_string(),
        verdict_label: workspace_verdict_label(verdict, status),
        summary: workspace_summary(push_preview),
        doctor_summary: doctor
            .get("summary")
            .map(|summary| {
                format!(
                    "{} pass, {} warn, {} fail",
                    summary.get("pass").and_then(Value::as_u64).unwrap_or(0),
                    summary.get("warn").and_then(Value::as_u64).unwrap_or(0),
                    summary.get("fail").and_then(Value::as_u64).unwrap_or(0)
                )
            })
            .unwrap_or_else(|| "doctor unavailable".to_string()),
        last_refreshed_unix: current_unix_timestamp(),
    }
}

fn uncached_workspace_entry() -> UiWorkspaceCacheEntry {
    UiWorkspaceCacheEntry {
        branch: None,
        upstream: None,
        tone: "review".to_string(),
        verdict_label: "Needs refresh".to_string(),
        summary: "No cached push posture yet".to_string(),
        doctor_summary: "Run refresh to compute doctor status".to_string(),
        last_refreshed_unix: 0,
    }
}

fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn bridge_auto_refresh_seconds() -> u64 {
    std::env::var("WOLFENCE_UI_AUTO_REFRESH_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(DEFAULT_UI_AUTO_REFRESH_SECS)
}

fn spawn_workspace_refresh_scheduler(repo_root: PathBuf, refresh_secs: u64) {
    if refresh_secs == 0 {
        return;
    }

    thread::spawn(move || {
        if let Err(error) = refresh_stale_workspaces(&repo_root, refresh_secs) {
            eprintln!("wolf ui: workspace auto-refresh failed: {error}");
        }

        loop {
            thread::sleep(Duration::from_secs(refresh_secs));
            if let Err(error) = refresh_stale_workspaces(&repo_root, refresh_secs) {
                eprintln!("wolf ui: workspace auto-refresh failed: {error}");
            }
        }
    });
}

fn refresh_stale_workspaces(repo_root: &Path, stale_after_secs: u64) -> AppResult<usize> {
    let state = load_workspace_state(repo_root)?;
    let cache = load_workspace_cache(repo_root).unwrap_or_default();
    let now = current_unix_timestamp();
    let mut refreshed = 0;

    for workspace in &state.repositories {
        let cached = cache.entries.get(&workspace.display().to_string());
        if workspace_cache_is_stale(cached, now, stale_after_secs) {
            let _ = refresh_workspace_cache_entry(repo_root, workspace)?;
            refreshed += 1;
        }
    }

    Ok(refreshed)
}

fn workspace_cache_is_stale(
    cached: Option<&UiWorkspaceCacheEntry>,
    now_unix: u64,
    stale_after_secs: u64,
) -> bool {
    match cached {
        None => true,
        Some(entry) => now_unix.saturating_sub(entry.last_refreshed_unix) >= stale_after_secs,
    }
}

fn atomic_write(path: &Path, body: &[u8]) -> AppResult<()> {
    let temp_path = path.with_extension(format!(
        "{}.tmp",
        path.extension().and_then(|value| value.to_str()).unwrap_or("file")
    ));
    fs::write(&temp_path, body)?;
    if let Err(error) = fs::rename(&temp_path, path) {
        fs::write(path, body).map_err(|write_error| {
            AppError::Config(format!(
                "failed to replace {} after temp-write rename error ({error}): {write_error}",
                path.display()
            ))
        })?;
        let _ = fs::remove_file(&temp_path);
    }
    Ok(())
}

fn resolve_repository_identifier(repo_root: &Path, identifier: &str) -> AppResult<PathBuf> {
    let state = load_workspace_state(repo_root)?;
    if identifier == "current" {
        return Ok(state.selected_path);
    }

    let decoded = percent_decode(identifier)?;
    let repository = git::discover_repo_root_from(Path::new(&decoded))?;
    if !state.repositories.iter().any(|candidate| candidate == &repository) {
        return Err(AppError::Config(format!(
            "repository `{}` is not currently pinned in the local browser workspace",
            repository.display()
        )));
    }

    Ok(repository)
}

fn percent_decode(value: &str) -> AppResult<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return Err(AppError::Config(format!(
                    "invalid percent-encoded repository identifier `{value}`"
                )));
            }
            let high = decode_hex_digit(bytes[index + 1])?;
            let low = decode_hex_digit(bytes[index + 2])?;
            decoded.push((high << 4) | low);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }

    String::from_utf8(decoded).map_err(|error| {
        AppError::Config(format!(
            "repository identifier `{value}` is not valid UTF-8 after decoding: {error}"
        ))
    })
}

fn decode_hex_digit(value: u8) -> AppResult<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(AppError::Config(format!(
            "invalid percent-encoding hex digit `{}`",
            value as char
        ))),
    }
}

fn run_wolf_json_with_env(
    repo_root: &Path,
    arguments: &[&str],
    env_updates: &[(&str, Option<&str>)],
) -> Value {
    let current_exe = match std::env::current_exe() {
        Ok(path) => path,
        Err(error) => {
            return command_error_value(arguments, &format!("failed to locate current executable: {error}"));
        }
    };

    let mut command = Command::new(&current_exe);
    command.args(arguments).current_dir(repo_root);
    for (key, value) in env_updates {
        match value {
            Some(value) => {
                command.env(key, value);
            }
            None => {
                command.env_remove(key);
            }
        }
    }

    let output = match command.output() {
        Ok(output) => output,
        Err(error) => {
            return command_error_value(
                arguments,
                &format!("failed to execute {}: {error}", current_exe.display()),
            );
        }
    };

    if output.stdout.is_empty() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return command_error_value(
            arguments,
            &if stderr.is_empty() {
                "command returned no JSON output".to_string()
            } else {
                stderr
            },
        );
    }

    match serde_json::from_slice::<Value>(&output.stdout) {
        Ok(value) => value,
        Err(error) => command_error_value(
            arguments,
            &format!("failed to decode JSON response: {error}"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        decode_hex_digit, percent_decode, reconcile_comparison_sets,
        repository_supports_browser_console, workspace_cache_is_stale,
        UiComparisonSetsFile, UiWorkspaceCacheEntry, UiWorkspaceState,
    };
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn percent_decode_restores_encoded_repository_paths() {
        let decoded =
            percent_decode("%2FUsers%2Fyoavperetz%2FDeveloper%2FWolfence").unwrap();
        assert_eq!(decoded, "/Users/yoavperetz/Developer/Wolfence");
    }

    #[test]
    fn percent_decode_rejects_truncated_sequences() {
        let error = percent_decode("%2").unwrap_err().to_string();
        assert!(error.contains("invalid percent-encoded repository identifier"));
    }

    #[test]
    fn decode_hex_digit_rejects_non_hex_input() {
        let error = decode_hex_digit(b'g').unwrap_err().to_string();
        assert!(error.contains("invalid percent-encoding hex digit"));
    }

    #[test]
    fn workspace_cache_is_stale_when_missing_or_expired() {
        assert!(workspace_cache_is_stale(None, 1_000, 300));

        let fresh = UiWorkspaceCacheEntry {
            branch: None,
            upstream: None,
            tone: "safe".to_string(),
            verdict_label: "Up to date".to_string(),
            summary: "No outbound scope right now".to_string(),
            doctor_summary: "17 pass, 0 warn, 0 fail".to_string(),
            last_refreshed_unix: 900,
        };
        assert!(!workspace_cache_is_stale(Some(&fresh), 1_000, 300));

        let stale = UiWorkspaceCacheEntry {
            last_refreshed_unix: 600,
            ..fresh
        };
        assert!(workspace_cache_is_stale(Some(&stale), 1_000, 300));
    }

    #[test]
    fn reconcile_comparison_sets_drops_unpinned_paths_and_invalid_selection() {
        let state = UiWorkspaceState {
            file_path: PathBuf::from("/tmp/workspaces.json"),
            repositories: vec![
                PathBuf::from("/repos/alpha"),
                PathBuf::from("/repos/bravo"),
            ],
            selected_path: PathBuf::from("/repos/alpha"),
        };
        let mut comparison_sets = UiComparisonSetsFile {
            sets: [
                (
                    "core".to_string(),
                    vec![
                        "/repos/alpha".to_string(),
                        "/repos/charlie".to_string(),
                    ],
                ),
                ("stale".to_string(), vec!["/repos/charlie".to_string()]),
            ]
            .into_iter()
            .collect(),
            selected_name: Some("stale".to_string()),
        };

        reconcile_comparison_sets(&state, &mut comparison_sets);

        assert_eq!(
            comparison_sets.sets.get("core"),
            Some(&vec!["/repos/alpha".to_string()])
        );
        assert!(!comparison_sets.sets.contains_key("stale"));
        assert_eq!(comparison_sets.selected_name, None);
    }

    #[test]
    fn repository_supports_browser_console_requires_expected_surface_files() {
        let temp_root = std::env::temp_dir().join(format!(
            "wolfence-ui-support-{}",
            std::process::id()
        ));
        let web_console_root = temp_root.join("apps/web-console/src/pages");
        fs::create_dir_all(&web_console_root).unwrap();
        fs::write(temp_root.join("apps/web-console/package.json"), "{}").unwrap();
        fs::write(web_console_root.join("index.astro"), "---\n").unwrap();

        assert!(repository_supports_browser_console(&temp_root));

        fs::remove_dir_all(temp_root).unwrap();
    }
}
