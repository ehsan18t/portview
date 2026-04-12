//! # Socket collector
//!
//! Calls the `listeners` crate to enumerate open sockets and `sysinfo` to
//! resolve process metadata (name, owning user). Enriches each entry with
//! Docker container info, project root detection, and app/framework labels.
//!
//! ## Module structure
//!
//! - `dedup` — Pure deduplication and proxy-collapsing engine.
//! - `tcp_state` — OS-specific TCP connection state polling.
//! - `user` — User identity resolution and privilege detection.

mod dedup;
mod tcp_state;
mod user;

use std::collections::HashMap;
use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::Result;
use log::debug;
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

use crate::docker::{self, ContainerPortMap};
use crate::types::{PortEntry, Protocol, State};
use crate::{framework, project};

use tcp_state::TcpStateIndex;
use user::UserResolver;

struct CollectContext<'a> {
    sys: &'a System,
    user_resolver: &'a mut UserResolver,
    container_map: &'a ContainerPortMap,
    tcp_states: &'a TcpStateIndex,
    now_epoch: u64,
    deep_enrichment: bool,
    project_cache: &'a mut HashMap<PathBuf, Option<PathBuf>>,
    home: Option<&'a Path>,
    #[cfg(target_os = "linux")]
    podman_rootless_resolver: &'a mut docker::RootlessPodmanResolver,
}

/// Options controlling how the collector enriches socket data.
#[derive(Debug, Clone, Copy)]
pub struct CollectOptions {
    /// Enable Docker/Podman lookup plus project-root and config-file enrichment.
    pub deep_enrichment: bool,
}

impl Default for CollectOptions {
    fn default() -> Self {
        Self {
            deep_enrichment: true,
        }
    }
}

/// Collect all open TCP and UDP sockets using the provided enrichment options.
///
/// When `deep_enrichment` is disabled, the collector skips Docker/Podman
/// probing, project-root walking, config-file scanning, and command-line path
/// fallback. Core socket, PID, user, uptime, and process-name detection remain.
pub fn collect_with_options(options: &CollectOptions) -> Result<Vec<PortEntry>> {
    // Start Docker/Podman detection early so it runs concurrently with
    // the OS-level socket enumeration and process metadata refresh.
    let docker_handle = if options.deep_enrichment {
        Some(docker::start_detection())
    } else {
        None
    };

    let raw_listeners = listeners::get_all()
        .map_err(|e| anyhow::anyhow!("failed to enumerate open sockets from the OS: {e}"))?;

    let mut sys = System::new();

    let mut tracked_pids: Vec<_> = raw_listeners
        .iter()
        .map(|listener| sysinfo::Pid::from_u32(listener.process.pid))
        .collect();
    tracked_pids.sort_unstable();
    tracked_pids.dedup();
    debug!(
        "enumerated raw listeners: deep_enrichment={} listeners={} tracked_pids={}",
        options.deep_enrichment,
        raw_listeners.len(),
        tracked_pids.len()
    );

    // `false` = do not remove previously-tracked dead processes. On a
    // freshly created System the internal map is empty, so this flag
    // has no effect either way. Passing `false` avoids the slightly
    // more expensive "clean up stale entries" pass.
    if !tracked_pids.is_empty() {
        sys.refresh_processes_specifics(
            ProcessesToUpdate::Some(&tracked_pids),
            false,
            process_refresh_kind(options.deep_enrichment),
        );
    }

    let mut user_resolver = UserResolver::default();

    // Block on Docker results only after all other I/O is done.
    let container_map =
        docker_handle.map_or_else(ContainerPortMap::default, docker::await_detection);
    let tcp_states = tcp_state::load_tcp_state_index();

    let now_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut project_cache: HashMap<PathBuf, Option<PathBuf>> =
        HashMap::with_capacity(raw_listeners.len());
    #[cfg(target_os = "linux")]
    let mut podman_rootless_resolver = docker::RootlessPodmanResolver::default();

    // Resolve the home directory once so that every per-process
    // invocation of find_from_dir does not each query the OS environment.
    let home = if options.deep_enrichment {
        project::home_dir()
    } else {
        None
    };
    let mut context = CollectContext {
        sys: &sys,
        user_resolver: &mut user_resolver,
        container_map: &container_map,
        tcp_states: &tcp_states,
        now_epoch,
        deep_enrichment: options.deep_enrichment,
        project_cache: &mut project_cache,
        home: home.as_deref(),
        #[cfg(target_os = "linux")]
        podman_rootless_resolver: &mut podman_rootless_resolver,
    };

    let all_entries: Vec<PortEntry> = raw_listeners
        .into_iter()
        .map(|l| build_entry(&l, &mut context))
        .collect();

    let mut entries = dedup::deduplicate(all_entries);
    entries.sort_by(|left, right| {
        (
            left.port,
            left.local_addr,
            left.proto,
            left.pid,
            left.process.as_str(),
        )
            .cmp(&(
                right.port,
                right.local_addr,
                right.proto,
                right.pid,
                right.process.as_str(),
            ))
    });
    debug!("finished socket collection: entries={}", entries.len());
    Ok(entries)
}

/// Return a best-effort warning when the current process lacks full visibility.
///
/// On Linux this checks for effective root privileges. On Windows it checks
/// whether the current token is elevated. Other targets return `None`.
#[must_use]
pub fn visibility_warning() -> Option<&'static str> {
    if user::has_full_visibility_privileges() {
        None
    } else {
        Some(visibility_warning_message())
    }
}

#[cfg(target_os = "linux")]
const fn visibility_warning_message() -> &'static str {
    "running without root privileges can hide sockets and container metadata; rerun with sudo for full visibility"
}

#[cfg(windows)]
const fn visibility_warning_message() -> &'static str {
    "running without Administrator privileges can hide sockets and process metadata; rerun in an elevated terminal for full visibility"
}

#[cfg(not(any(target_os = "linux", windows)))]
const fn visibility_warning_message() -> &'static str {
    ""
}

// ── Entry builder ────────────────────────────────────────────────────

/// Build a single [`PortEntry`] from a [`listeners::Listener`], enriching it
/// with Docker, project, framework, and uptime information.
fn build_entry(l: &listeners::Listener, context: &mut CollectContext<'_>) -> PortEntry {
    let proto = match l.protocol {
        listeners::Protocol::TCP => Protocol::Tcp,
        listeners::Protocol::UDP => Protocol::Udp,
    };

    let state = resolve_state(l, context.tcp_states);

    let sysinfo_pid = sysinfo::Pid::from_u32(l.process.pid);
    let sysinfo_process = context.sys.process(sysinfo_pid);
    let exe_path = sysinfo_process.and_then(sysinfo::Process::exe);
    let exe_name = process_executable_name(exe_path);
    let user = user::resolve_user(sysinfo_process, l.process.pid, context.user_resolver);

    let (container, project_name, project_root) = if context.deep_enrichment {
        let container = resolve_container(
            context,
            l.socket,
            proto,
            l.process.pid,
            &l.process.name,
            exe_name,
        );

        // Project detection: use container name for Docker ports, otherwise walk cwd.
        // The cache avoids redundant directory walks for processes sharing a cwd.
        let (project_name, project_root) = container.as_ref().map_or_else(
            || {
                let cwd = sysinfo_process.and_then(sysinfo::Process::cwd);
                let cmd = sysinfo_process.map_or(&[][..], sysinfo::Process::cmd);
                let root =
                    lookup_project_root(cwd, exe_path, cmd, context.project_cache, context.home);
                let name = root
                    .as_ref()
                    .and_then(|r| r.file_name())
                    .map(|n| n.to_string_lossy().into_owned());
                (name, root)
            },
            |c| (Some(c.name.clone()), None),
        );

        (container, project_name, project_root)
    } else {
        (None, None, None)
    };

    // App/framework detection
    let app = if context.deep_enrichment {
        framework::detect(container.as_ref(), project_root.as_deref(), &l.process.name)
            .or_else(|| exe_name.and_then(framework::detect_from_process))
    } else {
        framework::detect_from_process(&l.process.name)
            .or_else(|| exe_name.and_then(framework::detect_from_process))
    };

    // Uptime from process start time
    let uptime_secs = sysinfo_process.and_then(|p| {
        let start = p.start_time();
        if start > 0 && context.now_epoch > start {
            Some(context.now_epoch - start)
        } else {
            None
        }
    });

    PortEntry {
        port: l.socket.port(),
        local_addr: l.socket.ip(),
        proto,
        state,
        pid: l.process.pid,
        process: l.process.name.clone(),
        user,
        project: project_name,
        app,
        uptime_secs,
    }
}

// ── Container resolution ─────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn resolve_container(
    context: &mut CollectContext<'_>,
    socket: SocketAddr,
    proto: Protocol,
    pid: u32,
    process_name: &str,
    exe_name: Option<&str>,
) -> Option<docker::ContainerInfo> {
    if let Some(container) =
        lookup_container(context.container_map, socket, proto, process_name, exe_name)
    {
        return Some(container.clone());
    }

    let rootless_name =
        rootless_podman_process_name(process_name, exe_name).unwrap_or(process_name);
    docker::lookup_rootless_podman_container(
        pid,
        rootless_name,
        context.podman_rootless_resolver,
        context.home,
    )
}

#[cfg(not(target_os = "linux"))]
#[allow(clippy::needless_pass_by_ref_mut)]
fn resolve_container(
    context: &mut CollectContext<'_>,
    socket: SocketAddr,
    proto: Protocol,
    _pid: u32,
    process_name: &str,
    exe_name: Option<&str>,
) -> Option<docker::ContainerInfo> {
    lookup_container(context.container_map, socket, proto, process_name, exe_name).cloned()
}

fn process_executable_name(exe_path: Option<&Path>) -> Option<&str> {
    exe_path
        .and_then(Path::file_name)
        .and_then(std::ffi::OsStr::to_str)
        .filter(|name| !name.is_empty())
}

fn lookup_container<'a>(
    container_map: &'a ContainerPortMap,
    socket: SocketAddr,
    proto: Protocol,
    process_name: &str,
    exe_name: Option<&str>,
) -> Option<&'a docker::ContainerInfo> {
    // Exact match: the listener's local address matches the container's published IP.
    if let Some(container) = container_map.get(&(Some(socket.ip()), socket.port(), proto)) {
        return Some(container);
    }

    // Wildcard match: the container is mapped to a specific host IP, but the
    // OS-level listener reports 0.0.0.0 (or [::]) because the process itself
    // binds on all interfaces.
    if let Some(container) = container_map.get(&(None, socket.port(), proto)) {
        return Some(container);
    }

    // Proxy fallback: Docker Desktop Windows publishes ports via proxy
    // processes (wslrelay.exe, com.docker.backend.exe) that bind on a
    // different address than the container. When the port matches AND the
    // process is a known Docker proxy, try every container mapped to this
    // port+proto regardless of the published IP.
    if dedup::is_docker_proxy_process(process_name)
        || exe_name.is_some_and(dedup::is_docker_proxy_process)
    {
        return container_map
            .iter()
            .find(|((_, port, p), _)| *port == socket.port() && *p == proto)
            .map(|(_, container)| container);
    }

    None
}

#[cfg(target_os = "linux")]
fn rootless_podman_process_name<'a>(
    process_name: &'a str,
    exe_name: Option<&'a str>,
) -> Option<&'a str> {
    if docker::is_podman_rootlessport_process(process_name) {
        return Some(process_name);
    }
    exe_name.filter(|name| docker::is_podman_rootlessport_process(name))
}

// ── State resolution ─────────────────────────────────────────────────

fn resolve_state(l: &listeners::Listener, tcp_states: &TcpStateIndex) -> State {
    match l.protocol {
        listeners::Protocol::TCP => tcp_states.get(&l.socket).copied().unwrap_or(State::Listen),
        listeners::Protocol::UDP => State::Unknown,
    }
}

// ── Process refresh ──────────────────────────────────────────────────

/// Refresh kind for process metadata needed by enrichment.
///
/// Always collects user and executable-path metadata. Deep enrichment also
/// collects working-directory and command-line data for project detection.
fn process_refresh_kind(deep_enrichment: bool) -> ProcessRefreshKind {
    let refresh_kind = ProcessRefreshKind::nothing()
        .with_user(UpdateKind::OnlyIfNotSet)
        .with_exe(UpdateKind::OnlyIfNotSet);

    if deep_enrichment {
        refresh_kind
            .with_cwd(UpdateKind::OnlyIfNotSet)
            .with_cmd(UpdateKind::OnlyIfNotSet)
    } else {
        refresh_kind
    }
}

// ── Project cache ────────────────────────────────────────────────────

/// Look up the project root for a process, using a cache to skip repeated
/// directory walks for processes that share the same working directory.
///
/// Falls back to the executable path and then the first absolute path
/// found in the command-line arguments when cwd-based detection fails.
///
/// Accepts `Option<&Path>` to avoid allocating a `PathBuf` for every
/// process on the cache-hit path. A `PathBuf` is only allocated on a
/// cache miss when inserting the result.
///
/// `home` is the user's home directory ceiling resolved once by
/// [`collect_with_options`] and passed down to avoid repeated env-var reads.
fn lookup_project_root(
    cwd: Option<&Path>,
    exe: Option<&Path>,
    cmd: &[OsString],
    cache: &mut HashMap<PathBuf, Option<PathBuf>>,
    home: Option<&Path>,
) -> Option<PathBuf> {
    if let Some(cwd_path) = cwd
        && let Some(root) = lookup_cached_project_root(cwd_path, cache, home)
    {
        return Some(root);
    }

    if let Some(exe_path) = exe.and_then(Path::parent)
        && let Some(root) = lookup_cached_project_root(exe_path, cache, home)
    {
        return Some(root);
    }

    for cmd_path in project::absolute_cmd_parents(cmd) {
        if let Some(root) = lookup_cached_project_root(cmd_path, cache, home) {
            return Some(root);
        }
    }

    None
}

fn lookup_cached_project_root(
    start: &Path,
    cache: &mut HashMap<PathBuf, Option<PathBuf>>,
    home: Option<&Path>,
) -> Option<PathBuf> {
    let mut visited = Vec::new();

    for dir in project::walk_ancestors(start, home) {
        if let Some(cached) = cache.get(&dir).cloned() {
            for path in visited {
                cache.insert(path, cached.clone());
            }
            return cached;
        }

        visited.push(dir.clone());

        if project::has_marker(&dir) {
            let result = Some(dir);
            for path in visited {
                cache.insert(path, result.clone());
            }
            return result;
        }
    }

    for path in visited {
        cache.insert(path, None);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use tempfile::TempDir;

    #[test]
    fn container_lookup_prefers_exact_address_matches() {
        let mut map = HashMap::new();
        map.insert(
            (Some(IpAddr::V4(Ipv4Addr::LOCALHOST)), 8080, Protocol::Tcp),
            docker::ContainerInfo {
                name: "loopback-app".to_string(),
                image: "node:22".to_string(),
            },
        );

        let exact = lookup_container(
            &map,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
            Protocol::Tcp,
            "node",
            None,
        );
        assert_eq!(exact.map(|info| info.name.as_str()), Some("loopback-app"));

        let mismatch = lookup_container(
            &map,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 8080),
            Protocol::Tcp,
            "node",
            None,
        );
        assert!(
            mismatch.is_none(),
            "non-matching local addresses must not inherit container enrichment"
        );
    }

    #[test]
    fn container_lookup_uses_proxy_fallback_for_unique_port_mapping() {
        let mut map = HashMap::new();
        map.insert(
            (Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)), 5432, Protocol::Tcp),
            docker::ContainerInfo {
                name: "postgres".to_string(),
                image: "postgres:16".to_string(),
            },
        );

        let container = lookup_container(
            &map,
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 5432),
            Protocol::Tcp,
            "wslrelay.exe",
            None,
        );
        assert_eq!(container.map(|info| info.name.as_str()), Some("postgres"));
    }

    #[test]
    fn container_lookup_uses_proxy_fallback_for_rootlessport() {
        let mut map = HashMap::new();
        map.insert(
            (Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)), 6379, Protocol::Tcp),
            docker::ContainerInfo {
                name: "redis".to_string(),
                image: "redis:7-alpine".to_string(),
            },
        );

        let container = lookup_container(
            &map,
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 6379),
            Protocol::Tcp,
            "rootlessport",
            None,
        );
        assert_eq!(container.map(|info| info.name.as_str()), Some("redis"));
    }

    #[test]
    fn container_lookup_uses_exe_name_for_proxy_fallback() {
        let mut map = HashMap::new();
        map.insert(
            (Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)), 3000, Protocol::Tcp),
            docker::ContainerInfo {
                name: "web".to_string(),
                image: "node:22".to_string(),
            },
        );

        let container = lookup_container(
            &map,
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 3000),
            Protocol::Tcp,
            "truncated-helper",
            Some("wslrelay.exe"),
        );
        assert_eq!(container.map(|info| info.name.as_str()), Some("web"));
    }

    #[test]
    fn process_executable_name_uses_file_name() {
        let exe_path = Path::new("/usr/bin/google-chrome-stable");
        assert_eq!(
            process_executable_name(Some(exe_path)),
            Some("google-chrome-stable"),
            "the executable file name should be used when available"
        );
    }

    #[test]
    fn process_executable_name_ignores_empty_file_name() {
        let exe_path = Path::new("/");
        assert!(
            process_executable_name(Some(exe_path)).is_none(),
            "paths without a usable file name should be ignored"
        );
    }

    #[test]
    fn project_root_cache_learns_visited_ancestors() {
        let root = TempDir::new().unwrap();
        fs::write(root.path().join("Cargo.toml"), "").unwrap();

        let first = root.path().join("src").join("db");
        let second = root.path().join("src").join("utils");
        fs::create_dir_all(&first).unwrap();
        fs::create_dir_all(&second).unwrap();

        let mut cache = HashMap::new();

        let first_result = lookup_cached_project_root(&first, &mut cache, None);
        assert_eq!(first_result.as_deref(), Some(root.path()));
        assert_eq!(
            cache.get(first.as_path()).and_then(Option::as_deref),
            Some(root.path()),
            "the original cwd should be cached"
        );
        assert_eq!(
            cache
                .get(first.parent().unwrap())
                .and_then(Option::as_deref),
            Some(root.path()),
            "visited ancestors should also be cached"
        );

        let second_result = lookup_cached_project_root(&second, &mut cache, None);
        assert_eq!(second_result.as_deref(), Some(root.path()));
        assert_eq!(
            cache.get(second.as_path()).and_then(Option::as_deref),
            Some(root.path()),
            "sibling directories should learn from the cached ancestor"
        );
    }

    #[test]
    fn project_root_cache_does_not_poison_unrelated_ancestors() {
        let workspace = TempDir::new().unwrap();
        let outer = workspace.path().join("workspace");
        let project_root = outer.join("app");
        let inside = project_root.join("src").join("db");
        let unrelated = outer.join("services").join("worker");

        fs::create_dir_all(&inside).unwrap();
        fs::create_dir_all(&unrelated).unwrap();
        fs::write(project_root.join("Cargo.toml"), "").unwrap();

        let mut cache = HashMap::new();

        let first_result = lookup_cached_project_root(&inside, &mut cache, None);
        assert_eq!(first_result.as_deref(), Some(project_root.as_path()));
        assert!(
            !cache.contains_key(outer.as_path()),
            "ancestors above the discovered project root must not be cached as project hits"
        );

        let unrelated_result = lookup_cached_project_root(&unrelated, &mut cache, None);
        assert!(
            unrelated_result.is_none(),
            "an unrelated path under the same ancestor must not inherit another project's root"
        );
    }

    #[test]
    fn lookup_project_root_prefers_exe_parent_before_cmd_paths() {
        let workspace = TempDir::new().unwrap();
        let exe_root = workspace.path().join("service");
        let cmd_root = workspace.path().join("tooling");
        let exe_path = exe_root.join("bin").join("service.exe");
        let cmd_path = cmd_root.join("scripts").join("launcher.py");

        fs::create_dir_all(exe_path.parent().unwrap()).unwrap();
        fs::create_dir_all(cmd_path.parent().unwrap()).unwrap();
        fs::write(exe_root.join("Cargo.toml"), "").unwrap();
        fs::write(cmd_root.join("pyproject.toml"), "").unwrap();
        fs::write(&exe_path, "").unwrap();
        fs::write(&cmd_path, "").unwrap();

        let cmd = vec![OsString::from(&cmd_path)];
        let mut cache = HashMap::new();

        let result = lookup_project_root(None, Some(&exe_path), &cmd, &mut cache, None);
        assert_eq!(
            result.as_deref(),
            Some(exe_root.as_path()),
            "the executable path should win before command-line argument scanning"
        );
    }
}
