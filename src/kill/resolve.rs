//! Resolve a local port number to the set of unique PIDs using it.
//!
//! Reuses the socket collector so every platform-specific detail (IPv4/IPv6
//! duplication, `SO_REUSEPORT` workers, Docker userland-proxy collapsing) is
//! handled in one place.
//!
//! When a port is owned by a Docker/Podman container, the resolver creates
//! a [`ContainerTarget`] instead of a process target so the kill flow can
//! stop the container via the daemon API rather than killing the proxy PID.

use anyhow::Result;
use log::debug;

use crate::collector::{self, CollectOptions};
use crate::docker::{self, ContainerPortMap};

/// A PID/process-name pair for one target of a kill request.
#[derive(Debug, Clone)]
pub struct Target {
    /// OS process identifier.
    pub pid: u32,
    /// Best-effort process name, "-" if unknown.
    pub process: String,
}

/// A Docker/Podman container to stop via the daemon API.
#[derive(Debug, Clone)]
pub struct ContainerTarget {
    /// Container identifier for API calls (full hex ID or name).
    pub container_id: String,
    /// Human-readable container name.
    pub container_name: String,
    /// The host port being freed.
    pub port: u16,
    /// PID of the Docker/Podman proxy process on the host.
    pub proxy_pid: u32,
    /// Name of the proxy process (e.g. "docker-proxy").
    pub proxy_process: String,
}

/// A resolved target that is either a process or a container.
#[derive(Debug, Clone)]
pub enum ResolvedTarget {
    /// A regular OS process to be signaled.
    Process(Target),
    /// A container to be stopped via the Docker/Podman daemon API.
    Container(ContainerTarget),
}

/// Enumerate targets owning sockets on `port`.
///
/// Runs Docker/Podman detection in parallel with port enumeration. When
/// the listening process is a known Docker proxy and the daemon reports a
/// container for that port, the resolver yields a [`ContainerTarget`].
/// Otherwise it produces a regular process [`Target`].
pub fn targets_for_port(port: u16) -> Result<Vec<ResolvedTarget>> {
    // Start Docker detection early so it overlaps with socket enumeration.
    let docker_handle = docker::start_detection();

    let entries = collector::collect_with_options(&CollectOptions {
        deep_enrichment: false,
    })?;

    let container_map = docker::await_detection(docker_handle);

    let mut seen_pids: std::collections::HashSet<u32> = std::collections::HashSet::new();
    let mut seen_containers: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut targets = Vec::new();

    for entry in entries {
        if entry.port != port {
            continue;
        }
        // Skip duplicate PIDs (same process on IPv4 + IPv6).
        if !seen_pids.insert(entry.pid) {
            continue;
        }

        let process_name = entry.process.as_ref();

        // When the process is a known Docker proxy and we have container
        // info for this port, prefer stopping the container via API.
        if collector::is_docker_proxy_process(process_name)
            && let Some(ct) = container_target_for_port(&container_map, port, &entry)
        {
            // Dedup by container to avoid sending stop twice when the
            // proxy listens on both IPv4 and IPv6 with different PIDs.
            if seen_containers.insert(ct.container_id.clone()) {
                debug!(
                    "resolved port {port} to container '{}' (proxy pid {})",
                    ct.container_name, ct.proxy_pid
                );
                targets.push(ResolvedTarget::Container(ct));
            }
            continue;
        }

        targets.push(ResolvedTarget::Process(Target {
            pid: entry.pid,
            process: process_name.to_owned(),
        }));
    }
    Ok(targets)
}

/// Try to find a container mapping for the given port and build a target.
fn container_target_for_port(
    map: &ContainerPortMap,
    port: u16,
    entry: &crate::types::PortEntry,
) -> Option<ContainerTarget> {
    // Find any container that publishes this port.
    let info = map
        .iter()
        .find(|((_, p, _), _)| *p == port)
        .map(|(_, info)| info)?;

    // Use the container ID if available, otherwise fall back to the name.
    let api_id = if info.id.is_empty() {
        info.name.clone()
    } else {
        info.id.clone()
    };

    Some(ContainerTarget {
        container_id: api_id,
        container_name: info.name.clone(),
        port,
        proxy_pid: entry.pid,
        proxy_process: entry.process.as_ref().to_owned(),
    })
}

/// Resolve a PID by itself: look up its process name if possible.
///
/// Returns a synthetic target with "-" process name when the PID is not
/// currently enumerable (the kill path still treats that as `AlreadyGone` later).
pub fn target_for_pid(pid: u32) -> Target {
    use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};

    let mut sys = System::new();
    let sys_pid = Pid::from_u32(pid);
    sys.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[sys_pid]),
        false,
        ProcessRefreshKind::nothing(),
    );
    let process = sys.process(sys_pid).map_or_else(
        || "-".to_owned(),
        |p| p.name().to_string_lossy().into_owned(),
    );
    Target { pid, process }
}
