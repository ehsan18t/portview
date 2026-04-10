//! # portview
//!
//! A cross-platform CLI tool that lists open network ports and their associated
//! processes. Provides a fast, readable alternative to `netstat` and `ss`.
//!
//! ## Module structure
//!
//! - [`types`] - `PortEntry` struct and shared enums
//! - [`collector`] - socket enumeration + process/project/app enrichment
//! - [`filter`] - CLI filters and developer-relevance filter
//! - [`display`] - renders results as bordered/compact table or JSON
//! - [`docker`] - Docker/Podman container detection via socket API
//! - [`project`] - project root detection via marker file walk
//! - [`framework`] - app/framework detection from images, configs, process names
//!
//! ## Thread safety
//!
//! [`collector::collect`] spawns background threads to probe the
//! Docker/Podman daemon. Those threads are **not** joined on return.
//! This is intentional for a short-lived CLI process, but makes the
//! function unsuitable for long-running daemons or services: if the
//! Docker socket blocks, the probe thread will leak. Callers embedding
//! this crate in a persistent service should add their own timeout
//! wrapper around [`collector::collect`].

pub mod collector;
pub mod display;
pub mod docker;
pub mod filter;
pub mod framework;
pub mod project;
pub mod types;
