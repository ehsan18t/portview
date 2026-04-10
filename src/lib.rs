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

pub mod collector;
pub mod display;
pub mod docker;
pub mod filter;
pub mod framework;
pub mod project;
pub mod types;
