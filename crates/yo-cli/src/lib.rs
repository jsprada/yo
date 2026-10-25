//! The `yo` client: engine ([`client`]), networking, agent/daemon and the
//! terminal interface used by the `yo` binary.

pub mod agent;
pub mod client;
pub mod daemon;
pub mod net;
pub mod payload;
pub mod prompt;
pub mod service;
pub mod ui;
