//! `runtimed`: the read-only [`rt_api::Runtime`] served as JSON-RPC 2.0 over an owner-only Unix socket.
//! [`protocol`] is the wire format and its limits, [`dispatch`] the method table, [`server`] the socket, the
//! peer check, the connection limits and shutdown.
pub mod protocol;
