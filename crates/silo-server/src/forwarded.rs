//! Replaces the peer address with the client address named by
//! `X-Forwarded-For`, when the peer is a configured trusted proxy.
//!
//! Every handler reads the client address from the `ConnectInfo` extension,
//! so rewriting it once, before routing, makes the audit log record the
//! real client on every surface (HTTP, gRPC and the admin gateway).

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, Request, State};
use axum::middleware::Next;
use axum::response::Response;
use silo_core::proxies::TrustedProxies;

pub async fn apply(
    State(proxies): State<Arc<TrustedProxies>>,
    mut request: Request,
    next: Next,
) -> Response {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| *addr);
    if let Some(peer) = peer {
        let values = request
            .headers()
            .get_all("x-forwarded-for")
            .iter()
            // A field that is not valid text becomes an empty hop, which does
            // not parse as an address and so ends the walk there.
            .map(|v| v.to_str().unwrap_or(""));
        if let Some(client) = proxies.client_ip(peer.ip(), values) {
            let addr = SocketAddr::new(client, peer.port());
            request.extensions_mut().insert(ConnectInfo(addr));
            // gRPC handlers read the peer from tonic's extension, which was
            // filled in from the transport peer before this ran.
            request
                .extensions_mut()
                .insert(tonic::transport::server::TcpConnectInfo {
                    local_addr: None,
                    remote_addr: Some(addr),
                });
        }
    }
    next.run(request).await
}
