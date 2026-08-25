pub mod auth;
pub mod grpc;
pub mod http;

use silo_core::{Config, Storage};

pub struct AppState {
    pub config: Config,
    pub storage: Storage,
}
