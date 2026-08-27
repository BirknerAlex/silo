#[allow(clippy::result_large_err)] // tonic-generated client/server methods return tonic::Status errors; not ours to shrink
pub mod v1 {
    tonic::include_proto!("silo.v1");
}
