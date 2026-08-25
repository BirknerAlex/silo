fn main() {
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["../../proto/silo/v1/publish.proto"], &["../../proto"])
        .expect("failed to compile silo.v1 protos");
}
