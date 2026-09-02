fn main() {
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(
            &[
                "../../proto/silo/v1/publish.proto",
                "../../proto/silo/v1/auth.proto",
                "../../proto/silo/v1/admin.proto",
            ],
            &["../../proto"],
        )
        .expect("failed to compile silo.v1 protos");
}
