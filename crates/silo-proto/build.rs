fn main() {
    // Every generated type is also (de)serializable as JSON. The web admin
    // console's gateway (`silo-server`'s `webui::gateway`) speaks JSON to the
    // browser and calls the same service implementations the gRPC clients
    // reach, so the wire types are the single source of truth for both.
    //
    // `serde(default)` lets a request omit any field, the way protobuf does;
    // enums travel as their integer values.
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
        .message_attribute(".", "#[serde(default)]")
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
