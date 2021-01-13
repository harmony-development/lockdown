fn main() {
    let mut config = prost_build::Config::new();
    config.compile_protos(
        &[
            "secret/v1/secret.proto",
            "secret/v1/state.proto",
            "secret/v1/keys.proto",
            "secret/v1/encrypted.proto",
            "secret/v1/messages.proto",
        ],
        &[
            "src/protocol",
        ],
    ).expect("Protobuf code generation failed");
}