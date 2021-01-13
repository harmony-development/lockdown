fn main() {
    let mut config = prost_build::Config::new();
    config.compile_protos(
        &[
            "secret/secret.proto",
            "secret/state.proto",
            "secret/keys.proto",
            "secret/encrypted.proto",
            "secret/messages.proto",
        ],
        &[
            "src/protocol",
        ],
    ).expect("Protobuf code generation failed");
}