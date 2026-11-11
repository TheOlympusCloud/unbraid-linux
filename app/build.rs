// The engine's gRPC services from the same .proto files the engine is built with, compiled without protoc; the UI.
fn main() {
    let files = [
        "proto/daemon/started_service.proto",
        "proto/daemon/managed_service.proto",
        "proto/boxdd/desktop_service.proto",
    ];
    for f in files {
        println!("cargo:rerun-if-changed={f}");
    }
    let fds = protox::compile(files, ["proto"]).expect("compile the engine's .proto files");
    tonic_prost_build::configure().build_server(false).compile_fds(fds).expect("generate the engine client");
    slint_build::compile("ui/app.slint").expect("compile the UI");
}
