fn main() {
    // prost-build needs protoc; use the vendored binary so no system install is required.
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("vendored protoc");
    std::env::set_var("PROTOC", protoc);

    prost_build::compile_protos(&["proto/brave_sync.proto"], &["proto/"])
        .expect("compile brave_sync.proto");
    println!("cargo:rerun-if-changed=proto/brave_sync.proto");
}
