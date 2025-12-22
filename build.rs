fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Compile the protobuf definitions
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .out_dir("src/proto")
        .compile_protos(&["proto/sequencer.proto"], &["proto"])?;

    println!("cargo:rerun-if-changed=proto/sequencer.proto");

    Ok(())
}
