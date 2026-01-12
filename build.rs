fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Compile the protobuf definitions - v1 and v2 protocols
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .out_dir("src/proto")
        .compile_protos(
            &[
                "proto/sequencer.proto",      // v1 - existing protocol
                "proto/sequencer_v2.proto",   // v2 - VES v1.0 with streaming
            ],
            &["proto"],
        )?;

    println!("cargo:rerun-if-changed=proto/sequencer.proto");
    println!("cargo:rerun-if-changed=proto/sequencer_v2.proto");

    Ok(())
}
