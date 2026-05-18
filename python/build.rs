fn main() {
    // On macOS with homebrew Python, ensure the framework is linked properly
    // for abi3 mode
    if cfg!(target_os = "macos") {
        // Tell cargo to link against the Python framework
        println!("cargo:rustc-link-arg=-Wl,-undefined,suppress");
        println!("cargo:rustc-link-arg=-Wl,-flat_namespace");
    }
}
