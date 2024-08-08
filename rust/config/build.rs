use std::env;
use std::path::PathBuf;

fn main() {
    let header = "../../bin/default/include/config.h";
    println!("cargo:rerun-if-changed={}", header);
    let additions_header = "./additions.h";
    println!("cargo:rerun-if-changed={}", additions_header);

    let bindings = bindgen::Builder::default()
        .header(additions_header)
        .header(header)
        .generate()
        .expect("Failed generating config bindings!");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
