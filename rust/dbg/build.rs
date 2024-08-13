use std::env;
use std::path::PathBuf;

fn main() {
    let bindings = bindgen::Builder::default()
        .header("../../lib/util/debug.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    let mut src_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    src_dir.push("../../bin/default/lib/util");
    println!(
        "cargo:rustc-link-search=native={}",
        src_dir.to_str().unwrap()
    );
    println!("cargo:rustc-link-lib=samba-debug-private-samba");
    println!("cargo:rustc-link-lib=samba-util");
    println!("cargo:rustc-env=LD_LIBRARY_PATH=../../bin/shared:../../bin/shared/private/");
}
