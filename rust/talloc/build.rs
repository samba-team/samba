use std::env;
use std::path::PathBuf;

fn main() {
    let bindings = bindgen::Builder::default()
        .blocklist_function("qgcvt")
        .blocklist_function("qgcvt_r")
        .blocklist_function("qfcvt")
        .blocklist_function("qfcvt_r")
        .blocklist_function("qecvt")
        .blocklist_function("qecvt_r")
        .blocklist_function("strtold")
        .clang_arg("-Dbool=int")
        .generate_comments(false)
        .clang_arg("-I../../lib/talloc")
        .header("../../lib/util/talloc_stack.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");
    println!("cargo:rerun-if-changed=../../lib/util/talloc_stack.h");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    let mut src_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    src_dir.push("../../bin/default/lib/talloc");
    if config::USING_SYSTEM_TALLOC == 1 {
        println!("cargo:rustc-link-lib=talloc");
    } else {
        println!("cargo:rustc-link-lib=talloc-private-samba");
    }
    println!(
        "cargo:rustc-link-search=native={}",
        src_dir.to_str().unwrap()
    );
}
