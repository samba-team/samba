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
        .clang_arg("-includesys/stat.h")
        .header("../../lib/tdb/include/tdb.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    let mut src_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    src_dir.push("../../bin/default/lib/tdb");
    if config::USING_SYSTEM_TDB == 1 {
        println!("cargo:rustc-link-lib=tdb");
    } else {
        println!("cargo:rustc-link-lib=tdb-private-samba");
    }
    println!(
        "cargo:rustc-link-search=native={}",
        src_dir.to_str().unwrap()
    );
}
