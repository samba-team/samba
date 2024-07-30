use std::env;
use std::path::{Path, PathBuf};

fn main() {
    cc::Build::new()
        .file("../../source3/lib/version.c")
        .include(Path::new("../../bin/default"))
        .include(Path::new("./include")) // for the empty includes.h
        .warnings(false)
        .compile("version");

    let bindings = bindgen::Builder::default()
        .blocklist_function("qgcvt")
        .blocklist_function("qgcvt_r")
        .blocklist_function("qfcvt")
        .blocklist_function("qfcvt_r")
        .blocklist_function("qecvt")
        .blocklist_function("qecvt_r")
        .blocklist_function("strtold")
        .header("../../bin/default/version.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
