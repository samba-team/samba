use std::env;
use std::path::Path;
use std::path::PathBuf;

fn main() {
    cc::Build::new()
        .file("src/sss_idmap.c")
        .file("src/sss_idmap_conv.c")
        .file("src/murmurhash3.c")
        .include(Path::new("../../bin/default/include"))
        .warnings(false)
        .compile("sss_idmap");

    let bindings = bindgen::Builder::default()
        .blocklist_function("qgcvt")
        .blocklist_function("qgcvt_r")
        .blocklist_function("qfcvt")
        .blocklist_function("qfcvt_r")
        .blocklist_function("qecvt")
        .blocklist_function("qecvt_r")
        .blocklist_function("strtold")
        .header("src/sss_idmap.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
    println!("cargo:rustc-link-lib=utf8proc");
    println!("cargo:rustc-env=LD_LIBRARY_PATH=../../bin/shared/private/");
}
