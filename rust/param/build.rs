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
        .clang_arg("-Doffset_t=loff_t")
        .clang_arg("-I../../bin/default")
        .clang_arg("-I../../lib/talloc")
        .generate_comments(false)
        .clang_arg("-includestdint.h")
        .header("../../lib/param/param.h")
        .header("../../lib/param/loadparm.h")
        .header("../../source3/param/loadparm.h")
        .header("../../bin/default/lib/param/param_functions.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");
    println!("cargo:rerun-if-changed=../../lib/param/param.h");
    println!("cargo:rerun-if-changed=../../lib/param/loadparm.h");
    println!("cargo:rerun-if-changed=../../source3/param/loadparm.h");
    println!(
        "cargo:rerun-if-changed=../../bin/default/lib/param/param_functions.h"
    );

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    let mut src_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    src_dir.push("../../bin/default/source3");
    println!(
        "cargo:rustc-link-search=native={}",
        src_dir.to_str().unwrap()
    );
    println!("cargo:rustc-link-lib=smbconf");

    let mut src_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    src_dir.push("../../bin/default/lib/param");
    println!("cargo:rustc-link-lib=samba-hostconfig-private-samba");
    println!(
        "cargo:rustc-link-search=native={}",
        src_dir.to_str().unwrap()
    );
}
