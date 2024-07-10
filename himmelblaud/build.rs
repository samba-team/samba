use std::env;

fn main() {
    // Re-export the Target OS, so that Himmelblaud has access to this at
    // runtime.
    if &env::var("CARGO_CFG_TARGET_OS").unwrap() != "none" {
        println!(
            "cargo:rustc-env=TARGET_OS={}",
            &env::var("CARGO_CFG_TARGET_OS").unwrap()
        );
    } else {
        println!(
            "cargo:rustc-env=TARGET_OS={}",
            &env::var("CARGO_CFG_TARGET_FAMILY").unwrap()
        );
    }
    println!("cargo:rerun-if-changed-env=TARGET");
}
