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

    if let Some(vers) = version::samba_version_string() {
        println!("cargo:rustc-env=CARGO_PKG_VERSION={}", vers);
    }
    println!(
        "cargo:rustc-env=CARGO_PKG_VERSION_MAJOR={}",
        version::SAMBA_VERSION_MAJOR
    );
    println!(
        "cargo:rustc-env=CARGO_PKG_VERSION_MINOR={}",
        version::SAMBA_VERSION_MINOR
    );
    println!(
        "cargo:rustc-env=CARGO_PKG_VERSION_PATCH={}",
        version::SAMBA_VERSION_RELEASE
    );
}
