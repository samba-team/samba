fn main() {
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
    println!("cargo:rustc-env=LD_LIBRARY_PATH=../../bin/shared:../../bin/shared/private/");
}
