fn main() {
    println!("cargo:rustc-env=LD_LIBRARY_PATH=../../bin/shared:../../bin/shared/private/");
}
