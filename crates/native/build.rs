use std::env;

fn main() {
    let mut build = cc::Build::new();
    build.cpp(false)
        .std("c11")
        .warnings(true)
        .warnings_into_errors(true)
        .include("../../include")
        .include("c")
        .file("c/library.c")
        .file("c/module.c")
        .file("c/process.c");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux") {
        build.define("_GNU_SOURCE", None);
        println!("cargo:rustc-link-lib=dl");
    }

    build.compile("naga_native");

    for source in ["c/library.c", "c/module.c", "c/process.c", "c/naga_native.h", "../../include/naga.h"] {
        println!("cargo:rerun-if-changed={source}");
    }
}
