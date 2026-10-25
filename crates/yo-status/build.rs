fn main() {
    // The deploy scripts export YO_GIT_SHA; rebuild when it changes.
    println!("cargo:rerun-if-env-changed=YO_GIT_SHA");
    let sha = std::env::var("YO_GIT_SHA").unwrap_or_default();
    println!("cargo:rustc-env=YO_BUILD_SHA={sha}");
}
