//! Compose the `--version` line at build time so it can be a `const` in the
//! binary. The release workflow sets `KSEAL_GIT_SHA` to the built commit; a
//! plain local build leaves it unset and the line carries only the crate
//! version. `rerun-if-env-changed` makes a changed SHA actually rebuild, which a
//! bare `option_env!` in the source would not.

fn main() {
    println!("cargo:rerun-if-env-changed=KSEAL_GIT_SHA");
    let package_version = std::env::var("CARGO_PKG_VERSION").expect("cargo sets CARGO_PKG_VERSION");
    let version = match std::env::var("KSEAL_GIT_SHA") {
        Ok(sha) if !sha.is_empty() => format!("kseal {package_version} ({sha})"),
        _ => format!("kseal {package_version}"),
    };
    println!("cargo:rustc-env=KSEAL_VERSION={version}");
}
