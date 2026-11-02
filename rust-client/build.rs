fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        if let Err(e) = winresource::WindowsResource::new().set_icon("assets/icon.ico").compile() {
            println!("cargo:warning=icon embed failed: {}", e);
        }
    }
}
