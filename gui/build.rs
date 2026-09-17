fn main() {
    println!("cargo:rerun-if-changed=assets/plaine.ico");

    let target_os =
        std::env::var("CARGO_CFG_TARGET_OS")
            .unwrap_or_default();

    if target_os == "windows" {
        let mut res =
            winresource::WindowsResource::new();

        res.set_icon("assets/plaine.ico");

        res.set(
            "ProductName",
            "Pla(i)n[e] GUI Wallet",
        );

        res.set(
            "FileDescription",
            "Pla(i)n[e] GUI Wallet",
        );

        res.set(
            "CompanyName",
            "Aquacongas",
        );

        res.compile()
            .expect(
                "failed to compile Windows resources"
            );
    }
}
