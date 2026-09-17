#![forbid(unsafe_code)]

use plaine_wallet::ui::Streams;

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();

    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let stderr = std::io::stderr();
    let mut err = stderr.lock();

    let code = {
        let mut s = Streams::new(&mut input, &mut out, &mut err);
        plaine_wallet::wallet_cli::run(&argv, &mut s)
    };

    if code == 0
        && matches!(
            argv.first().map(String::as_str),
            Some("version" | "--version")
        )
    {
        println!("{}", env!("PLAINE_BUILD_LINE"));
    }

    use std::io::Write;
    let _ = out.flush();
    let _ = err.flush();
    std::process::exit(code);
}
