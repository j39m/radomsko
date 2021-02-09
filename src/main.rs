mod errors;
pub mod filesystem;

fn subcommand_not_implemented() {
    eprintln!("This subcommand is not implemented.");
    std::process::exit(1);
}

fn main() {
    let matches = clap::App::new("radomsko")
        .setting(clap::AppSettings::SubcommandRequiredElseHelp)
        .about("interacts with your password store")
        .version("0.1.0")
        .author("j39m")
        .subcommand(clap::App::new("show").about("decrypts passwords"))
        .subcommand(clap::App::new("edit").about("edits passwords"))
        .subcommand(clap::App::new("find").about("searches password store")).get_matches();

    match matches.subcommand_name() {
        Some("show") => return subcommand_not_implemented(),
        Some("edit") => return subcommand_not_implemented(),
        Some("find") => return subcommand_not_implemented(),
        _ => panic!("BUG: unhandled subcommand"),
    }
}
