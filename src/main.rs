mod errors;
mod filesystem;

use clap::{App, AppSettings, Arg};

use crate::errors::RadomskoError;

fn subcommand_not_implemented() {
    eprintln!("This subcommand is not implemented.");
    std::process::exit(1);
}

fn subcommand_find(search_term: &str) -> Result<(), RadomskoError> {
    let interface = filesystem::PasswordStoreInterface::new("", true)?;
    Ok(println!("{}", interface.draw_tree("", search_term)?))
}

fn main_impl() -> Result<(), RadomskoError> {
    let matches = App::new("radomsko")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .about("interacts with your password store")
        .version("0.1.0")
        .author("j39m")
        .subcommand(App::new("show").about("decrypts passwords"))
        .subcommand(App::new("edit").about("edits passwords"))
        .subcommand(
            App::new("find")
                .about("searches password store")
                .arg(Arg::with_name("keyword").help("search term").required(true)),
        )
        .get_matches();

    match matches.subcommand_name() {
        Some("show") => Ok(subcommand_not_implemented()),
        Some("edit") => Ok(subcommand_not_implemented()),
        Some("find") => Ok(subcommand_find(
            matches
                .subcommand_matches("find")
                .unwrap()
                .value_of("keyword")
                .unwrap(),
        )?),
        _ => panic!("BUG: unhandled subcommand"),
    }
}

fn main() {
    match main_impl() {
        Ok(_) => (),
        Err(e) => {
            eprintln!("Error: {:#?}", e);
            std::process::exit(1);
        }
    }
}
