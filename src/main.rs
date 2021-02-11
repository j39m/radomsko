mod cleartext_holder;
mod errors;
mod external_commands;
mod password_store;

use clap::{App, AppSettings, Arg};

use crate::errors::RadomskoError;
use crate::password_store::*;

fn subcommand_not_implemented() {
    eprintln!("This subcommand is not implemented.");
    std::process::exit(1);
}

struct CommandRunner {
    password_store: PasswordStoreInterface,
}

impl CommandRunner {
    pub fn new() -> Result<CommandRunner, RadomskoError> {
        Ok(CommandRunner {
            password_store: PasswordStoreInterface::new("", true)?,
        })
    }

    pub fn find(&self, search_term: &str) -> Result<(), RadomskoError> {
        Ok(println!(
            "{}",
            self.password_store.draw_tree("", search_term)?
        ))
    }

    pub fn show(&self, target: &str, clip: bool) -> Result<(), RadomskoError> {
        match self.password_store.draw_tree(target, "") {
            Ok(render) => {
                println!("{}", render);
                return Ok(());
            }
            Err(_) => (),
        }

        let path = self.password_store.path_for(target)?;
        external_commands::decrypt_password(path.to_str().unwrap(), clip)?;
        if clip {
            println!("clipped ``{}''", target);
        }
        Ok(())
    }
}

pub fn main_impl() -> Result<(), RadomskoError> {
    let matches = App::new("radomsko")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .about("interacts with your password store")
        .version("0.1.0")
        .author("j39m")
        .subcommand(
            App::new("show")
                .about("decrypts passwords (or shows subdirectories)")
                .arg(Arg::with_name("target").help("optional: password or subdirectory"))
                .arg(
                    Arg::with_name("clip")
                        .help("sends cleartext to clipboard")
                        .short("c"),
                ),
        )
        .subcommand(App::new("edit").about("edits passwords"))
        .subcommand(
            App::new("find")
                .about("searches password store")
                .arg(Arg::with_name("keyword").help("search term").required(true)),
        )
        .get_matches();

    let command_runner = CommandRunner::new()?;
    match matches.subcommand_name() {
        Some("show") => {
            let submatches = matches.subcommand_matches("show").unwrap();
            Ok(command_runner.show(
                submatches.value_of("target").unwrap_or(""),
                submatches.is_present("clip"),
            )?)
        }
        Some("edit") => Ok(subcommand_not_implemented()),
        Some("find") => Ok(command_runner.find(
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
