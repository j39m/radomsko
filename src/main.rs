mod cleartext_holder;
mod errors;
mod external_commands;
mod password_store;

use clap::{App, AppSettings, Arg};
use std::io::Write;

use crate::cleartext_holder::CleartextHolderInterface;
use crate::errors::RadomskoError;
use crate::password_store::PasswordStoreInterface;

struct CommandRunner {
    password_store: PasswordStoreInterface,
}

impl CommandRunner {
    pub fn new() -> Result<CommandRunner, RadomskoError> {
        Ok(CommandRunner {
            password_store: PasswordStoreInterface::new("", true)?,
        })
    }

    fn get_encrypted_edited_password(&self, target: &str) -> Result<Vec<u8>, RadomskoError> {
        let cleartext_holder = CleartextHolderInterface::new("")?;
        let target_path = self.password_store.path_for(target)?;
        let mut cleartext_tempfile = cleartext_holder.new_entry()?;

        let password_exists = target_path.is_file();
        if password_exists {
            let cleartext_password =
                external_commands::decrypt_password_to_string(target_path.as_path())?;
            cleartext_tempfile
                .as_file_mut()
                .write_all(cleartext_password.as_bytes())?;
            cleartext_tempfile.as_file_mut().sync_data()?;
        }

        external_commands::invoke_editor(cleartext_tempfile.path())?;
        external_commands::encrypt_cleartext(cleartext_tempfile.path())?;
        let encrypted =
            CleartextHolderInterface::encrypted_contents_for(cleartext_tempfile.path())?;
        cleartext_holder.remove_encrypted_output_of(cleartext_tempfile.path())?;

        Ok(encrypted)
    }

    pub fn edit(&self, target: &str) -> Result<(), RadomskoError> {
        let encrypted = self.get_encrypted_edited_password(target)?;

        let target_path = self.password_store.path_for(target)?;
        Ok(std::fs::write(target_path, encrypted)?)
    }

    pub fn find(&self, search_term: &str) -> Result<(), RadomskoError> {
        Ok(println!(
            "{}",
            self.password_store.draw_tree("", search_term)?
        ))
    }

    pub fn show(&self, target: &str, clip: bool) -> Result<(), RadomskoError> {
        if let Ok(render) = self.password_store.draw_tree(target, "") {
            println!("{}", render);
            return Ok(());
        }

        let path = self.password_store.path_for(target)?;
        external_commands::decrypt_password(path.as_path(), clip)?;
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
        .subcommand(
            App::new("edit").about("edits passwords").arg(
                Arg::with_name("target")
                    .help("password to edit")
                    .required(true),
            ),
        )
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
        Some("edit") => Ok(command_runner.edit(
            matches
                .subcommand_matches("edit")
                .unwrap()
                .value_of("target")
                .unwrap(),
        )?),
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
