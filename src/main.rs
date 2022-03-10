mod cleartext_holder;
mod enums;
mod external_commands;
mod password_store;

use clap::{App, AppSettings, Arg};
use std::io::Write;

use crate::cleartext_holder::CleartextHolderInterface;
use crate::enums::RadomskoError;
use crate::enums::ShowDestination;
use crate::password_store::PasswordStoreInterface;

const CLIPBOARD_CLEAR_TIMER: u64 = 13;

struct CommandRunner {
    password_store: PasswordStoreInterface,
}

fn wait_and_clear_clipboard(target: &str) {
    println!(
        "Clipped ``{};'' clearing in {}s",
        target, CLIPBOARD_CLEAR_TIMER
    );
    ctrlc::set_handler(move || {
        eprintln!("Interrupted");
        external_commands::clear_clipboard().expect("Error clearing clipboard");
        std::process::exit(1);
    })
    .expect("Error setting signal handler");
    std::thread::sleep(std::time::Duration::from_secs(CLIPBOARD_CLEAR_TIMER));
    external_commands::clear_clipboard().expect("Error clearing clipboard");
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

    pub fn show(&self, target: &str, dest: ShowDestination) -> Result<(), RadomskoError> {
        // If a tree can be drawn at all (i.e. `target` is ambiguous),
        // then we leave it at that.
        if let Ok(render) = self.password_store.draw_tree(target, "") {
            println!("{}", render);
            return Ok(());
        }

        let path = self.password_store.path_for(target)?;
        if !path.is_file() {
            return Err(RadomskoError::NotFound);
        }
        external_commands::decrypt_password(path.as_path(), dest)?;
        if dest == ShowDestination::Clip {
            wait_and_clear_clipboard(target);
        }
        Ok(())
    }
}

pub fn main_impl() -> Result<(), RadomskoError> {
    let matches = App::new("radomsko")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .about("interacts with your password store")
        .version("0.2.1")
        .author("j39m")
        .subcommand(
            App::new("show")
                .about("decrypts passwords (or shows subdirectories)")
                .arg(Arg::new("target").help("optional: password or subdirectory"))
                .arg(
                    Arg::new("clip")
                        .conflicts_with("qr")
                        .help("sends cleartext to clipboard")
                        .short('c'),
                )
                .arg(
                    Arg::new("qr")
                        .conflicts_with("clip")
                        .help("displays cleartext as QR code (dangerous!)")
                        .short('q'),
                ),
        )
        .subcommand(
            App::new("edit")
                .about("edits passwords")
                .arg(Arg::new("target").help("password to edit").required(true)),
        )
        .subcommand(
            App::new("find")
                .about("searches password store")
                .arg(Arg::new("keyword").help("search term").required(true)),
        )
        .get_matches();

    let command_runner = CommandRunner::new()?;
    match matches.subcommand_name() {
        Some("show") => {
            let submatches = matches.subcommand_matches("show").unwrap();
            let dest = if submatches.is_present("clip") {
                ShowDestination::Clip
            } else if submatches.is_present("qr") {
                ShowDestination::QrCode
            } else {
                ShowDestination::Stdout
            };
            Ok(command_runner.show(submatches.value_of("target").unwrap_or(""), dest)?)
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
