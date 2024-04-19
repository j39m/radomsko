mod cleartext_holder;
mod enums;
mod external_commands;
mod password_store;

use std::io::Write;

use crate::cleartext_holder::CleartextHolderInterface;
use crate::enums::RadomskoError;
use crate::enums::ShowDestination;
use crate::password_store::PasswordStoreInterface;

const CLIPBOARD_CLEAR_TIMER: u64 = 13;

use clap::Parser;

#[derive(clap::Parser)]
#[command(name = "radomsko", version = "0.2.2", about = "`pass` mimic")]
struct Cli {
    #[command(subcommand)]
    subcommand: Subcommand,
}

#[derive(clap::Subcommand)]
enum Subcommand {
    Edit(EditArgs),
    Find(FindArgs),
    Show(ShowArgs),
}

#[derive(clap::Args)]
struct EditArgs {
    #[arg(help = "target")]
    target: std::path::PathBuf,
}

#[derive(clap::Args)]
struct FindArgs {
    #[arg(help = "keyword")]
    keyword: std::path::PathBuf,
}

#[derive(clap::Args)]
struct ShowArgs {
    #[arg(help = "(optional) target")]
    target: Option<std::path::PathBuf>,
    #[command(flatten)]
    show_to: Option<ShowTo>,
}

#[derive(clap::Args)]
#[group(required = false, multiple = false)]
struct ShowTo {
    #[arg(short, help = "copy to clipboard")]
    clip: bool,
    #[arg(short, help = "show QR code")]
    qrcode: bool,
}

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
            let _ = external_commands::switch_workspace();
            wait_and_clear_clipboard(target);
        }
        Ok(())
    }
}

pub fn main_impl() -> Result<(), RadomskoError> {
    let command_runner = CommandRunner::new()?;
    let cli = Cli::parse();
    match cli.subcommand {
        Subcommand::Edit(args) => Ok(command_runner.edit(args.target.to_str().unwrap())?),
        Subcommand::Find(args) => Ok(command_runner.find(args.keyword.to_str().unwrap())?),
        Subcommand::Show(args) => {
            let dest = match args.show_to {
                Some(show_to) => {
                    if show_to.clip {
                        ShowDestination::Clip
                    } else if show_to.qrcode {
                        ShowDestination::QrCode
                    } else {
                        panic!("BUG: unhandled `ShowTo` arm")
                    }
                }
                None => ShowDestination::Stdout,
            };
            let target = match args.target {
                Some(targ) => targ.to_str().unwrap().to_owned(),
                None => String::new(),
            };
            Ok(command_runner.show(target.as_str(), dest)?)
        }
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
