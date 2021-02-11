// These functions don't share a real logical connection, but they share
// a common implementation in that they act outside the main body of
// radomsko through external binaries.

use std::path::Path;
use subprocess::{Exec, ExitStatus::*};

use crate::errors::RadomskoError;

const DISPLAY: &'static str = "DISPLAY";

fn gpg_decrypt_command(password_path: &str) -> Exec {
    Exec::cmd("gpg")
        .arg("--quiet")
        .arg("-d")
        .arg(password_path)
        .env_remove(DISPLAY)
}

fn return_exit_status(status: subprocess::ExitStatus) -> Result<(), RadomskoError> {
    match status {
        Exited(code) => {
            if code == 0 {
                Ok(())
            } else {
                Err(RadomskoError::SubprocessError(format!(
                    "subprocess failed with code {}",
                    code
                )))
            }
        }
        Signaled(signum) => Err(RadomskoError::SubprocessError(format!(
            "subprocess signaled with {}",
            signum
        ))),
        _ => Err(RadomskoError::SubprocessError(
            "Other / Undetermined branch (???)".to_string(),
        )),
    }
}

pub fn invoke_editor(password_path: &Path) -> Result<(), RadomskoError> {
    let editor = std::env::var("EDITOR")?;
    let status = Exec::cmd(editor)
        .arg(password_path.to_str().unwrap())
        .join()?;
    return_exit_status(status)
}

pub fn decrypt_password(password_path: &str, clip: bool) -> Result<(), RadomskoError> {
    let status: subprocess::ExitStatus;
    if clip {
        status = (gpg_decrypt_command(password_path) | Exec::cmd("wl-copy").arg("-n")).join()?;
    } else {
        status = gpg_decrypt_command(password_path).join()?;
    }
    return_exit_status(status)
}
