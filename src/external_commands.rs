// These functions don't share a real logical connection, but they share
// a common implementation in that they act outside the main body of
// radomsko through external binaries.

use subprocess::{Exec, ExitStatus::*};

use crate::errors::RadomskoError;

const DISPLAY: &'static str = "DISPLAY";

pub fn decrypt_password(password_path: &str, clip: bool) -> Result<(), RadomskoError> {
    let status: subprocess::ExitStatus;
    if clip {
        status = (Exec::cmd("gpg")
            .arg("--quiet")
            .arg("-d")
            .arg(password_path)
            .env_remove(DISPLAY)
            | Exec::cmd("wl-copy").arg("-n"))
        .join()?;
    } else {
        status = Exec::cmd("gpg")
            .arg("--quiet")
            .arg("-d")
            .arg(password_path)
            .env_remove(DISPLAY)
            .join()?;
    }

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
