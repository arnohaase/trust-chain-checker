use crate::err::*;

use std::fs;
use std::path::{Path, PathBuf};

use log::*;
use std::io::Write;
use std::process::Output;


pub struct PublicKey {
    pub fingerprint: String,
}

impl PublicKey {
    pub fn new(fingerprint: String) -> PublicKey {
        //TODO check length, no blanks, valid format
        PublicKey {
            fingerprint
        }
    }
}

/// A pair of paths, one pointing to a data file and the other pointing to the corresponding
/// signature file
#[derive(Debug)]
pub struct SignedFilePath {
    pub data_path: PathBuf,
    pub sig_path: PathBuf,
}

impl SignedFilePath {
    pub fn new(base_path: &Path, data_file_name: &str) -> SignedFilePath {
        let sig_file_name: &str = &format!("{}.sig", data_file_name);

        let data_path = base_path.join(data_file_name);
        let sig_path = base_path.join(sig_file_name);

        SignedFilePath {
            data_path,
            sig_path,
        }
    }

    pub fn temp(data_file_name: &str) -> SignedFilePath {
        SignedFilePath::new(&std::env::temp_dir(), data_file_name)
    }

    pub fn copy_to(&self, other: &SignedFilePath, kind_of_file: &str) -> Result<(), TrustChainError> {
        io_guarded!(fs::copy(&self.data_path, &other.data_path), Io, "error copying {} from {:?} to {:?}", kind_of_file, &self.data_path, &other.data_path);
        io_guarded!(fs::copy(&self.sig_path, &other.sig_path), Io, "error copying {} signature from {:?} to {:?}", kind_of_file, &self.sig_path, &other.sig_path);
        Ok(())
    }

    pub fn create_data_file(&self, content: &str, kind_of_file: &str) -> Result<(), TrustChainError> {
        let mut f = io_guarded!(fs::File::create(&self.data_path), Io, "error creating {} file {:?}", kind_of_file, &self.data_path);
        io_guarded!(f.write_all(content.as_bytes()), Io, "error writing to {} file {:?}", kind_of_file, &self.data_path);
        Ok(())
    }

    pub fn move_to(self, other: &SignedFilePath, kind_of_file: &str) -> Result<(), TrustChainError> {
        debug!("moving {} {:?} to {:?}", kind_of_file, &self, &other);

        self.copy_to(other, kind_of_file)?;

        io_guarded!(fs::remove_file(&self.data_path), Io, "error removing temporary {} file {:?}", kind_of_file, &self.data_path);
        io_guarded!(fs::remove_file(&self.sig_path), Io, "error removing temporary {} signature file {:?}", kind_of_file, &self.sig_path);

        Ok(())
    }
}


pub struct Gpg {
}

impl Gpg {
    pub fn sign(kind_of_file: &str, path: &SignedFilePath) -> Result<(), TrustChainError> {
        //TODO make gpg configurable
        execute!(Gpg, format!("error signing {} in {:?} (signature file {:?})", kind_of_file, &path.data_path, &path.sig_path),
            "gpg",
            "--detach-sign",
            "--armor",
            "--local-user",
            "dummy", //TODO make configurable
            "--output",
            &path.sig_path,
            &path.data_path
        );

        Ok(())
    }

    pub fn verify(path: &SignedFilePath) -> Result<PublicKey, TrustChainError> {
        // gpg --status-fd=1 --verify 4851de30-8c4c-41f9-9c14-9f2efaf10cd8.sig 4851de30-8c4c-41f9-9c14-9f2efaf10cd8

        let mut cmd = std::process::Command::new("gpg");
        cmd.arg("--status-fd=1");
        cmd.arg("--verify");
        cmd.arg(&path.sig_path);
        cmd.arg(&path.data_path);
        debug!("{:?}", &cmd);

        let out: Output = io_guarded!(cmd.output(), Gpg, "error invoking gpg to verify signature {:?} for {:?}", &path.sig_path, &path.data_path);
        let s = String::from_utf8_lossy(out.stdout.as_slice());

        let mut sig_key = None;

        for line in s.lines() {
            debug!("{}", line);
            let parts: Vec<&str> = line.split_ascii_whitespace().collect();
            if parts.len() > 2 && parts[0] == "[GNUPG:]" {
                match parts[1] {
                    "VALIDSIG" => {
                        // details about a valid signature - the primary key fingerprint in particular
                        // [GNUPG:] VALIDSIG B366A38296498FB36B1A44C56408C89E4018270C 2019-12-01 1575225882 0 4 0 1 10 00 5B8F59E68DA74387B3AB2761DBD433FD3D20D8F1
                        if parts.len() >= 12 {
                            sig_key = Some(PublicKey::new(parts[11].to_string()));
                        }
                        else {
                            sig_key = Some(PublicKey::new(parts[2].to_string()));
                        }
                    },
                    "GOODSIG" => {
                        // no problems with the signature
                        debug!("good signature {:?} for {:?}", &path.sig_path, &path.data_path);
                    },
                    "BADSIG" => {
                        // trouble! The signature does not match the document and / or the key!
                        error!("The signature {:?} is not a valid signature for {:?} - this may indicate an attack", &path.sig_path, &path.data_path);
                        return err!(InvalidSignature, "The signature {:?} is not a valid signature for {:?} - this may indicate an attack", &path.sig_path, &path.data_path);
                    },
                    "EXPSIG" => {
                        // the signature (as opposed to the key) has an expiration date that is in the past
                        return err!(ExpiredSignature, "The signature {:?} is for {:?} is expired. This is probably not a security issue.", &path.sig_path, &path.data_path);
                    },
                    "EXPKEYSIG" => {
                        // the key used for the signature is expired
                        debug!("good signature {:?} for {:?}, but the key is expired", &path.sig_path, &path.data_path);
                    },
                    "REVKEYSIG" => {
                        // the key used for the signature was revoked
                        //TODO is this the best way to handle this?
                        let mut key_id = "???";
                        let mut uid = "???";
                        if parts.len() >= 4 {
                            key_id = parts[2];
                            uid = parts[3];
                        }

                        error!("The signature {:?} is valid for {:?}, but the key {:?} for uid {:?} is expired", &path.sig_path, &path.data_path, key_id, uid);
                        return err!(ExpiredKeySignature, "The signature {:?} is valid for {:?}, but the key {:?} for uid {:?} is expired", &path.sig_path, &path.data_path, key_id, uid);
                    },
                    "ERRSIG" => {
                        // there is a format error in the signature
                        error!("The signature file {:?} does not contain a valid signature - it is probably formatted in an invalid way", &path.sig_path);
                        return err!(Generic, "The signature file {:?} does not contain a valid signature - it is probably formatted in an invalid way", &path.sig_path);
                    },
                    _ => {}
                }
            }
        }

        match sig_key {
            Some(key) => Ok(key),
            None => {
                if !out.status.success() {
                    err!(Gpg, "error verifying signature {:?} for {:?}", &path.sig_path, &path.data_path)
                }
                else {
                    err!(Gpg, "error in gpg output format verifying signature {:?} for {:?}", &path.sig_path, &path.data_path)
                }
            }
        }
    }
}
