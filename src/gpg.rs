use crate::err::*;

use std::fs;
use std::path::{Path, PathBuf};

use log::*;
use std::io::Write;


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
        let mut sig_path = base_path.join(sig_file_name);

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

        io_guarded!(fs::remove_file(&self.data_path), Claims, "error removing temporary {} file {:?}", kind_of_file, &self.data_path);
        io_guarded!(fs::remove_file(&self.sig_path), Claims, "error removing temporary {} signature file {:?}", kind_of_file, &self.sig_path);

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

    pub fn verify(data_path: &Path, sig_path: &Path) -> Result<(), TrustChainError> {


        Ok(())
    }
}
