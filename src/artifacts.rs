use log::*;
use regex::Regex;
use ring::digest::{Context, Digest, SHA256};
use std::fs;
use std::fs::{File, ReadDir, DirEntry};
use std::io::{ErrorKind, Read, Error};
use std::iter::Map;
use std::path::{Path, PathBuf};

use crate::err::*;



#[derive(Clone)]
pub struct ArtifactId {
    pub hash: Digest,
}
impl Copy for ArtifactId {}

pub enum ArtifactRepository {
    Maven(MavenRepository),
}

impl ArtifactRepository {
    pub fn new_maven(root: PathBuf) -> ArtifactRepository {
        ArtifactRepository::Maven (MavenRepository::new(root))
    }

    pub fn do_hash(&self, artifact_id: &str) -> Result<Digest, TrustChainError> {
        use ArtifactRepository::*;

        let mut context = Context::new(&SHA256);

        match self {
            Maven(repo) => {
                let path = repo.id_to_path(artifact_id)?;

                debug!("hashing file {:?}", &path);
                hash_file(&mut context, &path)?;
                Ok(context.finish())
            }
        }
    }
}

fn hash_file(context: &mut Context, path: &Path) -> Result<(),TrustChainError> {
    debug!("hashing file {:?}", path);
    let mut f = io_guarded!(File::open(path), ArtifactNotFound, "artifact not found at '{:?}'", path);
    let mut buf = [0u8;65536];

    loop {
        match f.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => context.update(&buf[..n]),
            Err(ref e) if e.kind() == ErrorKind::Interrupted => {},
            Err(e) => {
                return err!(ArtifactReadError, "error reading artifact '{:?}' @ {:?}", path, e);
            }
        }
    }
}

fn hash_folder(context: &mut Context, path: &Path) -> Result<(), TrustChainError> {
    debug!("hashing folder {:?}", path);

    let mut entries = Vec::new();
    for entry in io_guarded!(fs::read_dir(path), ArtifactFolderReadError, "Cannot read artifact folder {:?}", path) {
        let entry: &DirEntry = io_guarded!(&entry, ArtifactFolderReadError, "Cannot read artifact folder entry {:?}", &entry);
        let path = entry.path();

        match path.file_name() {
            None => continue,
            Some(s) if s == "." => continue,
            Some(_) => entries.push(path)
        }
    }

    entries.sort_by_cached_key(|p| p.file_name().unwrap().to_str().unwrap().to_string()); //TODO error handling - UTF-8 conversions, non-UTF-8 characters?!

    for path in entries {
        if path.read_link().is_ok() {
            //TODO hard links?
            debug!("skipping link {:?}", path);
            continue;
        }

        context.update(path.file_name().unwrap().to_str().unwrap().as_bytes());

        if path.is_dir() {
            hash_folder(context, &path)?;
        }
        if path.is_file() {
            hash_file(context, &path)?;
        }
    }

    Ok(())
}


pub struct MavenRepository {
    root: PathBuf,
    regex_id: Regex,
    regex_group: Regex,
}

impl MavenRepository {
    fn new(root: PathBuf) -> MavenRepository {
        MavenRepository {
            root,
            regex_id: Regex::new(r"^([^:]+):([^:]+):([^:]+)$").unwrap(),
            regex_group: Regex::new(r"([^.]+)").unwrap(),
        }
    }

    fn id_to_path(&self, artifact_id: &str) -> Result<PathBuf, TrustChainError> {
        let captures = match self.regex_id.captures(artifact_id) {
            Some(c) => c,
            None => return err!(InvalidArtifactId, "'{}' is not a valid Maven artifact identifier", artifact_id),
        };

        let group_id = &captures[1];
        let art_id = &captures[2];
        let version = &captures[3];

        let mut jar_file = art_id.to_string();
        jar_file.push('-');
        jar_file.push_str(version);
        jar_file.push_str(".jar");

        let mut result = self.root.clone();

        for group_seg in self.regex_group.captures_iter(group_id) {
            result.push(&group_seg[0]);
        }

        result.push(art_id);
        result.push(version);
        result.push(jar_file);

        Ok(result)
    }
}
