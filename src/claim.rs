use std::fs;
use std::path::{PathBuf, Path};
use std::time::SystemTime;

use log::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::artifacts::ArtifactId;
use crate::util::to_hex_string;
use std::sync::Arc;
use ring::digest::{Digest, Context, SHA256};
use std::fs::File;
use crate::err::TrustChainError;
use crate::gpg::{Gpg, SignedFilePath, PublicKey};

pub enum AuthenticatedClaim {
    Positive(PositiveClaimData),
    Revocation(CommonClaimData),
}

pub struct ClaimKind {
    claim_kind: String,
}
impl ClaimKind {
    fn new(kind: &str) -> ClaimKind {
        ClaimKind {
            claim_kind: kind.to_string()
        }
    }
}

pub struct CommonClaimData {
    id: Uuid,
    uid: String,
    artifact_id: ArtifactId,
    comment: Option<String>,
    timestamp: SystemTime,
}

pub struct PositiveClaimData {
    common_data: CommonClaimData,
    kind: ClaimKind,
}


#[derive(Serialize, Deserialize)]
struct PersistentClaim {
    id: String,
    uid: String,
    sig: String,
    artifact_id: String,
    comment: Option<String>,
    timestamp: SystemTime,
    specifics: PersistentClaimSpecifics,
}

impl PersistentClaim {
    fn into_authenticated_claim(self) -> AuthenticatedClaim {
        let common = CommonClaimData {
            id: Uuid::parse_str(&self.id).unwrap(), //TODO error handling
            uid: self.uid,
            artifact_id: ArtifactId {
                hash: Context::new(&SHA256).finish(), //TODO
            },
            comment: self.comment,
            timestamp: self.timestamp
        };

        match self.specifics {
            PersistentClaimSpecifics::Positive(data) =>
                AuthenticatedClaim::Positive(PositiveClaimData {
                    common_data: common,
                    kind: ClaimKind { claim_kind: data.claim_kind }
                }),
            PersistentClaimSpecifics::Revocation(_) =>
                AuthenticatedClaim::Revocation(common)
        }
    }
}

#[derive(Serialize, Deserialize)]
enum PersistentClaimSpecifics {
    Positive(PersistentPositiveClaimData),
    Revocation(PersistentRevocationData),
}

#[derive(Serialize, Deserialize)]
struct PersistentPositiveClaimData {
    claim_kind: String,
}
#[derive(Serialize, Deserialize)]
struct PersistentRevocationData {
}


pub trait ClaimRegistry {
    fn sign_claim(&self, artifact_id: &str, artifact_hash: &Digest, claim_key: &str, claim_value: Option<&str>) -> Result<String, TrustChainError>;
    fn revoke_claim(&self, artifact_id: &str, artifact_hash: &Digest, claim_id: &str) -> Result<String, TrustChainError>;
    fn verify_claim(&self, artifact_hash: &Digest, claim_file_name: &str) -> Result<PublicKey, TrustChainError>;
    fn authenticated_claims_for(&self, artifact: &ArtifactId) -> Result<Box<dyn Iterator<Item=Arc<AuthenticatedClaim>>>, TrustChainError>;
}

pub struct FileSystemClaimRegistry {
    root: PathBuf,
}

impl FileSystemClaimRegistry {
    pub fn new(root: PathBuf) -> std::io::Result<FileSystemClaimRegistry> {
        std::fs::create_dir_all(&root)?;
        Ok(FileSystemClaimRegistry {root})
    }
}

impl FileSystemClaimRegistry {
    fn artifact_folder(&self, artifact_hash: &Digest, create: bool) -> Result<PathBuf, TrustChainError> {
        //TODO hierarchy of folders
        let result = self.root.join(to_hex_string(artifact_hash.as_ref()));
        if create {
            io_guarded!(fs::create_dir_all(&result), Claims, "error creating folder {:?}", &result);
        }

        Ok(result)
    }

    fn sign_and_move_to_registry(&self, artifact_hash: &Digest, json: &str, data_file_name: &str, kind_of_file: &str) -> Result<(), TrustChainError> {
        let temp_path = SignedFilePath::temp(data_file_name);
        temp_path.create_data_file(json, kind_of_file)?;

        Gpg::sign(kind_of_file, &temp_path)?;

        let artifact_folder = self.artifact_folder(artifact_hash, true)?;

        let repo_path = SignedFilePath::new(&artifact_folder, data_file_name);
        temp_path.move_to(&repo_path, kind_of_file)?;

        //TODO 'clean-up' command for repository

        //TODO verify

        Ok(())
    }
}

impl ClaimRegistry for FileSystemClaimRegistry {

    fn sign_claim(&self, artifact_id: &str, artifact_hash: &Digest, claim_key: &str, claim_value: Option<&str>) -> Result<String, TrustChainError> {
        let claim_id = uuid::Uuid::new_v4().to_hyphenated().to_string();

        let json = serde_json::json!({
            "id": &claim_id,
            "artifact_id": artifact_id,
            "artifact_hash": to_hex_string(artifact_hash.as_ref()),
            "claim_key": claim_key,
            "claim_value": claim_value
        }).to_string();

        //TODO check size < 64k

        self.sign_and_move_to_registry(artifact_hash, &json, &claim_id, "claim")?;

        Ok(claim_id)
    }

    fn revoke_claim(&self, artifact_id: &str, artifact_hash: &Digest, claim_file_name: &str) -> Result<String, TrustChainError> {
        println!("{:?}", artifact_id);
        println!("{:?}", artifact_hash);
        println!("{:?}", claim_file_name);

        // TODO verify that the claim exists and was signed by us
        // TODO check that no revocation exists as yet

        // write revocation file to temp location

        // sign revocation file


        unimplemented!("todo");
    }

    fn verify_claim(&self, artifact_hash: &Digest, claim_file_name: &str) -> Result<PublicKey, TrustChainError> {
        //TODO check for revocation

        let artifact_folder = self.artifact_folder(artifact_hash, false)?;
        if !(artifact_folder.exists() && artifact_folder.is_dir()) {
            return err!(ClaimNotFound, "claim file {} not found for artifact with hash {}", claim_file_name, to_hex_string(artifact_hash.as_ref()));
        }

        let path = SignedFilePath::new(&artifact_folder, claim_file_name);
        Gpg::verify(&path)
    }


    fn authenticated_claims_for(&self, artifact: &ArtifactId) -> Result<Box<dyn Iterator<Item=Arc<AuthenticatedClaim>>>, TrustChainError> {
        let artifact_folder = self.artifact_folder(&artifact.hash, false)?;

        if artifact_folder.is_dir() {
            debug!("looking for claims in {:?}", artifact_folder);

            let dir = match fs::read_dir(artifact_folder) {
                Ok(d) => d,
                Err(e) => {
                    error!("{:?}", e); //TODO error reporting
                    return Ok(Box::new(std::iter::empty()));
                }
            };

            let iter = dir.filter_map(|e| match e {
                Err(e) => {
                    warn!("{:?}", e); //TODO error reporting
                    None
                },
                Ok(entry) if entry.path().is_file() => {
                    let ac = parse_claim(&entry.path());
                    ac.map(|a| Arc::new(a))
                },
                _ => None
            });

            Ok(Box::new(iter))
        }
        else {
            Ok(Box::new(std::iter::empty()))
        }
    }
}

fn parse_claim(path: &Path) -> Option<AuthenticatedClaim> {
    let metadata = fs::metadata(path).unwrap(); //TODO error handling
    if metadata.len() > 65536 { //TODO make this configurable
        warn!("claim file too long: {:?}", path);
        return None;
    }

//    let mut s = String::new();

    //TODO error handling
    let f = File::open(path).unwrap();
    let parsed: PersistentClaim = serde_json::from_reader(&f).unwrap(); //TODO error handling

    //TODO look up certificate, verify signature, confirm uid


    Some(parsed.into_authenticated_claim())

//    Some(AuthenticatedClaim::Positive(PositiveClaimData {
//        common_data: CommonClaimData {
//            id: Uuid::new_v4(),
//            uid: "whoever".to_string(),
//            artifact_id: ArtifactId {
//                hash: Context::new(&SHA256).finish(),
//            },
//            comment: Some("Some comment about something or other".to_string()),
//            timestamp: SystemTime::now()
//        },
//        kind: ClaimKind::new("dummy")
//    }))
}
