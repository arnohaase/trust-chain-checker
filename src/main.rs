#[macro_use] mod err;

mod artifacts;
mod checker;
mod claim;
mod eval;
mod gpg;
mod util;

use dirs::*;
use log::*;
use structopt::clap::arg_enum;
use structopt::StructOpt;
use std::path::PathBuf;
use crate::checker::Checker;
use crate::artifacts::ArtifactRepository;
use std::sync::Arc;
use crate::util::{to_hex_string, write_output};
use crate::claim::{ClaimRegistry, FileSystemClaimRegistry};
use crate::util::*;
use crate::err::*;
use std::time::SystemTime;
use std::fs::File;
use crate::gpg::PublicKey;

#[derive(Debug,StructOpt)]
#[structopt(about="The cross-language and cross-platform distributed build dependency verification tool")]
struct CliOpts {
    #[structopt(long="repository-kind", possible_values=&RepositoryKind::variants(), case_insensitive=true)]
    repository_kind: RepositoryKind,

    #[structopt(subcommand)]
    command: CliOptsCommand,
}

#[derive(Debug,StructOpt)]
enum CliOptsCommand {
    #[structopt(about="calculate an artifact's hash", )]
    Hash(HashOpts),

    #[structopt(about="sign a claim about an artifact", )]
    Sign(SignOpts),

    #[structopt(about="verify an artifact", )]
    Verify(VerifyOpts),
}

#[derive(Debug,StructOpt)]
struct SignOpts {
    #[structopt(name="The artifact's identifier", long="artifact")]
    artifact_id: String,

    #[structopt(name="The claim's identifier", long="claim-key")]
    claim_key: String,

    #[structopt(name="The claim's value, if any", long="claim-value")]
    claim_value: Option<String>,
}

#[derive(Debug,StructOpt)]
struct VerifyOpts {
    #[structopt(name="The id of the artifact to verify", long="artifact")]
    artifact_id: String,

    #[structopt(name="The file name of the claim to be verified", long="claim-file")]
    claim_file_name: String,
}

#[derive(Debug,StructOpt)]
struct HashOpts {
    #[structopt(name="The artifact's ID", long="artifact-id")]
    artifact_id: String,
}

arg_enum! {
  #[derive(Debug)]
  enum RepositoryKind {
    maven, npm, cargo,
  }
}


fn main() -> Result<(), crate::err::TrustChainError> {
    env_logger::init(); // levels controlled by RUST_LOG env variable

    let cli_opts = CliOpts::from_args();
    debug!("{:?}", cli_opts);

    match &cli_opts.command {
        CliOptsCommand::Hash(hash_opts) => do_hash(&cli_opts, hash_opts)?,
        CliOptsCommand::Sign(sign_opts) => {
            let claim_id = do_sign(&cli_opts, sign_opts)?;
            write_output(&format!("claim id: {}", claim_id));
        },
        CliOptsCommand::Verify(verify_opts) => {
            let key = do_verify(&cli_opts, &verify_opts)?;
            write_output(&format!("valid signature by {}", &key.fingerprint));
        },
    }

    Ok(())
}

fn do_hash(cli_opts: &CliOpts, hash_opts: &HashOpts) -> Result<(), TrustChainError> {
    debug!("calculating hash for {}", hash_opts.artifact_id);

    let artifact_repository = artifact_repository(&cli_opts);
    let hash = artifact_repository.do_hash(&hash_opts.artifact_id)?;
    let hash_string = to_hex_string(hash.as_ref());

    write_output(&hash_string);
    Ok(())
}

fn do_sign(cli_opts: &CliOpts, sign_opts: &SignOpts) -> Result<String, TrustChainError> {
    debug!("signing claim: {:?}", sign_opts);

    let artifact_repository = artifact_repository(&cli_opts);
    let claim_registry = claim_registry(cli_opts);

    let hash = artifact_repository.do_hash(&sign_opts.artifact_id)?;
    claim_registry.sign_claim(&sign_opts.artifact_id, &hash, &sign_opts.claim_key, sign_opts.claim_value.derefed())
}

fn do_verify(cli_opts: &CliOpts, verify_opts: &VerifyOpts) -> Result<PublicKey, TrustChainError> {
    debug!("verifying claim: {:?}", verify_opts);

    let artifact_repository = artifact_repository(&cli_opts);
    let claim_registry = claim_registry(cli_opts);

    let artifact_hash = artifact_repository.do_hash(&verify_opts.artifact_id)?;
    claim_registry.verify_claim(&artifact_hash, &verify_opts.claim_file_name)
}

fn artifact_repository(cli_opts: &CliOpts) -> Arc<ArtifactRepository> {
    Arc::new(match &cli_opts.repository_kind {
        RepositoryKind::maven => ArtifactRepository::new_maven(PathBuf::from("/home/arno/.m2/repository")), //TODO make path configurable
        RepositoryKind::npm => panic!("TODO"),
        RepositoryKind::cargo => panic!("TODO"),
    })
}

fn claim_registry(cli_opty: &CliOpts) -> Arc<dyn ClaimRegistry> {
    //TODO make path configurable
    //TODO error handling

    //TODO handle 'no home dir
    let path = dirs::home_dir().unwrap().join(".trust-chain-checker/registry");
    Arc::new(FileSystemClaimRegistry::new (path).unwrap())
}



