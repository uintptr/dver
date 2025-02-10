use dver::{
    common::hash::DVHashType,
    logging::init_logging,
    sign::sign_dir::{sign_directory, DVSignType},
    verify::verify_dir::verify_directory,
};
use structopt::StructOpt;

use dver::error::Result;

#[derive(Debug, StructOpt)]
struct SignOpt {
    /// Directory to sign
    #[structopt(long, short)]
    directory: String,
    /// Private key file path
    #[structopt(long, short = "k")]
    private_key: String,
    /// Output Signature File
    #[structopt(long = "output", short = "o")]
    signature_file: Option<String>,
    /// Hashing Algorithm
    #[structopt(long,default_value="sha256", possible_values = &["sha256", "sha512"])]
    hash_type: DVHashType,
    /// Verbose
    #[structopt(long, short)]
    verbose: bool,
    /// Include context in the signature to help troubleshooting
    #[structopt(long, default_value="complete", possible_values = &["short", "complete"])]
    signature_type: DVSignType,
    /// Files directories to ignore
    #[structopt(long = "exclude", short = "e")]
    exclude_list: Vec<String>,
}

#[derive(Debug, StructOpt)]
struct VerifyOpt {
    /// Directory to verify
    #[structopt(long, short)]
    directory: String,
    /// Public key file path
    #[structopt(long, short = "k")]
    public_key: String,
    /// Input Signature File
    #[structopt(long = "input", short = "i")]
    signature_file: Option<String>,
    /// Hashing Algorithm
    #[structopt(long,default_value="sha256", possible_values = &["sha256", "sha512"])]
    hash_type: DVHashType,
    /// Verbose
    #[structopt(long, short)]
    verbose: bool,
}

#[derive(Debug, StructOpt)]
#[structopt(about = "Deployment Verification Tool")]
enum DVCommand {
    /// Sign a deployment directory
    Sign(SignOpt),
    /// Verify a deployment directory
    Verify(VerifyOpt),
}

fn main() -> Result<()> {
    let opt = DVCommand::from_args();

    let verbose = match &opt {
        DVCommand::Sign(opt) => opt.verbose,
        DVCommand::Verify(opt) => opt.verbose,
    };

    if verbose {
        init_logging()?;
    }

    match opt {
        DVCommand::Sign(opt) => sign_directory(
            opt.directory,
            opt.private_key,
            opt.hash_type,
            opt.signature_file,
            opt.signature_type,
            opt.exclude_list,
        ),
        DVCommand::Verify(opt) => verify_directory(
            opt.directory,
            opt.public_key,
            opt.hash_type,
            opt.signature_file,
        ),
    }
}
