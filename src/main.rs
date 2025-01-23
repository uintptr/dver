use dverify::{signer::sign_directory, verifier::verify_directory, Error};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(about = "Deployment Verification Tool")]
enum DVCommand {
    /// Sign a deployment directory
    Sign {
        /// Directory to sign
        #[structopt(long, short)]
        directory: String,
        /// Private key file path
        #[structopt(long, short = "k")]
        private_key: String,
        #[structopt(long, short = "o")]
        signature_file: Option<String>,
        /// Hashing Algorithm
        #[structopt(long, default_value="sha256", possible_values = &["sha256", "sha384", "sha512"],)]
        hash_type: String,
    },
    /// Verify a deployment directory
    Verify {
        directory: String,
        public_key: String,
    },
}

fn main() -> Result<(), Error> {
    let opt = DVCommand::from_args();

    match opt {
        DVCommand::Sign {
            directory,
            private_key,
            signature_file,
            hash_type,
        } => sign_directory(
            &directory,
            &private_key,
            &hash_type,
            signature_file.as_ref(),
        ),
        DVCommand::Verify {
            directory,
            public_key,
        } => verify_directory(&directory, &public_key),
    }
}
