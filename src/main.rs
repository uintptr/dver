use dverify::{signer::sign_directory, verifier::verify_directory, DVError};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(about = "Deployment Verification Tool")]
enum DVCommand {
    /// Sign a deployment directory
    Sign {
        #[structopt(long, short)]
        directory: String,
        #[structopt(long, short = "k")]
        private_key: String,
        //#[structopt(long, short = "i")]
        //ignore: Option<Vec<String>>,
    },
    /// Verify a deployment directory
    Verify {
        directory: String,
        public_key: String,
    },
}

fn main() -> Result<(), DVError> {
    let opt = DVCommand::from_args();

    match opt {
        DVCommand::Sign {
            directory,
            private_key,
            ..
        } => sign_directory(&directory, &private_key),
        DVCommand::Verify {
            directory,
            public_key,
        } => verify_directory(&directory, &public_key),
    }
}
