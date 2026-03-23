use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
#[command(name = "lpts", version, about = "Linux Package Threat Scanner")]
pub struct Cli {
    pub alvo: PathBuf,
}
