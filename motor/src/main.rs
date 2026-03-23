mod assinaturas;
mod cli;
mod extrator;
mod features;
mod inferencia;

use std::path::Path;

use clap::Parser;

fn main() -> anyhow::Result<()> {
    let args = cli::Cli::parse();
    let dir_pai = Path::new("temp");
    std::fs::create_dir_all(dir_pai)?;

    println!("[*] Extraindo pacote: {}", args.alvo.display());
    let pacote = extrator::extrair_deb(&args.alvo, dir_pai)?;

    println!(
        "[+] {} arquivos extraídos para {}",
        pacote.arquivos.len(),
        pacote.dir_temp.path().display()
    );

    for arquivo in &pacote.arquivos {
        println!("    {}", arquivo.display());
    }

    Ok(())
}
