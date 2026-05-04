use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "lpts", version, about = "Linux Package Threat Scanner")]
pub struct Cli {
    #[command(subcommand)]
    pub comando: Comando,
}

#[derive(Subcommand)]
pub enum Comando {
    /// Analisa um único pacote .deb e imprime o resultado no terminal
    Scan(ArgsScan),
    /// Varre em lote todos os .deb de um diretório e gera relatório CSV
    Benchmark(ArgsBenchmark),
}

#[derive(clap::Args)]
pub struct ArgsScan {
    /// Caminho para o pacote .deb a ser analisado
    pub alvo: PathBuf,
    /// Caminho para o modelo ONNX
    #[arg(long, default_value = "modelo_ia/random_forest.onnx")]
    pub modelo: PathBuf,
    /// Diretório contendo as regras YARA (.yar)
    #[arg(long, default_value = "regras_yara")]
    pub regras: PathBuf,
}

#[derive(clap::Args)]
pub struct ArgsBenchmark {
    /// Diretório contendo os pacotes .deb a serem analisados
    pub diretorio: PathBuf,
    /// Caminho para o modelo ONNX
    #[arg(long, default_value = "modelo_ia/random_forest.onnx")]
    pub modelo: PathBuf,
    /// Diretório contendo as regras YARA (.yar)
    #[arg(long, default_value = "regras_yara")]
    pub regras: PathBuf,
    /// Arquivo CSV de saída com os resultados do benchmark
    #[arg(long, default_value = "resultados.csv")]
    pub saida: PathBuf,
}
