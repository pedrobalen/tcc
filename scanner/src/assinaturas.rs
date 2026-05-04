use std::fs;
use std::path::{Path, PathBuf};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AssinaturasErro {
    #[error("falha de I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("falha ao compilar regras YARA: {0}")]
    Compilacao(String),
    #[error("falha ao escanear arquivo: {0}")]
    Varredura(#[from] yara_x::ScanError),
}

// Representa uma regra YARA que casou com o conteudo de um arquivo.
pub struct Deteccao {
    pub regra: String,
    pub severidade: String,
    pub arquivo: PathBuf,
}

// Compila todas as regras .yar encontradas no diretorio informado e
// retorna o objeto Rules pronto para uso pelo Scanner. A compilacao e
// feita uma unica vez e o resultado pode ser reutilizado em multiplas
// varreduras, evitando retrabalho em modo benchmark.b
pub fn compilar_regras(diretorio: &Path) -> Result<yara_x::Rules, AssinaturasErro> {
    let mut compiler = yara_x::Compiler::new();

    for entrada in fs::read_dir(diretorio)? {
        let caminho = entrada?.path();
        if caminho.extension().is_some_and(|ext| ext == "yar") {
            let fonte = fs::read_to_string(&caminho)?;
            compiler
                .add_source(fonte.as_str())
                .map_err(|e| AssinaturasErro::Compilacao(e.to_string()))?;
        }
    }

    Ok(compiler.build())
}

// Varre uma lista de arquivos extraidos contra as regras YARA compiladas.
// Para cada arquivo, instancia um Scanner, executa o scan e coleta as regras
// que casaram junto com seus metadados de severidade. Segue a logica Fast-Fail:
// retorna as deteccoes encontradas para que o chamador decida se deve abortar
// o pipeline antes do estagio de ML.
pub fn varrer_arquivos(
    regras: &yara_x::Rules,
    arquivos: &[PathBuf],
) -> Result<Vec<Deteccao>, AssinaturasErro> {
    let mut deteccoes = Vec::new();
    let mut scanner = yara_x::Scanner::new(regras);

    for arquivo in arquivos {
        let resultados = scanner.scan_file(arquivo)?;

        for regra in resultados.matching_rules() {
            let severidade = regra
                .metadata()
                .find(|(chave, _)| *chave == "severidade")
                .and_then(|(_, valor)| match valor {
                    yara_x::MetaValue::String(s) => Some(s.to_string()),
                    _ => None,
                })
                .unwrap_or_else(|| "desconhecida".to_string());

            deteccoes.push(Deteccao {
                regra: regra.identifier().to_string(),
                severidade,
                arquivo: arquivo.clone(),
            });
        }
    }

    Ok(deteccoes)
}
