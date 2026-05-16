use std::path::PathBuf;

use thiserror::Error;

const REGRAS_YARA: &str = include_str!("../regras_yara/base.yar");

#[derive(Debug, Error)]
pub enum AssinaturasErro {
    #[error("falha ao compilar regras YARA: {0}")]
    Compilacao(String),
    #[error("falha ao escanear arquivo: {0}")]
    Varredura(#[from] yara_x::ScanError),
}

pub struct Deteccao {
    pub regra: String,
    pub descricao: String,
    pub severidade: String,
    pub arquivo: PathBuf,
}

pub fn compilar_regras() -> Result<yara_x::Rules, AssinaturasErro> {
    let mut compiler = yara_x::Compiler::new();
    compiler
        .add_source(REGRAS_YARA)
        .map_err(|e| AssinaturasErro::Compilacao(e.to_string()))?;
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

            let descricao = regra
                .metadata()
                .find(|(chave, _)| *chave == "descricao")
                .and_then(|(_, valor)| match valor {
                    yara_x::MetaValue::String(s) => Some(s.to_string()),
                    _ => None,
                })
                .unwrap_or_else(|| "sem descricao".to_string());

            deteccoes.push(Deteccao {
                regra: regra.identifier().to_string(),
                descricao,
                severidade,
                arquivo: arquivo.clone(),
            });
        }
    }

    Ok(deteccoes)
}
