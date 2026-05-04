use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use tempfile::TempDir;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ExtratorErro {
    #[error("falha de I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("membro data.tar não encontrado no pacote .deb")]
    DataTarNaoEncontrado,
    #[error("formato de compressão não suportado: {0}")]
    CompressaoNaoSuportada(String),
}

pub struct PacoteExtraido {
    // Mantido pelo struct para garantir que o diretório temporário
    // só seja deletado quando PacoteExtraido for descartado.
    _dir_temp: TempDir,
    pub arquivos: Vec<PathBuf>,
    pub especificacoes: EspecificacoesPacote,
}

#[derive(Clone)]
pub struct EspecificacoesPacote {
    pub tamanho_pacote: u64,
    pub membro_data: String,
    pub compressao_data: String,
    pub arquivos_extraidos: usize,
    pub bytes_extraidos: u64,
    pub campos_controle: Vec<(String, String)>,
}

pub fn extrair_deb(caminho: &Path, dir_pai: &Path) -> Result<PacoteExtraido, ExtratorErro> {
    let dir_temp = tempfile::tempdir_in(dir_pai)?;
    let tamanho_pacote = caminho.metadata()?.len();
    let arquivo = File::open(caminho)?;
    let mut ar = ar::Archive::new(arquivo);
    let mut dados_data: Option<(String, Vec<u8>)> = None;
    let mut campos_controle = Vec::new();

    while let Some(entrada) = ar.next_entry() {
        let mut entrada = entrada?;
        let identificador = String::from_utf8_lossy(entrada.header().identifier())
            .trim_end_matches('/')
            .to_string();

        let mut dados = Vec::new();
        entrada.read_to_end(&mut dados)?;

        if identificador.starts_with("control.tar") {
            campos_controle = ler_campos_controle(&identificador, &dados)?;
        } else if identificador.starts_with("data.tar") {
            dados_data = Some((identificador, dados));
        }
    }

    if let Some((membro_data, dados)) = dados_data {
        let compressao_data = tipo_compressao(&membro_data)?;
        let arquivos = descompactar_tar_por_tipo(&membro_data, &dados, dir_temp.path())?;
        let bytes_extraidos = somar_tamanho_arquivos(&arquivos)?;
        let especificacoes = EspecificacoesPacote {
            tamanho_pacote,
            membro_data,
            compressao_data,
            arquivos_extraidos: arquivos.len(),
            bytes_extraidos,
            campos_controle,
        };

        return Ok(PacoteExtraido {
            _dir_temp: dir_temp,
            arquivos,
            especificacoes,
        });
    }

    Err(ExtratorErro::DataTarNaoEncontrado)
}

fn tipo_compressao(identificador: &str) -> Result<String, ExtratorErro> {
    if identificador.ends_with(".gz") {
        Ok("gzip".to_string())
    } else if identificador.ends_with(".xz") {
        Ok("xz".to_string())
    } else {
        Err(ExtratorErro::CompressaoNaoSuportada(
            identificador.to_string(),
        ))
    }
}

fn descompactar_tar_por_tipo(
    identificador: &str,
    dados: &[u8],
    destino: &Path,
) -> Result<Vec<PathBuf>, ExtratorErro> {
    if identificador.ends_with(".gz") {
        descompactar_tar_gz(dados, destino)
    } else if identificador.ends_with(".xz") {
        descompactar_tar_xz(dados, destino)
    } else {
        Err(ExtratorErro::CompressaoNaoSuportada(
            identificador.to_string(),
        ))
    }
}

fn descompactar_tar_gz(dados: &[u8], destino: &Path) -> Result<Vec<PathBuf>, ExtratorErro> {
    let decodificador = flate2::read::GzDecoder::new(dados);
    extrair_tar(decodificador, destino)
}

fn descompactar_tar_xz(dados: &[u8], destino: &Path) -> Result<Vec<PathBuf>, ExtratorErro> {
    let decodificador = xz2::read::XzDecoder::new(dados);
    extrair_tar(decodificador, destino)
}

fn extrair_tar<R: Read>(leitor: R, destino: &Path) -> Result<Vec<PathBuf>, ExtratorErro> {
    let mut tar = tar::Archive::new(leitor);
    let mut arquivos = Vec::new();

    for entrada in tar.entries()? {
        let mut entrada = entrada?;
        let tipo = entrada.header().entry_type();

        if tipo.is_symlink() || tipo.is_hard_link() {
            continue;
        }

        if tipo.is_file() {
            entrada.unpack_in(destino)?;
            let caminho = destino.join(entrada.path()?);
            arquivos.push(caminho);
        } else if tipo.is_dir() {
            entrada.unpack_in(destino)?;
        }
    }

    Ok(arquivos)
}

fn ler_campos_controle(
    identificador: &str,
    dados: &[u8],
) -> Result<Vec<(String, String)>, ExtratorErro> {
    if identificador.ends_with(".gz") {
        let decodificador = flate2::read::GzDecoder::new(dados);
        ler_control_tar(decodificador)
    } else if identificador.ends_with(".xz") {
        let decodificador = xz2::read::XzDecoder::new(dados);
        ler_control_tar(decodificador)
    } else {
        Err(ExtratorErro::CompressaoNaoSuportada(
            identificador.to_string(),
        ))
    }
}

fn ler_control_tar<R: Read>(leitor: R) -> Result<Vec<(String, String)>, ExtratorErro> {
    let mut tar = tar::Archive::new(leitor);

    for entrada in tar.entries()? {
        let mut entrada = entrada?;
        let caminho = entrada.path()?;
        let nome = caminho.file_name().and_then(|n| n.to_str());

        if nome != Some("control") {
            continue;
        }

        let mut conteudo = String::new();
        entrada.read_to_string(&mut conteudo)?;
        return Ok(parsear_campos_controle(&conteudo));
    }

    Ok(Vec::new())
}

fn parsear_campos_controle(conteudo: &str) -> Vec<(String, String)> {
    let mut campos: Vec<(String, String)> = Vec::new();

    for linha in conteudo.lines() {
        if linha.starts_with(' ') || linha.starts_with('\t') {
            if let Some((_, valor)) = campos.last_mut() {
                valor.push(' ');
                valor.push_str(linha.trim());
            }
            continue;
        }

        if let Some((chave, valor)) = linha.split_once(':') {
            campos.push((chave.trim().to_string(), valor.trim().to_string()));
        }
    }

    campos
}

fn somar_tamanho_arquivos(arquivos: &[PathBuf]) -> Result<u64, ExtratorErro> {
    let mut total = 0u64;

    for arquivo in arquivos {
        total += File::open(arquivo)?.metadata()?.len();
    }

    Ok(total)
}
