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
    pub dir_temp: TempDir,
    pub arquivos: Vec<PathBuf>,
}

pub fn extrair_deb(caminho: &Path, dir_pai: &Path) -> Result<PacoteExtraido, ExtratorErro> {
    let dir_temp = tempfile::tempdir_in(dir_pai)?;
    let arquivo = File::open(caminho)?;
    let mut ar = ar::Archive::new(arquivo);

    while let Some(entrada) = ar.next_entry() {
        let mut entrada = entrada?;
        let identificador = String::from_utf8_lossy(entrada.header().identifier())
            .trim_end_matches('/')
            .to_string();

        if !identificador.starts_with("data.tar") {
            continue;
        }

        let mut dados = Vec::new();
        entrada.read_to_end(&mut dados)?;

        let arquivos = if identificador.ends_with(".gz") {
            descompactar_tar_gz(&dados, dir_temp.path())?
        } else if identificador.ends_with(".xz") {
            descompactar_tar_xz(&dados, dir_temp.path())?
        } else {
            return Err(ExtratorErro::CompressaoNaoSuportada(identificador));
        };

        return Ok(PacoteExtraido { dir_temp, arquivos });
    }

    Err(ExtratorErro::DataTarNaoEncontrado)
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
