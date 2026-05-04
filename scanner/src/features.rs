use std::fs;
use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum FeaturesErro {
    #[error("falha de I/O: {0}")]
    Io(#[from] std::io::Error),
}

// Vetor de características extraídas de um binário ELF, usado como entrada
// para o modelo de ML. As quatro features foram escolhidas por capturarem
// indicadores complementares: tamanho bruto, aleatoriedade do conteúdo
// (entropia), complexidade estrutural (seções) e dependências externas
// (importações dinâmicas).
#[derive(Clone)]
pub struct FeaturesElf {
    pub arquivo: PathBuf,
    pub tamanho: u64,
    pub entropia: f64,
    pub num_secoes: usize,
    pub num_importacoes: usize,
}

impl FeaturesElf {
    // Retorna o vetor na ordem esperada pelo modelo ONNX.
    pub fn como_vetor(&self) -> [f32; 4] {
        [
            self.tamanho as f32,
            self.entropia as f32,
            self.num_secoes as f32,
            self.num_importacoes as f32,
        ]
    }
}

// Calcula a entropia de Shannon sobre os bytes brutos do arquivo.
// Valores próximos de 0 indicam conteúdo repetitivo (ex: seções zeradas),
// enquanto valores próximos de 8 indicam alta aleatoriedade, típica de
// dados cifrados, comprimidos ou ofuscados — característica comum em malware.
fn calcular_entropia(dados: &[u8]) -> f64 {
    if dados.is_empty() {
        return 0.0;
    }

    let mut frequencias = [0u64; 256];
    for &byte in dados {
        frequencias[byte as usize] += 1;
    }

    let total = dados.len() as f64;
    let mut entropia = 0.0;

    for &contagem in &frequencias {
        if contagem > 0 {
            let probabilidade = contagem as f64 / total;
            entropia -= probabilidade * probabilidade.log2();
        }
    }

    entropia
}

// Tenta parsear um arquivo como ELF usando goblin. Se o arquivo não for
// um binário ELF válido (ex: scripts, configs), retorna None sem erro,
// permitindo que o pipeline ignore arquivos não-analisáveis.
fn parsear_elf(dados: &[u8]) -> Option<goblin::elf::Elf<'_>> {
    match goblin::Object::parse(dados) {
        Ok(goblin::Object::Elf(elf)) => Some(elf),
        _ => None,
    }
}

// Extrai as features de todos os binários ELF encontrados na lista de
// arquivos. Arquivos que não são ELF são silenciosamente ignorados, já
// que pacotes .deb contêm uma mistura de binários, scripts e configs.
pub fn extrair_features(arquivos: &[PathBuf]) -> Result<Vec<FeaturesElf>, FeaturesErro> {
    let mut resultados = Vec::new();

    for caminho in arquivos {
        let dados = fs::read(caminho)?;

        if let Some(elf) = parsear_elf(&dados) {
            resultados.push(FeaturesElf {
                arquivo: caminho.clone(),
                tamanho: dados.len() as u64,
                entropia: calcular_entropia(&dados),
                num_secoes: elf.section_headers.len(),
                num_importacoes: elf.dynsyms.iter().filter(|s| s.is_import()).count(),
            });
        }
    }

    Ok(resultados)
}
