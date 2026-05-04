use std::path::{Path, PathBuf};

use ort::session::Session;
use ort::value::Tensor;
use thiserror::Error;

use crate::features::FeaturesElf;

#[derive(Debug, Error)]
pub enum InferenciaErro {
    #[error("falha no runtime ONNX: {0}")]
    Ort(#[from] ort::Error),
}

// Resultado da classificação ML para um único binário ELF analisado.
#[derive(Clone)]
pub struct ResultadoInferencia {
    pub arquivo: PathBuf,
    // 0 = benigno, 1 = malicioso (saída binária do Random Forest)
    pub predicao: i64,
    // Probabilidade da classe predita, entre 0.0 e 1.0
    pub confianca: f32,
}

// Carrega o modelo ONNX do disco e cria uma sessão reutilizável.
// A sessão pode ser passada para múltiplas chamadas de `classificar`
// sem reinicializar o runtime, o que é eficiente em modo benchmark.
pub fn carregar_modelo(caminho: &Path) -> Result<Session, InferenciaErro> {
    Ok(Session::builder()?.commit_from_file(caminho)?)
}

// Classifica cada binário ELF injetando seu vetor de features [tamanho,
// entropia, num_secoes, num_importacoes] na sessão ONNX e coletando a
// predição binária com a confiança associada.
//
// Assume exportação com zipmap=False no skl2onnx, de modo que
// "output_probability" seja um tensor float32 linearizado [n_amostras × n_classes].
pub fn classificar(
    sessao: &mut Session,
    features: &[FeaturesElf],
) -> Result<Vec<ResultadoInferencia>, InferenciaErro> {
    let mut resultados = Vec::new();

    for feat in features {
        let vetor = feat.como_vetor();
        // Tensor 2D [1, 4]: uma amostra com as quatro features ELF
        let tensor = Tensor::<f32>::from_array(([1usize, 4], vetor.to_vec()))?;
        let saidas = sessao.run(ort::inputs!["X" => tensor])?;

        // "label": int64 [n_amostras] — rótulo predito (0 ou 1)
        let (_, rotulos) = saidas["label"].try_extract_tensor::<i64>()?;
        let predicao = rotulos[0];

        // "probabilities": float32 [n_amostras × n_classes], linearizado.
        // Para uma amostra, índice 0 = P(benigno), índice 1 = P(malicioso).
        let (_, probs) = saidas["probabilities"].try_extract_tensor::<f32>()?;
        let confianca = probs[predicao as usize];

        resultados.push(ResultadoInferencia {
            arquivo: feat.arquivo.clone(),
            predicao,
            confianca,
        });
    }

    Ok(resultados)
}
