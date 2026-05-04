mod assinaturas;
mod cli;
mod extrator;
mod features;
mod inferencia;

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use clap::Parser;
use ort::session::Session;
use serde::Serialize;
use yara_x::Rules;

use cli::{Cli, Comando};

// Resultado do pipeline de análise para um único pacote .deb.
// O campo `tem_elf` em SinalVerde distingue se o ML efetivamente rodou
// (verdadeiro) ou se o pacote simplesmente não continha binários ELF (falso),
// evitando que o CSV registre predicao="0" quando o modelo nunca foi invocado.
enum ResultadoPipeline {
    // Estágio 1: regra YARA casou — pipeline abortado (Fast-Fail).
    AlertaVermelho {
        deteccoes: Vec<assinaturas::Deteccao>,
    },
    // Estágio 2: ML classificou ao menos um binário como malicioso.
    AlertaLaranja {
        ameacas: Vec<inferencia::ResultadoInferencia>,
    },
    // Pacote limpo: `tem_elf=true` → ML rodou e aprovou; `false` → sem ELF.
    SinalVerde {
        tem_elf: bool,
    },
}

struct RelatorioAnalise {
    especificacoes: extrator::EspecificacoesPacote,
    resultado: ResultadoPipeline,
    features: Vec<features::FeaturesElf>,
    inferencias: Vec<inferencia::ResultadoInferencia>,
}

// Executa o pipeline completo (extração → YARA → features → ML) sobre um único
// pacote .deb. Recebe regras e sessão prontas para permitir reutilização em
// modo benchmark sem recompilação ou recarga a cada iteração.
//
// O diretório base "temp/" é local para manter caminhos curtos e evitar o
// limite MAX_PATH do Windows ao combinar %TEMP% com subdiretórios do pacote.
fn executar_pipeline(
    alvo: &Path,
    regras: &Rules,
    sessao: &mut Session,
) -> anyhow::Result<RelatorioAnalise> {
    let dir_base = Path::new("temp");
    fs::create_dir_all(dir_base)?;
    let pacote = extrator::extrair_deb(alvo, dir_base)?;
    let especificacoes = pacote.especificacoes.clone();

    // Estágio 1 — varredura YARA (Fast-Fail)
    let deteccoes = assinaturas::varrer_arquivos(regras, &pacote.arquivos)?;
    if !deteccoes.is_empty() {
        return Ok(RelatorioAnalise {
            especificacoes,
            resultado: ResultadoPipeline::AlertaVermelho { deteccoes },
            features: Vec::new(),
            inferencias: Vec::new(),
        });
    }

    // Estágio 2 — extração de features ELF e inferência ML
    let features = features::extrair_features(&pacote.arquivos)?;
    if features.is_empty() {
        return Ok(RelatorioAnalise {
            especificacoes,
            resultado: ResultadoPipeline::SinalVerde { tem_elf: false },
            features,
            inferencias: Vec::new(),
        });
    }

    let resultados = inferencia::classificar(sessao, &features)?;
    let ameacas: Vec<_> = resultados
        .iter()
        .filter(|r| r.predicao == 1)
        .cloned()
        .collect();

    let resultado = if ameacas.is_empty() {
        ResultadoPipeline::SinalVerde { tem_elf: true }
    } else {
        ResultadoPipeline::AlertaLaranja { ameacas }
    };

    Ok(RelatorioAnalise {
        especificacoes,
        resultado,
        features,
        inferencias: resultados,
    })
}

// Imprime o resultado de um único pacote no terminal com formatação legível.
fn imprimir_resultado(alvo: &Path, relatorio: &RelatorioAnalise) {
    println!();
    println!("=== Resultado da analise ===");
    println!("Pacote: {}", alvo.display());
    imprimir_especificacoes(&relatorio.especificacoes);

    match &relatorio.resultado {
        ResultadoPipeline::AlertaVermelho { deteccoes } => {
            println!();
            println!(
                "[!] ALERTA VERMELHO — {} ameaça(s) detectada(s) por assinatura:",
                deteccoes.len()
            );
            for d in deteccoes {
                println!(
                    "    regra: {} | severidade: {} | arquivo: {}",
                    d.regra,
                    d.severidade,
                    formatar_caminho_pacote(&d.arquivo)
                );
            }
        }
        ResultadoPipeline::AlertaLaranja { ameacas } => {
            println!();
            println!(
                "[!] ALERTA LARANJA — {} binário(s) suspeito(s) detectado(s) por heurística:",
                ameacas.len()
            );
            for r in ameacas {
                println!(
                    "    arquivo: {} | confiança: {:.1}%",
                    formatar_caminho_pacote(&r.arquivo),
                    r.confianca * 100.0
                );
            }
            imprimir_features(&relatorio.features, &relatorio.inferencias);
        }
        ResultadoPipeline::SinalVerde { tem_elf } => {
            println!();
            println!(
                "[+] SINAL VERDE — {} está aparentemente limpo.",
                alvo.display()
            );
            if *tem_elf {
                imprimir_features(&relatorio.features, &relatorio.inferencias);
            } else {
                println!(
                    "    motivo: pacote sem binários ELF analisáveis; estágio ML não executado."
                );
            }
        }
    }
}

fn imprimir_especificacoes(especificacoes: &extrator::EspecificacoesPacote) {
    println!();
    println!("Especificacoes do pacote:");
    println!(
        "  tamanho do .deb: {}",
        formatar_bytes(especificacoes.tamanho_pacote)
    );
    println!(
        "  membro de dados: {} ({})",
        especificacoes.membro_data, especificacoes.compressao_data
    );
    println!(
        "  conteudo extraido: {} arquivo(s), {}",
        especificacoes.arquivos_extraidos,
        formatar_bytes(especificacoes.bytes_extraidos)
    );

    if especificacoes.campos_controle.is_empty() {
        println!("  controle Debian: nao encontrado no pacote");
        return;
    }

    println!("  controle Debian:");
    for chave in [
        "Package",
        "Version",
        "Architecture",
        "Maintainer",
        "Description",
    ] {
        if let Some((_, valor)) = especificacoes
            .campos_controle
            .iter()
            .find(|(campo, _)| campo == chave)
        {
            println!("    {chave}: {valor}");
        }
    }
}

fn imprimir_features(
    features: &[features::FeaturesElf],
    inferencias: &[inferencia::ResultadoInferencia],
) {
    if features.is_empty() {
        return;
    }

    println!();
    println!("Binarios ELF analisados:");
    for feat in features {
        let inferencia = inferencias.iter().find(|r| r.arquivo == feat.arquivo);
        let classificacao = inferencia
            .map(|r| {
                if r.predicao == 1 {
                    "malicioso"
                } else {
                    "benigno"
                }
            })
            .unwrap_or("nao classificado");
        let confianca = inferencia
            .map(|r| format!("{:.1}%", r.confianca * 100.0))
            .unwrap_or_else(|| "-".to_string());

        println!("  arquivo: {}", formatar_caminho_pacote(&feat.arquivo));
        println!("    tamanho: {}", formatar_bytes(feat.tamanho));
        println!("    entropia: {:.3}", feat.entropia);
        println!("    secoes ELF: {}", feat.num_secoes);
        println!("    importacoes dinamicas: {}", feat.num_importacoes);
        println!("    classificacao ML: {classificacao} ({confianca})");
    }
}

fn formatar_caminho_pacote(caminho: &Path) -> String {
    let raiz_pacote = [
        "bin", "boot", "etc", "lib", "lib64", "opt", "sbin", "usr", "var",
    ];
    let componentes: Vec<_> = caminho.components().collect();

    for (indice, componente) in componentes.iter().enumerate() {
        let nome = componente.as_os_str().to_string_lossy();
        if raiz_pacote.iter().any(|raiz| nome == *raiz) {
            let mut relativo = PathBuf::new();
            for parte in &componentes[indice..] {
                relativo.push(parte.as_os_str());
            }
            return relativo.display().to_string();
        }
    }

    caminho.display().to_string()
}

fn formatar_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;

    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KiB", bytes as f64 / KIB)
    } else {
        format!("{:.1} MiB", bytes as f64 / MIB)
    }
}

// Linha de dados exportada para o CSV de benchmark.
// Os campos `predicao` e `confianca_pct` ficam vazios quando o estágio de ML
// não foi executado (ALERTA_VERMELHO ou pacote sem binários ELF).
#[derive(Serialize)]
struct RegistroCsv {
    arquivo: String,
    resultado: String,
    regras_yara: String,
    predicao: String,
    confianca_pct: String,
    tempo_ms: u128,
}

// Converte o ResultadoPipeline em um registro CSV.
// Para ALERTA_LARANJA com múltiplos binários, registra a maior confiança
// observada como valor representativo do pacote.
fn para_registro_csv(alvo: &Path, relatorio: &RelatorioAnalise, tempo_ms: u128) -> RegistroCsv {
    let arquivo = alvo
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();

    match &relatorio.resultado {
        ResultadoPipeline::AlertaVermelho { deteccoes } => {
            let regras = deteccoes
                .iter()
                .map(|d| d.regra.as_str())
                .collect::<Vec<_>>()
                .join(",");
            RegistroCsv {
                arquivo,
                resultado: "ALERTA_VERMELHO".to_string(),
                regras_yara: regras,
                predicao: String::new(),
                confianca_pct: String::new(),
                tempo_ms,
            }
        }
        ResultadoPipeline::AlertaLaranja { ameacas } => {
            let max_confianca = ameacas.iter().map(|a| a.confianca).fold(0.0f32, f32::max);
            RegistroCsv {
                arquivo,
                resultado: "ALERTA_LARANJA".to_string(),
                regras_yara: String::new(),
                predicao: "1".to_string(),
                confianca_pct: format!("{:.2}", max_confianca * 100.0),
                tempo_ms,
            }
        }
        ResultadoPipeline::SinalVerde { tem_elf } => RegistroCsv {
            arquivo,
            resultado: "LIMPO".to_string(),
            regras_yara: String::new(),
            predicao: if *tem_elf {
                "0".to_string()
            } else {
                String::new()
            },
            confianca_pct: String::new(),
            tempo_ms,
        },
    }
}

// Analisa um único pacote e imprime o resultado no terminal (RF01–RF04, RNF04).
fn cmd_scan(args: &cli::ArgsScan) -> anyhow::Result<()> {
    println!("[*] Compilando regras YARA de: {}", args.regras.display());
    let regras = assinaturas::compilar_regras(&args.regras)?;

    println!("[*] Carregando modelo ONNX: {}", args.modelo.display());
    let mut sessao = inferencia::carregar_modelo(&args.modelo)?;

    println!("[*] Analisando: {}", args.alvo.display());
    let resultado = executar_pipeline(&args.alvo, &regras, &mut sessao)?;
    imprimir_resultado(&args.alvo, &resultado);

    Ok(())
}

// Varre em lote todos os .deb de um diretório e escreve um CSV de auditoria (RF05).
// Regras YARA e sessão ONNX são compiladas/carregadas uma única vez antes do loop
// para não penalizar o tempo de cada iteração com overhead de inicialização.
fn cmd_benchmark(args: &cli::ArgsBenchmark) -> anyhow::Result<()> {
    println!("[*] Compilando regras YARA de: {}", args.regras.display());
    let regras = assinaturas::compilar_regras(&args.regras)?;

    println!("[*] Carregando modelo ONNX: {}", args.modelo.display());
    let mut sessao = inferencia::carregar_modelo(&args.modelo)?;

    let debs: Vec<_> = fs::read_dir(&args.diretorio)?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "deb"))
        .collect();

    if debs.is_empty() {
        println!(
            "[!] Nenhum arquivo .deb encontrado em: {}",
            args.diretorio.display()
        );
        return Ok(());
    }

    println!(
        "[*] {} pacote(s) encontrado(s). Iniciando varredura em lote...",
        debs.len()
    );

    let mut escritor = csv::Writer::from_path(&args.saida)?;
    let mut total_ok = 0usize;
    let mut total_erros = 0usize;

    for alvo in &debs {
        let inicio = Instant::now();
        match executar_pipeline(alvo, &regras, &mut sessao) {
            Ok(resultado) => {
                let tempo_ms = inicio.elapsed().as_millis();
                let tag = match &resultado.resultado {
                    ResultadoPipeline::AlertaVermelho { .. } => "ALERTA_VERMELHO",
                    ResultadoPipeline::AlertaLaranja { .. } => "ALERTA_LARANJA",
                    ResultadoPipeline::SinalVerde { .. } => "LIMPO",
                };
                println!(
                    "  [{tag}] {} ({tempo_ms} ms)",
                    alvo.file_name().unwrap_or_default().to_string_lossy()
                );
                escritor.serialize(para_registro_csv(alvo, &resultado, tempo_ms))?;
                total_ok += 1;
            }
            Err(e) => {
                println!(
                    "  [ERRO] {}: {e}",
                    alvo.file_name().unwrap_or_default().to_string_lossy()
                );
                total_erros += 1;
            }
        }
    }

    escritor.flush()?;
    println!(
        "[+] Concluído: {total_ok}/{} pacote(s) analisado(s). Relatório: {}",
        debs.len(),
        args.saida.display()
    );
    if total_erros > 0 {
        println!("[!] {total_erros} pacote(s) com erro foram ignorados.");
    }

    Ok(())
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match &cli.comando {
        Comando::Scan(args) => cmd_scan(args),
        Comando::Benchmark(args) => cmd_benchmark(args),
    }
}
