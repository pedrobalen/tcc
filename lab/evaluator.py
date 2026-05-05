"""
Avaliador de resultados do pipeline LPTS para a monografia.

Le os CSVs de benchmark gerados pelo motor Rust (comando `lpts benchmark`)
e produz graficos de validacao. O benchmark deve ser executado duas vezes,
uma para cada conjunto de amostras:

  lpts benchmark amostras/maliciosos --saida resultado_maliciosos.csv
  lpts benchmark amostras/benignos   --saida resultado_benignos.csv

Cada CSV tem as colunas: arquivo, resultado, regras_yara, predicao,
confianca_pct, tempo_ms (definidas em RegistroCsv no main.rs do scanner).

A coluna `resultado` contem o veredito do pipeline: ALERTA_VERMELHO (YARA
detectou), ALERTA_LARANJA (ML detectou) ou LIMPO (nenhuma ameaca).

Uso:
  python evaluator.py <resultado_maliciosos.csv> <resultado_benignos.csv>

Saida (diretorio resultado/):
  - matriz_confusao_pipeline.png   (grafico 1)
  - distribuicao_resultados.png    (grafico 2)
  - histograma_tempos.png          (grafico 3)
  - deteccao_yara_vs_ml.png        (grafico 4)
  - metricas_pipeline.txt          (tabela-resumo)
"""

import sys
from pathlib import Path

import matplotlib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.metrics import confusion_matrix

# Backend nao-interativo: gera PNGs sem precisar de display grafico.
# Necessario em servidores e ambientes sem GUI (ex: WSL, CI).
matplotlib.use("Agg")

LAB_DIR = Path(__file__).parent
RESULTADO_DIR = LAB_DIR / "resultado"

# Paleta consistente para os tres vereditos do pipeline ao longo de
# todos os graficos, facilitando a leitura cruzada na monografia.
CORES_VEREDITO = {
    "ALERTA_VERMELHO": "#d62728",
    "ALERTA_LARANJA": "#ff7f0e",
    "LIMPO": "#2ca02c",
}


def carregar_csvs(caminho_maliciosos: Path, caminho_benignos: Path) -> pd.DataFrame:
    """Carrega os dois CSVs de benchmark e adiciona a coluna `rotulo_real`.

    O rotulo_real e a ground truth: 1 para as amostras que sabemos serem
    maliciosas (vieram do dataset de malware), 0 para as benignas (vieram
    de repositorios oficiais). Esse rotulo NAO vem do CSV do scanner — ele
    e inferido pela origem do arquivo, ja que o pesquisador rodou o benchmark
    separadamente em cada conjunto."""

    df_mal = pd.read_csv(caminho_maliciosos)
    df_mal["rotulo_real"] = 1

    df_ben = pd.read_csv(caminho_benignos)
    df_ben["rotulo_real"] = 0

    dataset = pd.concat([df_mal, df_ben], ignore_index=True)
    print(f"  Maliciosos: {len(df_mal)} pacotes")
    print(f"  Benignos:   {len(df_ben)} pacotes")
    print(f"  Total:      {len(dataset)} pacotes")
    return dataset


def calcular_predicao_pipeline(df: pd.DataFrame) -> pd.Series:
    """Converte a coluna `resultado` do scanner em predicao binaria do pipeline.

    ALERTA_VERMELHO e ALERTA_LARANJA sao ambos "detectou ameaca" (1),
    independente de ter sido YARA ou ML que detectou. LIMPO e "nao detectou" (0).
    Essa unificacao e necessaria porque a matriz de confusao e as metricas
    avaliam o pipeline como um todo, nao cada estagio isoladamente."""

    return df["resultado"].map({
        "ALERTA_VERMELHO": 1,
        "ALERTA_LARANJA": 1,
        "LIMPO": 0,
    })


def grafico_matriz_confusao(df: pd.DataFrame) -> None:
    """Grafico 1: Matriz de confusao do pipeline completo (YARA + ML).

    Diferente da matriz gerada pelo treinar.py (que avalia so o modelo ML
    isolado sobre features ELF), esta avalia o sistema inteiro operando
    sobre pacotes .deb reais, incluindo o estagio YARA e a logica Fast-Fail.
    E a metrica mais importante da monografia porque valida a ferramenta
    como produto final, nao apenas um componente."""

    y_real = df["rotulo_real"]
    y_pred = calcular_predicao_pipeline(df)

    cm = confusion_matrix(y_real, y_pred, labels=[0, 1])

    fig, ax = plt.subplots(figsize=(6, 5))
    sns.heatmap(
        cm,
        annot=True,
        fmt="d",
        cmap="Blues",
        xticklabels=["benigno", "malicioso"],
        yticklabels=["benigno", "malicioso"],
        ax=ax,
    )
    ax.set_xlabel("Predito pelo pipeline")
    ax.set_ylabel("Rotulo real")
    ax.set_title("Matriz de Confusao — Pipeline LPTS (YARA + ML)")
    fig.tight_layout()

    caminho = RESULTADO_DIR / "matriz_confusao_pipeline.png"
    fig.savefig(caminho, dpi=150)
    plt.close(fig)
    print(f"  Salvo: {caminho}")


def grafico_distribuicao_resultados(df: pd.DataFrame) -> None:
    """Grafico 2: Barras empilhadas mostrando como cada conjunto foi classificado.

    Eixo X: dois grupos — "Amostras Maliciosas" e "Amostras Benignas".
    Barras empilhadas: proporcao de ALERTA_VERMELHO, ALERTA_LARANJA e LIMPO.

    Para o conjunto malicioso, o ideal e que LIMPO seja zero (deteccao total).
    Para o conjunto benigno, o ideal e que so tenha LIMPO (zero falsos positivos).
    Qualquer desvio desses ideais fica visualmente obvio no grafico."""

    # Conta quantos pacotes de cada conjunto receberam cada veredito
    contagens = (
        df.groupby(["rotulo_real", "resultado"])
        .size()
        .unstack(fill_value=0)
    )

    # Garante que as tres colunas existam mesmo que algum veredito nao apareca
    for veredito in CORES_VEREDITO:
        if veredito not in contagens.columns:
            contagens[veredito] = 0

    # Ordena as colunas na ordem de severidade (vermelho, laranja, verde)
    contagens = contagens[["ALERTA_VERMELHO", "ALERTA_LARANJA", "LIMPO"]]
    contagens.index = contagens.index.map({1: "Amostras\nMaliciosas", 0: "Amostras\nBenignas"})

    fig, ax = plt.subplots(figsize=(7, 5))
    contagens.plot(
        kind="bar",
        stacked=True,
        color=[CORES_VEREDITO[c] for c in contagens.columns],
        ax=ax,
        edgecolor="white",
        linewidth=0.5,
    )

    ax.set_ylabel("Quantidade de pacotes")
    ax.set_title("Distribuicao de Resultados por Conjunto de Amostras")
    ax.legend(title="Veredito", loc="upper right")
    ax.set_xticklabels(ax.get_xticklabels(), rotation=0)

    # Adiciona o total acima de cada barra para referencia
    for i, total in enumerate(contagens.sum(axis=1)):
        ax.text(i, total + 0.5, f"n={total}", ha="center", fontsize=9)

    fig.tight_layout()

    caminho = RESULTADO_DIR / "distribuicao_resultados.png"
    fig.savefig(caminho, dpi=150)
    plt.close(fig)
    print(f"  Salvo: {caminho}")


def grafico_histograma_tempos(df: pd.DataFrame) -> None:
    """Grafico 3: Histograma do tempo de execucao por pacote.

    Valida o RNF01 (performance aceitavel). Mostra a distribuicao dos tempos
    de analise para que a monografia possa afirmar, por exemplo, "95% dos
    pacotes foram analisados em menos de X ms".

    Separa por conjunto (malicioso/benigno) para revelar se ha diferenca
    de performance entre os dois — pacotes maliciosos com ALERTA_VERMELHO
    tendem a ser mais rapidos porque o pipeline aborta no YARA (Fast-Fail)
    sem precisar rodar o estagio de ML."""

    fig, ax = plt.subplots(figsize=(8, 5))

    tempos_mal = df[df["rotulo_real"] == 1]["tempo_ms"]
    tempos_ben = df[df["rotulo_real"] == 0]["tempo_ms"]

    # Bins compartilhados para que as distribuicoes sejam comparaveis visualmente.
    # O range vai de 0 ate o tempo maximo observado, com 30 divisoes.
    tempo_max = df["tempo_ms"].max()
    bins = np.linspace(0, tempo_max, 30)

    ax.hist(tempos_mal, bins=bins, alpha=0.7, label="Maliciosos", color="#d62728")
    ax.hist(tempos_ben, bins=bins, alpha=0.7, label="Benignos", color="#2ca02c")

    ax.set_xlabel("Tempo de analise (ms)")
    ax.set_ylabel("Quantidade de pacotes")
    ax.set_title("Distribuicao do Tempo de Execucao por Pacote")
    ax.legend()

    # Linha vertical com a mediana geral para referencia rapida
    mediana = df["tempo_ms"].median()
    ax.axvline(mediana, color="black", linestyle="--", linewidth=1)
    ax.text(
        mediana, ax.get_ylim()[1] * 0.9,
        f"  mediana: {mediana:.0f} ms",
        fontsize=9,
    )

    fig.tight_layout()

    caminho = RESULTADO_DIR / "histograma_tempos.png"
    fig.savefig(caminho, dpi=150)
    plt.close(fig)
    print(f"  Salvo: {caminho}")


def grafico_yara_vs_ml(df: pd.DataFrame) -> None:
    """Grafico 4: Contribuicao do YARA vs ML na deteccao de malware.

    Mostra quantas amostras maliciosas foram detectadas por cada estagio.
    Justifica a arquitetura hibrida na monografia: se o YARA sozinho pegasse
    tudo, o ML seria desnecessario; se o ML pegasse tudo, o YARA seria
    desnecessario. O valor da ferramenta esta na complementaridade.

    So considera amostras realmente maliciosas (rotulo_real == 1), porque
    o objetivo e medir a contribuicao de cada estagio na DETECCAO, nao
    nos falsos positivos."""

    maliciosos = df[df["rotulo_real"] == 1]
    total = len(maliciosos)

    if total == 0:
        print("  [!] Nenhuma amostra maliciosa — grafico YARA vs ML ignorado.")
        return

    por_yara = (maliciosos["resultado"] == "ALERTA_VERMELHO").sum()
    por_ml = (maliciosos["resultado"] == "ALERTA_LARANJA").sum()
    nao_detectados = (maliciosos["resultado"] == "LIMPO").sum()

    categorias = ["YARA\n(assinatura)", "ML\n(heuristica)", "Nao detectado"]
    valores = [por_yara, por_ml, nao_detectados]
    cores = ["#d62728", "#ff7f0e", "#999999"]

    fig, ax = plt.subplots(figsize=(7, 5))
    barras = ax.bar(categorias, valores, color=cores, edgecolor="white", width=0.5)

    # Percentual acima de cada barra para leitura direta
    for barra, valor in zip(barras, valores):
        pct = (valor / total) * 100
        ax.text(
            barra.get_x() + barra.get_width() / 2,
            barra.get_height() + 0.3,
            f"{valor} ({pct:.1f}%)",
            ha="center",
            fontsize=10,
        )

    ax.set_ylabel("Quantidade de pacotes maliciosos")
    ax.set_title(f"Contribuicao na Deteccao de Malware (n={total})")
    fig.tight_layout()

    caminho = RESULTADO_DIR / "deteccao_yara_vs_ml.png"
    fig.savefig(caminho, dpi=150)
    plt.close(fig)
    print(f"  Salvo: {caminho}")


def gerar_metricas_txt(df: pd.DataFrame) -> None:
    """Tabela-resumo com as metricas de validacao citadas no pre-projeto.

    Calcula taxa de deteccao (recall), taxa de falsos positivos (FPR) e
    estatisticas de tempo de execucao. Essas sao as metricas que o
    pre-projeto se comprometeu a apresentar na secao de metodologia."""

    y_real = df["rotulo_real"]
    y_pred = calcular_predicao_pipeline(df)

    # Verdadeiros/Falsos positivos e negativos
    vp = ((y_pred == 1) & (y_real == 1)).sum()  # malicioso detectado corretamente
    fp = ((y_pred == 1) & (y_real == 0)).sum()  # benigno classificado como malicioso
    vn = ((y_pred == 0) & (y_real == 0)).sum()  # benigno classificado como limpo
    fn = ((y_pred == 0) & (y_real == 1)).sum()  # malicioso que passou despercebido

    total_maliciosos = (y_real == 1).sum()
    total_benignos = (y_real == 0).sum()

    # Taxa de deteccao = VP / (VP + FN): percentual de malware que a ferramenta pegou.
    # E o recall do pre-projeto. Quanto mais proximo de 100%, melhor.
    taxa_deteccao = vp / total_maliciosos if total_maliciosos > 0 else 0.0

    # Taxa de falsos positivos = FP / (FP + VN): percentual de software benigno
    # que foi incorretamente bloqueado. Quanto mais proximo de 0%, melhor.
    taxa_fp = fp / total_benignos if total_benignos > 0 else 0.0

    # Precisao = VP / (VP + FP): quando a ferramenta diz "malicioso", com que
    # frequencia ela esta certa. Complementa as duas metricas acima.
    precisao = vp / (vp + fp) if (vp + fp) > 0 else 0.0

    # F1-Score: media harmonica entre precisao e recall. Penaliza desbalanco
    # entre as duas — um F1 alto garante que ambas sao boas simultaneamente.
    f1 = 2 * (precisao * taxa_deteccao) / (precisao + taxa_deteccao) if (precisao + taxa_deteccao) > 0 else 0.0

    # Detalhamento por estagio: quantos o YARA pegou vs quantos o ML pegou
    maliciosos_df = df[df["rotulo_real"] == 1]
    deteccoes_yara = (maliciosos_df["resultado"] == "ALERTA_VERMELHO").sum()
    deteccoes_ml = (maliciosos_df["resultado"] == "ALERTA_LARANJA").sum()

    tempos = df["tempo_ms"]

    texto = (
        "=" * 60 + "\n"
        "  LPTS - Metricas de Validacao do Pipeline\n"
        "=" * 60 + "\n"
        "\n"
        "--- Conjunto de Dados ---\n"
        f"  Amostras maliciosas: {total_maliciosos}\n"
        f"  Amostras benignas:   {total_benignos}\n"
        f"  Total:               {len(df)}\n"
        "\n"
        "--- Metricas do Pipeline (YARA + ML) ---\n"
        f"  Taxa de deteccao (recall): {taxa_deteccao:.4f} ({taxa_deteccao*100:.1f}%)\n"
        f"  Taxa de falsos positivos:  {taxa_fp:.4f} ({taxa_fp*100:.1f}%)\n"
        f"  Precisao:                  {precisao:.4f} ({precisao*100:.1f}%)\n"
        f"  F1-Score:                  {f1:.4f}\n"
        "\n"
        "--- Detalhamento da Deteccao ---\n"
        f"  Verdadeiros positivos: {vp}\n"
        f"  Falsos positivos:      {fp}\n"
        f"  Verdadeiros negativos: {vn}\n"
        f"  Falsos negativos:      {fn}\n"
        "\n"
        "--- Contribuicao por Estagio (sobre amostras maliciosas) ---\n"
        f"  Detectados por YARA (assinatura):   {deteccoes_yara}\n"
        f"  Detectados por ML (heuristica):     {deteccoes_ml}\n"
        f"  Nao detectados:                     {fn}\n"
        "\n"
        "--- Tempo de Execucao (ms) ---\n"
        f"  Minimo:   {tempos.min():.0f} ms\n"
        f"  Mediana:  {tempos.median():.0f} ms\n"
        f"  Media:    {tempos.mean():.0f} ms\n"
        f"  Maximo:   {tempos.max():.0f} ms\n"
        f"  P95:      {tempos.quantile(0.95):.0f} ms\n"
        "=" * 60 + "\n"
    )

    caminho = RESULTADO_DIR / "metricas_pipeline.txt"
    caminho.write_text(texto)
    print(f"\n{texto}")
    print(f"  Salvo: {caminho}")


def main() -> None:
    if len(sys.argv) != 3:
        print(f"Uso: python {sys.argv[0]} <resultado_maliciosos.csv> <resultado_benignos.csv>")
        print()
        print("Os CSVs sao gerados pelo comando `lpts benchmark`:")
        print("  lpts benchmark amostras/maliciosos --saida resultado_maliciosos.csv")
        print("  lpts benchmark amostras/benignos   --saida resultado_benignos.csv")
        sys.exit(1)

    caminho_maliciosos = Path(sys.argv[1])
    caminho_benignos = Path(sys.argv[2])

    RESULTADO_DIR.mkdir(exist_ok=True)

    print("=" * 60)
    print("LPTS - Avaliador de Resultados do Pipeline")
    print("=" * 60)

    print("\n[1/6] Carregando CSVs de benchmark...")
    df = carregar_csvs(caminho_maliciosos, caminho_benignos)

    print("\n[2/6] Gerando matriz de confusao do pipeline...")
    grafico_matriz_confusao(df)

    print("\n[3/6] Gerando distribuicao de resultados...")
    grafico_distribuicao_resultados(df)

    print("\n[4/6] Gerando histograma de tempos...")
    grafico_histograma_tempos(df)

    print("\n[5/6] Gerando grafico YARA vs ML...")
    grafico_yara_vs_ml(df)

    print("\n[6/6] Calculando metricas de validacao...")
    gerar_metricas_txt(df)

    print("\nConcluido! Graficos salvos em:", RESULTADO_DIR)


if __name__ == "__main__":
    main()
