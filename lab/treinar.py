"""
Treinamento do modelo Random Forest para classificacao de binarios ELF.

Fluxo:
  1. Carrega os CSVs de features estaticas (benignos + maliciosos)
  2. Divide em treino/teste (80/20, estratificado)
  3. Treina um Random Forest
  4. Avalia com metricas (acuracia, precisao, recall, F1)
  5. Exporta o modelo para ONNX com vetor de entrada [None, 4]

O modelo exportado e compativel com o motor Rust: o scanner injeta um
tensor float32 [1, 4] com [tamanho, entropia, num_secoes, num_importacoes].

Uso:
  python treinar.py

Espera encontrar os CSVs no diretorio dataset/:
  - dataset/benignos.csv    (gerado por extrator_features.py)
  - dataset/maliciosos.csv

Saida:
  - modelo/random_forest.onnx
  - resultado/metricas.txt
  - resultado/matriz_confusao.png
"""

from pathlib import Path

import matplotlib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType

matplotlib.use("Agg")

ESTILO_ACADEMICO = {
    "font.family": "serif",
    "font.serif": ["DejaVu Serif"],
    "font.size": 11,
    "axes.titlesize": 13,
    "axes.labelsize": 12,
    "xtick.labelsize": 10,
    "ytick.labelsize": 10,
    "axes.facecolor": "#FFFFFF",
    "figure.facecolor": "#FFFFFF",
    "axes.edgecolor": "#333333",
    "axes.linewidth": 0.8,
    "axes.grid": True,
    "grid.color": "#CCCCCC",
    "grid.linestyle": ":",
    "grid.linewidth": 0.5,
    "figure.figsize": (6.4, 4.8),
    "figure.dpi": 300,
    "savefig.dpi": 300,
    "savefig.bbox": "tight",
    "savefig.pad_inches": 0.15,
}

NOMES_FEATURES = {
    "tamanho": "Tamanho",
    "entropia": "Entropia",
    "num_secoes": "Seções",
    "num_importacoes": "Importações",
}

PALETA_CLASSES = {"Benigno": "#5B7F95", "Malicioso": "#2C3E50"}

LAB_DIR = Path(__file__).parent
DATASET_DIR = LAB_DIR / "dataset"
MODELO_DIR = LAB_DIR / "modelo"
RESULTADO_DIR = LAB_DIR / "resultado"

# Ordem identica a FeaturesElf::como_vetor() em features.rs
FEATURES = ["tamanho", "entropia", "num_secoes", "num_importacoes"]
ROTULO = "rotulo"

N_ESTIMATORS = 100
MAX_DEPTH = 10
RANDOM_STATE = 42
TEST_SIZE = 0.2


def carregar_dataset() -> pd.DataFrame:
    csvs = sorted(DATASET_DIR.glob("*.csv"))
    if not csvs:
        raise FileNotFoundError(f"Nenhum CSV encontrado em {DATASET_DIR}")

    frames = []
    for csv in csvs:
        df = pd.read_csv(csv)
        print(f"  [{csv.name}] {len(df)} registros (rotulo {sorted(df[ROTULO].unique())})")
        frames.append(df)

    dataset = pd.concat(frames, ignore_index=True)
    print(f"\n  Total: {len(dataset)} registros")
    print(f"  Benignos:    {(dataset[ROTULO] == 0).sum()}")
    print(f"  Maliciosos:  {(dataset[ROTULO] == 1).sum()}")
    return dataset


def treinar_modelo(X_treino, y_treino) -> RandomForestClassifier:
    modelo = RandomForestClassifier(
        n_estimators=N_ESTIMATORS,
        max_depth=MAX_DEPTH,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    modelo.fit(X_treino, y_treino)
    return modelo


def _plotar_matriz_confusao(y_teste, y_pred) -> None:
    cm = confusion_matrix(y_teste, y_pred)

    estilo_sem_grid = {**ESTILO_ACADEMICO, "axes.grid": False}
    with plt.rc_context(estilo_sem_grid):
        fig, ax = plt.subplots(figsize=(5, 4))
        sns.heatmap(
            cm,
            annot=True,
            fmt="d",
            cmap=sns.light_palette("#2C3E50", as_cmap=True),
            xticklabels=["Benigno", "Malicioso"],
            yticklabels=["Benigno", "Malicioso"],
            linewidths=0.8,
            linecolor="#FFFFFF",
            cbar_kws={"shrink": 0.8},
            annot_kws={"fontsize": 16, "fontweight": "bold"},
            ax=ax,
        )
        ax.set_xlabel("Predito")
        ax.set_ylabel("Real")
        ax.set_title("Matriz de Confusão")

        caminho = RESULTADO_DIR / "matriz_confusao.png"
        fig.savefig(caminho)
        plt.close(fig)
        print(f"  Matriz de confusão salva em {caminho}")


def _plotar_importancia_features(modelo) -> None:
    importancias = modelo.feature_importances_
    nomes = [NOMES_FEATURES[f] for f in FEATURES]
    ordem = np.argsort(importancias)

    with plt.rc_context(ESTILO_ACADEMICO):
        fig, ax = plt.subplots(figsize=(6, 3.5))
        barras = ax.barh(
            np.array(nomes)[ordem],
            importancias[ordem],
            color="#5B7F95",
            edgecolor="#2C3E50",
            linewidth=0.6,
            height=0.55,
        )

        for barra in barras:
            largura = barra.get_width()
            ax.text(
                largura + 0.008,
                barra.get_y() + barra.get_height() / 2,
                f"{largura:.1%}",
                va="center",
                fontsize=10,
            )

        ax.set_xlim(0, max(importancias) * 1.18)
        ax.set_xlabel("Importância Relativa")
        ax.set_title("Importância das Features — Random Forest")
        ax.grid(axis="y", visible=False)

        caminho = RESULTADO_DIR / "importancia_features.png"
        fig.savefig(caminho)
        plt.close(fig)
        print(f"  Importância das features salva em {caminho}")


def _plotar_distribuicao_features(dataset: pd.DataFrame) -> None:
    df = dataset.copy()
    df["classe"] = df[ROTULO].map({0: "Benigno", 1: "Malicioso"})

    with plt.rc_context(ESTILO_ACADEMICO):
        fig, axes = plt.subplots(2, 2, figsize=(8, 6))

        for ax, feat in zip(axes.flat, FEATURES):
            sns.boxplot(
                data=df,
                x="classe",
                y=feat,
                hue="classe",
                ax=ax,
                palette=PALETA_CLASSES,
                width=0.45,
                linewidth=0.8,
                flierprops={"marker": "o", "markersize": 4, "alpha": 0.6},
                legend=False,
            )
            ax.set_title(NOMES_FEATURES[feat])
            ax.set_xlabel("")
            ax.set_ylabel("")

        fig.suptitle(
            "Distribuição das Features por Classe",
            fontsize=13,
            y=1.01,
        )
        fig.tight_layout()

        caminho = RESULTADO_DIR / "distribuicao_features.png"
        fig.savefig(caminho)
        plt.close(fig)
        print(f"  Distribuição das features salva em {caminho}")


def avaliar_modelo(modelo, X_teste, y_teste, dataset: pd.DataFrame) -> None:
    RESULTADO_DIR.mkdir(exist_ok=True)
    y_pred = modelo.predict(X_teste)

    acuracia = accuracy_score(y_teste, y_pred)
    precisao = precision_score(y_teste, y_pred)
    recall = recall_score(y_teste, y_pred)
    f1 = f1_score(y_teste, y_pred)
    relatorio = classification_report(y_teste, y_pred, target_names=["benigno", "malicioso"])
    importancias = dict(zip(FEATURES, modelo.feature_importances_))

    texto = (
        f"Acuracia:  {acuracia:.4f}\n"
        f"Precisao:  {precisao:.4f}\n"
        f"Recall:    {recall:.4f}\n"
        f"F1-Score:  {f1:.4f}\n"
        f"\n--- Relatorio de Classificacao ---\n\n{relatorio}\n"
        f"--- Importancia das Features ---\n\n"
    )
    for feat, imp in sorted(importancias.items(), key=lambda x: -x[1]):
        texto += f"  {feat}: {imp:.4f}\n"

    caminho_metricas = RESULTADO_DIR / "metricas.txt"
    caminho_metricas.write_text(texto)
    print(f"\n{texto}")
    print(f"  Metricas salvas em {caminho_metricas}")

    _plotar_matriz_confusao(y_teste, y_pred)
    _plotar_importancia_features(modelo)
    _plotar_distribuicao_features(dataset)


def exportar_onnx(modelo: RandomForestClassifier) -> None:
    """Exporta para ONNX com entrada 'X' float32 [None, 4] e probabilidades
    como tensor float32 (zipmap=False), compativel com inferencia.rs."""
    MODELO_DIR.mkdir(exist_ok=True)

    initial_types = [("X", FloatTensorType([None, 4]))]
    options = {RandomForestClassifier: {"zipmap": False}}

    modelo_onnx = convert_sklearn(
        modelo,
        initial_types=initial_types,
        options=options,
        target_opset=15,
    )

    caminho = MODELO_DIR / "random_forest.onnx"
    caminho.write_bytes(modelo_onnx.SerializeToString())
    print(f"  Modelo ONNX salvo em {caminho}")


def main() -> None:
    print("=" * 60)
    print("LPTS - Treinamento do Modelo Random Forest")
    print("=" * 60)

    print("\n[1/4] Carregando dataset...")
    dataset = carregar_dataset()

    X = dataset[FEATURES].values
    y = dataset[ROTULO].values

    print("\n[2/4] Dividindo treino/teste...")
    X_treino, X_teste, y_treino, y_teste = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )
    print(f"  Treino: {len(X_treino)} | Teste: {len(X_teste)}")

    print("\n[3/4] Treinando modelo...")
    modelo = treinar_modelo(X_treino, y_treino)
    print(f"  Random Forest: {N_ESTIMATORS} arvores, profundidade max {MAX_DEPTH}")

    print("\n[4/4] Avaliando modelo...")
    avaliar_modelo(modelo, X_teste, y_teste, dataset)

    print("\nExportando para ONNX...")
    exportar_onnx(modelo)

    print("\nConcluido!")


if __name__ == "__main__":
    main()
