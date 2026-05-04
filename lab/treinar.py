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


def avaliar_modelo(modelo, X_teste, y_teste) -> None:
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

    cm = confusion_matrix(y_teste, y_pred)
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
    ax.set_xlabel("Predito")
    ax.set_ylabel("Real")
    ax.set_title("Matriz de Confusao — LPTS")
    fig.tight_layout()

    caminho_figura = RESULTADO_DIR / "matriz_confusao.png"
    fig.savefig(caminho_figura, dpi=150)
    plt.close(fig)
    print(f"  Matriz de confusao salva em {caminho_figura}")


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
    avaliar_modelo(modelo, X_teste, y_teste)

    print("\nExportando para ONNX...")
    exportar_onnx(modelo)

    print("\nConcluido!")


if __name__ == "__main__":
    main()
