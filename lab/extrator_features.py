"""
Extrator de features estaticas de binarios ELF.

Le binarios de um diretorio, extrai quatro features estruturais e gera
um CSV compativel com o vetor esperado pelo motor Rust (features.rs):

  - tamanho:         tamanho bruto do arquivo em bytes
  - entropia:        entropia de Shannon (0–8); valores altos indicam
                     conteudo cifrado/comprimido, caracteristico de malware packed
  - num_secoes:      numero de secoes ELF; malware costuma ter estrutura atipica
  - num_importacoes: simbolos indefinidos em .dynsym (importacoes dinamicas);
                     binarios packed tem pouquissimas importacoes

Arquivos que nao sao ELF validos sao silenciosamente ignorados.

Uso:
  python extrator_features.py <dir_binarios> <rotulo> <saida.csv>

  rotulo: 0 = benigno, 1 = malicioso
"""

import math
import sys
from pathlib import Path

from elftools.elf.elffile import ELFFile

COLUNAS = ["tamanho", "entropia", "num_secoes", "num_importacoes", "rotulo"]

MAGIC_ELF = b"\x7fELF"


def calcular_entropia(dados: bytes) -> float:
    if not dados:
        return 0.0
    freq = [0] * 256
    for b in dados:
        freq[b] += 1
    total = len(dados)
    return -sum((c / total) * math.log2(c / total) for c in freq if c > 0)


def extrair_features(caminho: Path) -> list[float] | None:
    """Retorna [tamanho, entropia, num_secoes, num_importacoes] ou None."""
    dados = caminho.read_bytes()
    if dados[:4] != MAGIC_ELF:
        return None
    try:
        with caminho.open("rb") as f:
            elf = ELFFile(f)
            num_secoes = elf.num_sections()

            # Importacoes dinamicas: simbolos com shndx indefinido em .dynsym,
            # equivalente a goblin's is_import() no motor Rust.
            secao_dynsym = elf.get_section_by_name(".dynsym")
            num_importacoes = (
                sum(1 for s in secao_dynsym.iter_symbols() if s.entry["st_shndx"] == "SHN_UNDEF")
                if secao_dynsym
                else 0
            )

        return [
            float(len(dados)),
            calcular_entropia(dados),
            float(num_secoes),
            float(num_importacoes),
        ]
    except Exception:
        return None


def processar_diretorio(dir_binarios: Path, rotulo: int) -> list[dict]:
    arquivos = sorted(dir_binarios.iterdir())
    resultados = []
    ignorados = 0

    for caminho in arquivos:
        if not caminho.is_file():
            continue
        features = extrair_features(caminho)
        if features is None:
            ignorados += 1
            continue
        tamanho, entropia, num_secoes, num_importacoes = features
        resultados.append({
            "tamanho": tamanho,
            "entropia": entropia,
            "num_secoes": num_secoes,
            "num_importacoes": num_importacoes,
            "rotulo": rotulo,
        })

    print(f"  [{dir_binarios.name}] {len(resultados)} ELFs processados, {ignorados} ignorados")
    return resultados


def salvar_csv(resultados: list[dict], saida: Path) -> None:
    with open(saida, "w") as f:
        f.write(",".join(COLUNAS) + "\n")
        for r in resultados:
            f.write(",".join(str(r[c]) for c in COLUNAS) + "\n")
    print(f"  [{saida.name}] {len(resultados)} registros salvos")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(f"Uso: python {sys.argv[0]} <dir_binarios> <rotulo> <saida.csv>")
        print("  rotulo: 0 = benigno, 1 = malicioso")
        sys.exit(1)

    dir_binarios = Path(sys.argv[1])
    rotulo = int(sys.argv[2])
    saida = Path(sys.argv[3])

    if not dir_binarios.is_dir():
        print(f"Erro: {dir_binarios} nao e um diretorio valido")
        sys.exit(1)

    resultados = processar_diretorio(dir_binarios, rotulo)
    if not resultados:
        print("Nenhum binario ELF valido encontrado.")
        sys.exit(1)

    salvar_csv(resultados, saida)
