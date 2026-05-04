"""
Baixa amostras de malware ELF do MalwareBazaar (abuse.ch).

O MalwareBazaar e um repositorio publico e gratuito de amostras de malware
mantido pela abuse.ch. A API requer autenticacao via Auth-Key (gratuita).

Para obter a Auth-Key:
  1. Crie uma conta em bazaar.abuse.ch
  2. Acesse o perfil e copie a Auth-Key
  3. Passe via --api-key ou defina a variavel MALWAREBAZAAR_API_KEY no .env

Fluxo:
  1. Consulta a API por amostras do tipo "elf"
  2. Baixa cada amostra (ZIP protegido com senha "infected")
  3. Extrai o binario e salva em dataset/maliciosos/

Uso:
  python baixar_maliciosos.py [--api-key <KEY>] [--limite 100]
"""

import argparse
import io
import os
import sys
import time
from pathlib import Path

import pyzipper
import requests

LAB_DIR = Path(__file__).parent
SAIDA = LAB_DIR / "dataset" / "maliciosos"

# Carrega variaveis do .env sem sobrescrever o ambiente do sistema.
_env_file = LAB_DIR / ".env"
if _env_file.exists():
    for _linha in _env_file.read_text().splitlines():
        _linha = _linha.strip()
        if _linha and not _linha.startswith("#") and "=" in _linha:
            _chave, _, _valor = _linha.partition("=")
            os.environ.setdefault(_chave.strip(), _valor.strip())

API_URL = "https://mb-api.abuse.ch/api/v1/"
ZIP_SENHA = b"infected"
ELF_MAGIC = b"\x7fELF"


def _headers(api_key: str) -> dict:
    return {"User-Agent": "lpts-lab/1.0", "Auth-Key": api_key}


def _post_com_retry(data: dict, api_key: str, tentativas: int = 5, timeout: int = 60) -> requests.Response:
    """POST com retry exponencial para absorver instabilidades do servidor."""
    for i in range(tentativas):
        try:
            resp = requests.post(API_URL, data=data, headers=_headers(api_key), timeout=timeout)
            if resp.status_code < 500:
                return resp
            print(f"  [retry {i+1}/{tentativas}] servidor retornou {resp.status_code}, aguardando...")
        except requests.exceptions.Timeout:
            print(f"  [retry {i+1}/{tentativas}] timeout, aguardando...")
        except requests.exceptions.ConnectionError:
            print(f"  [retry {i+1}/{tentativas}] erro de conexao, aguardando...")
        time.sleep(10 * (i + 1))
    raise RuntimeError(f"API indisponivel apos {tentativas} tentativas")


def consultar_hashes(limite: int, api_key: str) -> list[dict]:
    resp = _post_com_retry(
        {"query": "get_file_type", "file_type": "elf", "limit": limite},
        api_key,
        timeout=60,
    )
    resp.raise_for_status()
    resultado = resp.json()

    if resultado.get("query_status") != "ok":
        print(f"  Erro na consulta: {resultado.get('query_status')}")
        return []

    amostras = resultado.get("data", [])
    print(f"  {len(amostras)} amostras ELF encontradas na API")
    return amostras


def baixar_amostra(sha256: str, api_key: str) -> bytes | None:
    try:
        resp = _post_com_retry(
            {"query": "get_file", "sha256_hash": sha256},
            api_key,
            timeout=90,
        )
        if resp.ok and resp.content[:2] == b"PK":
            return resp.content
    except Exception:
        pass
    return None


def extrair_elf_do_zip(dados_zip: bytes) -> bytes | None:
    # MalwareBazaar usa AES-256 (metodo 99), que o zipfile padrao nao suporta.
    try:
        with pyzipper.AESZipFile(io.BytesIO(dados_zip)) as zf:
            for nome in zf.namelist():
                conteudo = zf.read(nome, pwd=ZIP_SENHA)
                if conteudo[:4] == ELF_MAGIC:
                    return conteudo
    except Exception:
        pass
    return None


def main():
    parser = argparse.ArgumentParser(
        description="Baixa amostras ELF maliciosas do MalwareBazaar"
    )
    parser.add_argument(
        "--limite", type=int, default=100,
        help="Quantidade de amostras para consultar (padrao: 100, max: 1000)",
    )
    parser.add_argument(
        "--api-key", type=str, default=os.environ.get("MALWAREBAZAAR_API_KEY", ""),
        help="Auth-Key do MalwareBazaar (ou defina MALWAREBAZAAR_API_KEY no .env)",
    )
    args = parser.parse_args()

    if not args.api_key:
        print("Erro: Auth-Key nao fornecida.")
        print("  Use --api-key <KEY> ou defina MALWAREBAZAAR_API_KEY no lab/.env")
        sys.exit(1)

    print("=" * 50)
    print("LPTS - Download de amostras maliciosas")
    print("=" * 50)

    SAIDA.mkdir(parents=True, exist_ok=True)

    print(f"\n[1/2] Consultando API MalwareBazaar (limite={args.limite})...")
    amostras = consultar_hashes(args.limite, args.api_key)

    if not amostras:
        print("  Nenhuma amostra encontrada.")
        sys.exit(1)

    print(f"\n[2/2] Baixando e extraindo binarios ELF...")
    sucesso = 0
    falhas = 0

    for i, amostra in enumerate(amostras, 1):
        sha256 = amostra["sha256_hash"]
        nome = sha256[:16]
        destino = SAIDA / nome

        if destino.exists():
            print(f"  [{i}/{len(amostras)}] {nome} — ja existe, pulando")
            sucesso += 1
            continue

        print(f"  [{i}/{len(amostras)}] {nome}...", end=" ", flush=True)

        dados_zip = baixar_amostra(sha256, args.api_key)
        if dados_zip is None:
            print("FALHA (download)")
            falhas += 1
            time.sleep(0.5)
            continue

        elf = extrair_elf_do_zip(dados_zip)
        if elf is None:
            print("FALHA (nao e ELF)")
            falhas += 1
            time.sleep(0.5)
            continue

        destino.write_bytes(elf)
        print(f"OK ({len(elf):,} bytes)")
        sucesso += 1
        time.sleep(0.5)

    print(f"\nResultado: {sucesso} sucesso, {falhas} falhas")
    print("Concluido!")


if __name__ == "__main__":
    main()
