"""
Baixa e extrai binarios ELF benignos a partir de pacotes de um repositorio
Ubuntu. Baixa pacotes comuns do sistema (coreutils, binutils, findutils, etc.)
e extrai os binarios ELF de dentro de cada .deb.

Isso garante centenas de binarios diversificados (ls, grep, gcc, tar, ...)
que sao representativos de software legitimo em Linux.

Uso:
  python baixar_benignos.py

Saida:
  dataset/benignos/ preenchido com binarios ELF extraidos
"""

import io
import gzip
import tarfile
import urllib.request
from pathlib import Path

LAB_DIR = Path(__file__).parent
SAIDA = LAB_DIR / "dataset" / "benignos"

ELF_MAGIC = b"\x7fELF"

MIRROR = "http://archive.ubuntu.com/ubuntu/pool/main"

PACOTES = [
    f"{MIRROR}/c/coreutils/coreutils_9.4-3.1ubuntu1_amd64.deb",
    f"{MIRROR}/b/binutils/binutils-x86-64-linux-gnu_2.42-4ubuntu2_amd64.deb",
    f"{MIRROR}/f/findutils/findutils_4.9.0-5build1_amd64.deb",
    f"{MIRROR}/g/grep/grep_3.11-4build1_amd64.deb",
    f"{MIRROR}/g/gawk/gawk_5.2.1-2build3_amd64.deb",
    f"{MIRROR}/s/sed/sed_4.9-2build1_amd64.deb",
    f"{MIRROR}/t/tar/tar_1.35+dfsg-3build1_amd64.deb",
    f"{MIRROR}/g/gzip/gzip_1.12-1.1ubuntu1_amd64.deb",
    f"{MIRROR}/d/diffutils/diffutils_3.10-1build1_amd64.deb",
    f"{MIRROR}/p/patch/patch_2.7.6-7build3_amd64.deb",
    f"{MIRROR}/f/file/file_5.45-3build1_amd64.deb",
    f"{MIRROR}/n/net-tools/net-tools_2.10-0.1ubuntu4_amd64.deb",
    f"{MIRROR}/p/procps/procps_4.0.4-4ubuntu3_amd64.deb",
    f"{MIRROR}/u/util-linux/util-linux_2.39.3-9ubuntu6_amd64.deb",
    f"{MIRROR}/i/iproute2/iproute2_6.1.0-1ubuntu6_amd64.deb",
    f"{MIRROR}/c/curl/curl_8.5.0-2ubuntu10.1_amd64.deb",
    f"{MIRROR}/o/openssh/openssh-client_9.6p1-3ubuntu13_amd64.deb",
    f"{MIRROR}/g/git/git_2.43.0-1ubuntu7_amd64.deb",
    f"{MIRROR}/s/strace/strace_6.7-0.1ubuntu2_amd64.deb",
    f"{MIRROR}/l/lsof/lsof_4.98.0-4build1_amd64.deb",
]


def baixar(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "lpts-lab/1.0"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read()


def extrair_elfs_do_deb(dados_deb: bytes) -> list[tuple[str, bytes]]:
    """Extrai binarios ELF de um .deb (ar archive > data.tar.* > ELFs)."""
    import struct

    resultados = []

    if not dados_deb.startswith(b"!<arch>\n"):
        return resultados

    pos = 8
    data_tar = None
    data_nome = None

    while pos < len(dados_deb):
        if pos + 60 > len(dados_deb):
            break

        header = dados_deb[pos:pos + 60]
        nome = header[0:16].decode("ascii", errors="replace").strip().rstrip("/")
        try:
            tamanho = int(header[48:58].decode("ascii").strip())
        except ValueError:
            break

        pos += 60
        conteudo = dados_deb[pos:pos + tamanho]
        pos += tamanho
        if tamanho % 2 != 0:
            pos += 1

        if nome.startswith("data.tar"):
            data_tar = conteudo
            data_nome = nome
            break

    if data_tar is None:
        return resultados

    try:
        if data_nome.endswith(".gz"):
            tar_data = gzip.decompress(data_tar)
        elif data_nome.endswith(".xz"):
            import lzma
            tar_data = lzma.decompress(data_tar)
        elif data_nome.endswith(".zst"):
            import zstandard
            dctx = zstandard.ZstdDecompressor()
            tar_data = dctx.decompress(data_tar, max_output_size=100 * 1024 * 1024)
        else:
            tar_data = data_tar

        with tarfile.open(fileobj=io.BytesIO(tar_data), mode="r:") as tar:
            for membro in tar.getmembers():
                if not membro.isfile() or membro.size < 1000:
                    continue

                f = tar.extractfile(membro)
                if f is None:
                    continue

                dados = f.read()
                if dados[:4] == ELF_MAGIC:
                    nome_limpo = membro.name.replace("/", "_").lstrip("._")
                    resultados.append((nome_limpo, dados))
    except Exception as e:
        pass

    return resultados


def main():
    print("=" * 50)
    print("LPTS - Download de binarios benignos")
    print("=" * 50)

    SAIDA.mkdir(parents=True, exist_ok=True)
    total_elfs = 0

    for i, url in enumerate(PACOTES, 1):
        nome_pacote = url.split("/")[-1]
        print(f"\n  [{i}/{len(PACOTES)}] {nome_pacote}...", end=" ", flush=True)

        try:
            dados = baixar(url)
        except Exception as e:
            print(f"FALHA ({e})")
            continue

        elfs = extrair_elfs_do_deb(dados)

        for nome, conteudo in elfs:
            destino = SAIDA / nome
            if not destino.exists():
                with open(destino, "wb") as f:
                    f.write(conteudo)

        print(f"OK ({len(elfs)} ELFs)")
        total_elfs += len(elfs)

    print(f"\n  Total: {total_elfs} binarios ELF extraidos para {SAIDA}")
    print("Concluido!")


if __name__ == "__main__":
    main()
