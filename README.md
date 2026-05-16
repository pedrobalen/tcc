# LPTS - Linux Package Threat Scanner

Scanner de ameaças em pacotes `.deb` que combina detecção por assinaturas YARA com classificação por Machine Learning (Random Forest via ONNX).

## Instalação

### Binário pré-compilado

Baixe o binário da [página de Releases](../../releases) e extraia:

```bash
tar xzf lpts-linux-x64.tar.gz
sudo mv lpts /usr/local/bin/
```

### Dependência: ONNX Runtime

Requer a biblioteca ONNX Runtime 1.17+ instalada no sistema:

```bash
# Ubuntu/Debian
curl -L -o ort.tgz https://github.com/microsoft/onnxruntime/releases/download/v1.17.3/onnxruntime-linux-x64-1.17.3.tgz
tar xzf ort.tgz
sudo cp onnxruntime-linux-x64-1.17.3/lib/libonnxruntime.so* /usr/local/lib/
sudo ldconfig
```

### Build from source

```bash
git clone <url-do-repositorio>
cd tcc/scanner
export ORT_DYLIB_PATH=/usr/local/lib/libonnxruntime.so
cargo build --release
```

O binário estará em `target/release/lpts`.

## Uso

### Analisar um pacote

```bash
lpts scan pacote.deb
```

### Varredura em lote com relatório CSV

```bash
lpts benchmark diretorio_com_debs/ --saida resultados.csv
```

## Como funciona

1. **Extração** -- o pacote `.deb` é descompactado em um diretório temporário.
2. **Estágio 1 (YARA)** -- os arquivos são varridos contra regras de assinatura embutidas. Se houver match, emite alerta vermelho e aborta (Fast-Fail).
3. **Estágio 2 (ML)** -- as features dos binários ELF (tamanho, entropia, seções, importações) são extraídas e classificadas pelo modelo Random Forest. Se malicioso, emite alerta laranja.
