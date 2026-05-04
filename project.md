# 📋 Documento de Planejamento: Linux Package Threat Scanner (LPTS)

## 1. Visão Geral do Projeto
Desenvolvimento de uma ferramenta de segurança em nível de sistema operacional capaz de interceptar e analisar pacotes de instalação Linux (`.deb`) antes de sua execução. O sistema utiliza uma arquitetura híbrida focada em performance (Fast-Fail), combinando detecção determinística por assinaturas e detecção probabilística via Machine Learning.

---

## 2. Arquitetura de Software e Divisão de Papéis

O projeto é estritamente dividido em dois ecossistemas para maximizar a eficiência de engenharia e a capacidade de análise científica:

### A. Laboratório de Pesquisa e Análise (Python)
Ambiente offline utilizado exclusivamente pelo pesquisador.
* **Função 1 (Treinamento):** Ler o dataset de malwares e binários benignos, treinar o algoritmo Random Forest e exportar o modelo para o formato padronizado `.onnx`.
* **Função 2 (Avaliação):** Ler os arquivos de saída (`.csv`) gerados pelo motor principal e utilizar bibliotecas de visualização para plotar gráficos de eficácia e performance.

### B. Motor de Varredura e Inferência (Rust)
A aplicação de produção, otimizada para I/O e segurança de memória.
* **Função 1 (Desconstrução):** Abrir pacotes `.deb` e extrair a árvore de diretórios e binários internos na memória.
* **Função 2 (Análise Estática):** Executar o motor YARA contra os arquivos extraídos.
* **Função 3 (Extração de Features):** Fazer o parsing de cabeçalhos ELF e calcular métricas matemáticas.
* **Função 4 (Inferência ML):** Carregar o modelo `.onnx` gerado pelo Python, injetar as features extraídas e classificar a ameaça.

---

## 3. Requisitos do Sistema

### 3.1. Requisitos Funcionais (RF)
* **RF01:** O sistema deve extrair nativamente formatos de compressão embutidos no `.deb`.
* **RF02:** O sistema deve possuir um motor de leitura e processamento de regras YARA padronizadas.
* **RF03:** O sistema deve extrair as seguintes features de arquivos ELF:
    * Tamanho do arquivo
    * Entropia de Shannon
    * Contagem de Seções
    * Contagem de Importações Dinâmicas
* **RF04:** O sistema deve carregar um modelo preditivo externo via formato ONNX para realizar inferências locais sem dependência de rede.
* **RF05:** O sistema deve possuir um modo "Benchmark" para varredura em lote que gere um arquivo de relatório em formato `.csv` detalhando as predições e tempos de execução.

### 3.2. Requisitos Não Funcionais (RNF)
* **RNF01 (Performance):** A varredura completa de um pacote não deve exceder um limite de tolerância prático para o usuário final.
* **RNF02 (Arquitetura):** O fluxo de análise deve seguir a lógica Fast-Fail, onde a análise por ML só ocorre se a análise por YARA não encontrar ameaças.
* **RNF03 (Desacoplamento):** O motor em Rust não deve possuir dependências de compilação ou runtime com o ecossistema Python.
* **RNF04 (Usabilidade):** O sistema deve operar via Interface de Linha de Comando (CLI).

---

## 4. Fluxo de Execução Principal (O Pipeline Rust)

1.  **Entrada:** Usuário executa o binário apontando para um alvo.
2.  **Descompressão:** O alvo é validado e seus arquivos internos isolados.
3.  **Estágio 1 (YARA):**
    * Varredura contra o banco de regras.
    * Se `Match == True` -> Aborta análise, emite ALERTA VERMELHO.
    * Se `Match == False` -> Segue para Estágio 2.
4.  **Estágio 2 (Inteligência Artificial):**
    * Leitura estrutural do arquivo e cálculo de Entropia.
    * Montagem do vetor de características.
    * Injeção no motor de inferência ONNX.
    * Se `Predição == 1` -> Emite ALERTA LARANJA (Heurística).
    * Se `Predição == 0` -> Emite SINAL VERDE (Limpo).
5.  **Saída:** Geração do log no terminal ou escrita do registro no `.csv` de auditoria.

---

## 5. Estrutura de Diretórios do Projeto

```text
lpts-tcc-project/
├── laboratório/
│   ├── dataset/
│   │   ├── benignos/
│   │   └── maliciosos/
│   ├── trainer.py
│   ├── evaluator.py
│   └── requirements.txt
├── motor/
│   ├── Cargo.toml
│   ├── src/
│   │   ├── main.rs
│   │   ├── cli.rs
│   │   ├── extrator.rs
│   │   ├── assinaturas.rs
│   │   ├── features.rs
│   │   └── inferencia.rs
├── regras_yara/
│   └── base.yar
└── modelo_ia/
    └── random_forest.onnx