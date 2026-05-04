# Metodologia de Machine Learning — LPTS

## 1. Dataset

| Classe | Fonte | Amostras | Rótulo |
|---|---|---|---|
| Benigno | Binários ELF extraídos de pacotes `.deb` oficiais do repositório Debian (utilitários do sistema: binutils, findutils, gawk, grep, net-tools, procps, util-linux, etc.) | 191 | 0 |
| Malicioso | Amostras ELF reais baixadas do MalwareBazaar (abuse.ch) via API | 98 | 1 |
| **Total** | | **289** | |

A divisão treino/teste foi **80/20 estratificada** (231 treino, 58 teste), garantindo a proporção das classes em ambos os conjuntos.

---

## 2. Features Extraídas

Quatro features estruturais foram extraídas de cada binário ELF. A escolha foi guiada por dois critérios: (1) deriváveis puramente de análise estática, sem execução; (2) comprovadamente discriminativas na literatura de detecção de malware.

| Feature | Tipo | Descrição | Relevância |
|---|---|---|---|
| `tamanho` | Inteiro (bytes) | Tamanho bruto do arquivo | Malware compacto ou inflado artificialmente |
| `entropia` | Float (0–8) | Entropia de Shannon sobre os bytes brutos | Valores próximos de 8 indicam conteúdo cifrado/comprimido (packing, ofuscação) |
| `num_secoes` | Inteiro | Número de seções no cabeçalho ELF | Binários empacotados ou gerados por ofuscadores têm estrutura atípica |
| `num_importacoes` | Inteiro | Símbolos indefinidos em `.dynsym` (importações dinâmicas) | Binários packed têm pouquíssimas importações; malware de funcionalidade ampla tem muitas |

As features são extraídas pelo módulo `features.rs` do motor Rust e pelo script `extrator_features.py` do laboratório, usando a mesma lógica de cálculo para garantir consistência entre treinamento e inferência.

### Importância das features (resultado do treinamento)

| Feature | Importância |
|---|---|
| `num_secoes` | 47,09% |
| `num_importacoes` | 41,85% |
| `entropia` | 9,60% |
| `tamanho` | 1,47% |

`num_secoes` e `num_importacoes` dominam a classificação, o que é consistente com a literatura: malware empacotado colapsa seções e elimina importações dinâmicas como técnica de evasão.

---

## 3. Algoritmo: Random Forest

O algoritmo escolhido foi o **Random Forest** (scikit-learn, 100 árvores, profundidade máxima 10).

### Por que Random Forest?

- **Tabular e interpretável:** opera diretamente sobre o vetor de features numéricas sem necessidade de normalização ou embedding; as importâncias de features são diretamente extraíveis.
- **Robusto a overfitting em datasets pequenos:** o mecanismo de bagging (bootstrap aggregating) e a seleção aleatória de features por árvore reduz a variância mesmo com ~300 amostras.
- **Exportável para ONNX:** suporte nativo via `skl2onnx`, permitindo inferência no motor Rust sem dependência do ecossistema Python em produção.
- **Sem necessidade de GPU:** inferência leve e determinística, adequada para execução local no fluxo de instalação de pacotes.

O modelo foi exportado no formato `.onnx` com entrada `float32 [1, 4]` e saídas `output_label` (int64) e `output_probability` (float32), compatíveis com o runtime `ort` do motor Rust.

---

## 4. Resultados do Treinamento

```
Acuracia:  1.0000
Precisao:  1.0000
Recall:    1.0000
F1-Score:  1.0000
```

A acurácia perfeita no conjunto de teste reflete a separabilidade das classes com as features escolhidas e o tamanho reduzido do dataset. Em produção, a camada ML opera como **segundo estágio** (após YARA), portanto falsos positivos têm impacto controlado.

---

## 5. Detecção Heurística vs. Análise por Assinatura

O LPTS combina duas abordagens complementares em um pipeline **Fast-Fail**:

### Análise por assinatura (YARA) — Estágio 1

Busca padrões **exatos e conhecidos** nos bytes dos arquivos extraídos: strings de reverse shell, sequências hexadecimais de empacotadores, expressões regulares de endereços de carteiras de criptomoeda, etc.

- **Determinístico:** se o padrão está presente, a regra dispara — sem margem de erro.
- **Limitação:** só detecta **ameaças conhecidas**. Uma variante que renomeia strings ou recompila o binário pode escapar completamente.

### Detecção heurística por aprendizado estatístico (Random Forest) — Estágio 2

Ao invés de buscar um padrão fixo, o modelo aprende **fronteiras de decisão** a partir de combinações de features estruturais que separam binários benignos de maliciosos no espaço de treinamento.

- **Probabilístico:** produz uma confiança (0–100%) em vez de verdadeiro/falso.
- **Generalização:** consegue classificar amostras **nunca vistas antes**, desde que sigam padrões estruturais similares aos do treino (ex: um novo malware que também usa packing terá alta entropia e poucas importações).
- **Limitação:** sujeito a falsos positivos e dependente da qualidade e diversidade do dataset de treinamento.

### Diferença fundamental

| | Assinatura (YARA) | Heurística ML (Random Forest) |
|---|---|---|
| Base de decisão | Padrão exato no arquivo | Combinação estatística de features |
| Tipo de ameaça detectada | Conhecida | Conhecida e variantes desconhecidas |
| Resultado | Binário (match / no match) | Probabilístico (score de confiança) |
| Falso positivo | Praticamente zero | Possível |
| Custo de atualização | Escrever nova regra YARA | Retreinar com novas amostras |

A heurística ML **não substitui** a análise por assinatura: ela a complementa, cobrindo a camada de ameaças emergentes e variantes que nenhuma regra explícita ainda descreve.
