# Suricata_ML

Projeto para análise de dados de IDS (Intrusion Detection System), integrando Suricata com modelos de Machine Learning para classificação de tráfego de rede e detecção de ataques. Desenvolvido como trabalho final da disciplina Segurança de Sistemas (DCC075-2025.1-A).

## Objetivo

- Coletar e processar dados de rede utilizando Suricata.
- Realizar pré-processamento e extração de features relevantes.
- Treinar e integrar modelos de Machine Learning para classificação automática de tráfego (benigno/maligno).
- Enviar alertas automáticos via Telegram em caso de detecção de ataques.

## Estrutura do Projeto

- `load_dataset.py`: Download e carregamento do dataset CICIDS2017.
- `pre_processing.py`: Limpeza e tratamento dos dados (remoção de nulos, normalização).
- `variables.py`: Definição das features e arquivos utilizados.
- `suricata/extract_flows.py` e `extract_flows2.py`: Extração de fluxos e features dos logs do Suricata.
- `suricata/suricata_classification.py`: Classificação dos fluxos em tempo real e envio de alertas.
- `src/capture/traffic_capture.py`: Captura modular com cicflowmeter por 60 segundos e validação visual do CSV.
- `.env.example`: Variáveis de ambiente obrigatórias para execução em diferentes máquinas.
- `requirements.txt`: Lista de dependências do projeto.
- `main.ipynb`: Notebook para experimentação e análise.

## Instalação

Requisitos: Python 3.11

```bash
git clone https://github.com/ricardo-ervilha/TF_DCC075.git
cd TF_DCC075
pip install -r requirements.txt
```

## Dataset

Utiliza o [CICIDS2017](https://www.kaggle.com/datasets/chethuhn/network-intrusion-dataset?resource=download) para treinamento e validação dos modelos.

## Uso

O notebook `main.ipynb` é utilizado para o treinamento e validação do modelo de Machine Learning, utilizando o dataset CICIDS2017 e as funções dos scripts auxiliares.

Após o treinamento, a classificação dos fluxos de rede e o envio de alertas são realizados separadamente pelos scripts do Suricata:

1. **Download e preparação do dataset**
   - Execute `load_dataset.py` para baixar e consolidar os arquivos CSV do CICIDS2017.
2. **Pré-processamento**
   - Utilize `pre_processing.py` para tratar valores nulos e normalizar os dados.
3. **Treinamento do modelo**
   - Utilize o notebook `main.ipynb` para treinar e validar o modelo de classificação.
4. **Extração de fluxos e classificação**
   - Rode Suricata para gerar o arquivo `eve.json` com os logs de rede.
   - Execute `suricata/suricata_classification.py` para carregar o modelo treinado e classificar os fluxos em tempo real, enviando alertas via Telegram em caso de detecção de tráfego malicioso.

## Exemplo de Execução

```bash
python suricata/suricata_classification.py
```

## Captura Isolada com Cicflowmeter

Este fluxo executa apenas a captura e validação do CSV, sem integração com Suricata e sem inferência de Machine Learning.

### 1) Configuração de ambiente

Crie um `.env` na raiz do projeto com base no `.env.example`:

```bash
CICFLOWMETER_PATH=/home/user/cicflowmeter/.venv/bin/cicflowmeter
NETWORK_INTERFACE=eth0
CAPTURE_OUTPUT_DIR=data/raw/captures
```

### 2) Executar captura por 60 segundos

```bash
python src/capture/traffic_capture.py
```

O script executa o cicflowmeter com `sudo`, aguarda 60 segundos, envia `SIGINT` para encerramento seguro e valida o CSV gerado com `pandas` (incluindo tratamento de nulos com `fillna(0)`).

### 3) Saída esperada

- CSV em `data/raw/captures/` com timestamp no nome.
- Impressão das colunas extraídas e das 5 primeiras linhas no terminal.

### Observação sobre privilégios

A captura em interface de rede exige permissões administrativas. Se necessário, rode `sudo -v` antes para evitar interrupção por prompt de senha durante a execução.

## Principais Dependências

- pandas, numpy, scikit-learn, joblib, requests, cicflowmeter, seaborn, matplotlib, polars, imbalanced-learn, kagglehub

Veja `requirements.txt` para a lista completa.

## Observações

- Certifique-se de que o Suricata está configurado e gerando o arquivo `eve.json` em `/var/log/suricata/eve.json`.
- Os modelos treinados devem estar na pasta `modelo/` (`random_forest_model.joblib` e `minmax_scaler.joblib`).
- Configure o token e chat_id do Telegram em `suricata_classification.py` para receber alertas.
