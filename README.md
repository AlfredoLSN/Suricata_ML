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
- `src/capture/traffic_capture.py`: Captura continua com tcpdump e rotacao nativa de arquivos PCAP a cada 60 segundos.
- `src/capture/flow_extraction_service.py`: Servico observador que processa PCAPs finalizados com CICFlowMeter e gera CSVs de features.
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

## Captura Continua com Tcpdump

Este fluxo executa apenas a captura bruta de pacotes em arquivos PCAP, sem integração com Suricata e sem inferência de Machine Learning.

### 1) Configuração de ambiente

Crie um `.env` na raiz do projeto com base no `.env.example`:

```bash
NETWORK_INTERFACE=eth0
CAPTURE_OUTPUT_DIR=data/raw/captures
FLOW_OUTPUT_DIR=data/processed/flows
FLOW_WORKER_COUNT=1
CICFLOWMETER_BIN=cicflowmeter
CICFLOWMETER_CWD=
CLASSIFICATION_ENABLED=false
CLASSIFICATION_MODEL_PATH=modelo/pipeline.joblib
CLASSIFICATION_LABEL_ENCODER_PATH=modelo/label_encoder.joblib
CLASSIFIED_FLOW_OUTPUT_DIR=data/processed/classified_flows
CLASSIFICATION_LABELS=
CLASSIFICATION_BENIGN_LABELS=BENIGN,0
CLASSIFICATION_EXCLUDED_SRC_IP=
CLASSIFICATION_REMOVE_SRC_IP=true
THREAT_RESPONSE_MODE=off
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
TELEGRAM_TIMEOUT_SECONDS=5
FIREWALL_COMMAND=iptables
FIREWALL_CHAIN=INPUT
FIREWALL_TARGET=DROP
```

### 2) Executar captura continua

```bash
python src/capture/traffic_capture.py
```

O script executa o `tcpdump` com `sudo` e o mantem ativo ate o usuario pressionar `Ctrl+C`. A rotacao dos arquivos e feita pelo proprio `tcpdump` a cada 60 segundos com `-G 60`, gerando arquivos `.pcap` com timestamp no nome.

### 3) Saída esperada

- Arquivos PCAP em `data/raw/captures/` com timestamp no nome.
- Encerramento seguro do processo filho do `tcpdump` ao pressionar `Ctrl+C`, preservando o ultimo arquivo gerado.

### Observação sobre privilégios

A captura em interface de rede exige `tcpdump` instalado e permissões administrativas. Se necessário, rode `sudo -v` antes para evitar interrupção por prompt de senha durante a execução.

## Extração de Features com CICFlowMeter

Este servico roda em paralelo com a captura continua. Ele observa `data/raw/captures/` com `watchdog`, publica apenas eventos de fechamento de arquivos `.pcap` em uma fila interna e deixa workers separados executarem o CICFlowMeter sem bloquear o observador.

### 1) Requisitos

- Instale as dependencias Python com `pip install -r requirements.txt`.
- Instale o CICFlowMeter separadamente e confirme que o comando `cicflowmeter` esta disponivel no terminal, ou configure `CICFLOWMETER_BIN` com o caminho do executavel.
- Se o CICFlowMeter precisar ser executado a partir de um diretorio especifico, configure `CICFLOWMETER_CWD`.

### 2) Configuracao

No `.env`, configure os caminhos e a quantidade inicial de workers:

```bash
CAPTURE_OUTPUT_DIR=data/raw/captures
FLOW_OUTPUT_DIR=data/processed/flows
FLOW_WORKER_COUNT=1
CICFLOWMETER_BIN=cicflowmeter
CICFLOWMETER_CWD=
CLASSIFICATION_ENABLED=false
CLASSIFICATION_MODEL_PATH=modelo/pipeline.joblib
CLASSIFICATION_LABEL_ENCODER_PATH=modelo/label_encoder.joblib
CLASSIFIED_FLOW_OUTPUT_DIR=data/processed/classified_flows
CLASSIFICATION_LABELS=
CLASSIFICATION_BENIGN_LABELS=BENIGN,0
CLASSIFICATION_EXCLUDED_SRC_IP=
CLASSIFICATION_REMOVE_SRC_IP=true
THREAT_RESPONSE_MODE=off
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
TELEGRAM_TIMEOUT_SECONDS=5
FIREWALL_COMMAND=iptables
FIREWALL_CHAIN=INPUT
FIREWALL_TARGET=DROP
```

### 3) Executar o servico

Em um terminal, rode a captura:

```bash
python src/capture/traffic_capture.py
```

Em outro terminal, rode a extracao de features:

```bash
python src/capture/flow_extraction_service.py
```

O servico nao reprocessa PCAPs antigos ao iniciar. Apenas novos arquivos `.pcap` fechados pelo `tcpdump` depois do inicio do observador entram na fila. A saida CSV do CICFlowMeter e gravada em `data/processed/flows/`.

### 4) Classificacao automatica dos CSVs gerados

Para classificar cada CSV logo apos uma extracao bem-sucedida do CICFlowMeter, habilite no `.env`:

```bash
CLASSIFICATION_ENABLED=true
CLASSIFICATION_MODEL_PATH=modelo/pipeline.joblib
CLASSIFICATION_LABEL_ENCODER_PATH=modelo/label_encoder.joblib
CLASSIFIED_FLOW_OUTPUT_DIR=data/processed/classified_flows
```

O servico carrega o pipeline treinado, usa as colunas de `feature_names_in_` salvas no pipeline ou em seus steps, decodifica as predicoes com `label_encoder.joblib` quando disponivel, adiciona as colunas `Prediction`, `Prediction Label` e, quando disponivel, `Prediction Confidence`, e grava um novo CSV em `data/processed/classified_flows/`.

Antes da inferencia, o CSV do CICFlowMeter e preparado para bater com as colunas do treino: nomes alternativos como `Total Fwd Packet`, `Total Bwd packets`, `Packet Length Min`, `FWD Init Win Bytes` e outros sao mapeados para os nomes esperados pelo modelo. Valores nao numericos sao convertidos para `NaN`; o tratamento de `Infinity`, `-Infinity` e valores ausentes fica a cargo do proprio pipeline (`ReplaceInfWithNan` e `SimpleImputer`). Se uma feature esperada nao existir no CSV, a classificacao daquele arquivo falha com log explicito em vez de predizer com colunas erradas.

Para remover flows originados do proprio host antes da classificacao, configure:

```bash
CLASSIFICATION_EXCLUDED_SRC_IP=192.168.0.10
CLASSIFICATION_REMOVE_SRC_IP=true
```

Se voce nao quiser usar `CLASSIFICATION_LABEL_ENCODER_PATH`, deixe essa variavel vazia e nomeie classes numericas manualmente com:

```bash
CLASSIFICATION_LABELS=BENIGN,DOS,PORTSCAN,BOT,INFILTRATION
```

Caso `CLASSIFICATION_LABEL_ENCODER_PATH` e `CLASSIFICATION_LABELS` fiquem vazios, o CSV classificado preserva o valor numerico retornado pelo modelo como texto em `Prediction Label`.

### Resposta IDS/IPS

Depois de cada classificacao, o servico pode reagir a fluxos cujo `Prediction Label` nao esteja em `CLASSIFICATION_BENIGN_LABELS`. Por padrao, `BENIGN` e `0` sao considerados trafego normal:

```bash
# Apenas gera CSV classificado
THREAT_RESPONSE_MODE=off

# IDS: envia alerta no Telegram
THREAT_RESPONSE_MODE=ids
TELEGRAM_BOT_TOKEN=123456:token-do-bot
TELEGRAM_CHAT_ID=-1001234567890

# IPS: bloqueia o Src IP no firewall
THREAT_RESPONSE_MODE=ips
FIREWALL_COMMAND=iptables
FIREWALL_CHAIN=INPUT
FIREWALL_TARGET=DROP
```

No modo `ids`, o alerta resume ate 10 fluxos maliciosos por CSV classificado. No modo `ips`, o servico valida os enderecos em `Src IP`, evita criar regra duplicada com `iptables -C` e entao insere a regra com `iptables -I INPUT -s <ip> -j DROP`. Para usar IPS, execute o servico com permissao para alterar regras de firewall.

## Principais Dependências

- pandas, numpy, scikit-learn, joblib, requests, seaborn, matplotlib, polars, imbalanced-learn, kagglehub, watchdog

Veja `requirements.txt` para a lista completa.

## Observações

- Certifique-se de que o Suricata está configurado e gerando o arquivo `eve.json` em `/var/log/suricata/eve.json`.
- Os modelos treinados devem estar na pasta `modelo/` (`random_forest_model.joblib` e `minmax_scaler.joblib`).
- Configure `THREAT_RESPONSE_MODE=ids` e as variaveis `TELEGRAM_BOT_TOKEN`/`TELEGRAM_CHAT_ID` no `.env` para receber alertas no Telegram.
