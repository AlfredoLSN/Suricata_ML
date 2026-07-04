const stateText = document.querySelector("#stateText");
const statePill = document.querySelector("#statePill");
const controlForm = document.querySelector("#controlForm");
const interfaceSelect = document.querySelector("#interfaceSelect");
const manualInterface = document.querySelector("#manualInterface");
const modelSelect = document.querySelector("#modelSelect");
const ignoredIps = document.querySelector("#ignoredIps");
const startButton = document.querySelector("#startButton");
const pauseButton = document.querySelector("#pauseButton");
const errorText = document.querySelector("#errorText");
const pcapCount = document.querySelector("#pcapCount");
const flowCount = document.querySelector("#flowCount");
const classifiedCount = document.querySelector("#classifiedCount");
const alertCount = document.querySelector("#alertCount");
const predictionCounts = document.querySelector("#predictionCounts");
const recentFiles = document.querySelector("#recentFiles");
const alertsList = document.querySelector("#alertsList");

const stateLabels = {
  stopped: "parado",
  starting: "iniciando",
  capturing: "capturando",
  pausing: "pausando",
  processing_pending: "processando",
  error: "erro",
};

async function requestJson(url, options = {}) {
  const response = await fetch(url, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new Error(payload.detail || `Erro HTTP ${response.status}`);
  }
  return response.json();
}

async function loadConfig() {
  const config = await requestJson("/api/config/options");
  interfaceSelect.innerHTML = "";
  for (const iface of config.interfaces) {
    const option = document.createElement("option");
    option.value = iface;
    option.textContent = iface;
    interfaceSelect.appendChild(option);
  }

  modelSelect.innerHTML = "";
  for (const model of config.models) {
    const option = document.createElement("option");
    option.value = model;
    option.textContent = model;
    modelSelect.appendChild(option);
  }
}

async function refresh() {
  const [status, summary, alerts] = await Promise.all([
    requestJson("/api/pipeline/status"),
    requestJson("/api/results/summary"),
    requestJson("/api/alerts?limit=20"),
  ]);

  renderStatus(status);
  renderSummary(summary);
  renderAlerts(alerts);
}

function renderStatus(status) {
  const label = stateLabels[status.state] || status.state;
  statePill.className = `status-pill ${status.state}`;
  statePill.textContent = label;
  stateText.textContent = status.last_error || buildStatusLine(status);
  pcapCount.textContent = status.pcap_count;
  flowCount.textContent = status.flow_csv_count;
  classifiedCount.textContent = status.classified_csv_count;
  alertCount.textContent = status.alert_count;

  const running = ["starting", "capturing", "pausing", "processing_pending"].includes(status.state);
  startButton.disabled = running;
  pauseButton.disabled = !["starting", "capturing"].includes(status.state);
}

function buildStatusLine(status) {
  if (!status.run_id) {
    return "Selecione a interface e inicie a captura.";
  }
  const iface = status.network_interface || "-";
  const model = status.model_path ? status.model_path.split(/[\\/]/).pop() : "-";
  return `${iface} usando ${model}`;
}

function renderSummary(summary) {
  predictionCounts.innerHTML = "";
  const entries = Object.entries(summary.prediction_counts || {});
  if (!entries.length) {
    predictionCounts.innerHTML = '<span class="empty">Sem classificacoes recentes.</span>';
  } else {
    for (const [label, count] of entries) {
      const chip = document.createElement("span");
      chip.className = "chip";
      chip.textContent = `${label}: ${count}`;
      predictionCounts.appendChild(chip);
    }
  }

  recentFiles.innerHTML = "";
  for (const file of summary.recent_classified_files || []) {
    const row = document.createElement("div");
    row.textContent = file;
    recentFiles.appendChild(row);
  }
}

function renderAlerts(alerts) {
  alertsList.innerHTML = "";
  if (!alerts.length) {
    alertsList.innerHTML = '<p class="empty">Nenhum alerta registrado.</p>';
    return;
  }
  for (const alert of alerts) {
    const row = document.createElement("article");
    row.className = "alert-row";
    row.innerHTML = `
      <div>
        <strong>${escapeHtml(alert.prediction_label)}</strong>
        <span>${formatDate(alert.created_at)}</span>
      </div>
      <div>
        <strong>${escapeHtml(alert.source_ip || "origem desconhecida")} -> ${escapeHtml(alert.destination_ip || "destino desconhecido")}</strong>
        <span>${escapeHtml(formatPorts(alert))}</span>
      </div>
      <div>
        <strong>${formatConfidence(alert.prediction_confidence)}</strong>
        <span>${escapeHtml(alert.protocol || "protocolo -")}</span>
      </div>
    `;
    alertsList.appendChild(row);
  }
}

function formatPorts(alert) {
  const source = alert.source_port ? `:${alert.source_port}` : "";
  const destination = alert.destination_port ? `:${alert.destination_port}` : "";
  return `${source || "porta origem -"} -> ${destination || "porta destino -"}`;
}

function formatConfidence(value) {
  if (value === null || value === undefined) {
    return "conf. -";
  }
  return `conf. ${(Number(value) * 100).toFixed(1)}%`;
}

function formatDate(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return date.toLocaleString("pt-BR");
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

controlForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  errorText.textContent = "";
  const selectedInterface = manualInterface.value.trim() || interfaceSelect.value;
  const ips = ignoredIps.value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
  try {
    await requestJson("/api/pipeline/start", {
      method: "POST",
      body: JSON.stringify({
        network_interface: selectedInterface,
        model_path: modelSelect.value,
        ignored_source_ips: ips,
      }),
    });
    await refresh();
  } catch (error) {
    errorText.textContent = error.message;
  }
});

pauseButton.addEventListener("click", async () => {
  errorText.textContent = "";
  try {
    await requestJson("/api/pipeline/pause", { method: "POST" });
    await refresh();
  } catch (error) {
    errorText.textContent = error.message;
  }
});

loadConfig()
  .then(refresh)
  .catch((error) => {
    errorText.textContent = error.message;
    stateText.textContent = "Falha ao carregar a interface.";
  });

setInterval(() => {
  refresh().catch((error) => {
    errorText.textContent = error.message;
  });
}, 3000);
