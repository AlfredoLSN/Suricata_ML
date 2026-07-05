const stateText = document.querySelector("#stateText");
const statePill = document.querySelector("#statePill");
const controlForm = document.querySelector("#controlForm");
const interfaceSelect = document.querySelector("#interfaceSelect");
const ignoredIps = document.querySelector("#ignoredIps");
const startButton = document.querySelector("#startButton");
const pauseButton = document.querySelector("#pauseButton");
const injectAttackButton = document.querySelector("#injectAttackButton");
const errorText = document.querySelector("#errorText");
const pcapCount = document.querySelector("#pcapCount");
const flowCount = document.querySelector("#flowCount");
const classifiedCount = document.querySelector("#classifiedCount");
const alertCount = document.querySelector("#alertCount");
const predictionCounts = document.querySelector("#predictionCounts");
const classificationsList = document.querySelector("#classificationsList");
const classificationPageInfo = document.querySelector("#classificationPageInfo");
const classificationPrev = document.querySelector("#classificationPrev");
const classificationNext = document.querySelector("#classificationNext");
const alertsList = document.querySelector("#alertsList");

const classificationPageSize = 30;
let classificationOffset = 0;
let classificationTotal = 0;

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
  if (!config.interfaces.length) {
    const option = document.createElement("option");
    option.value = "";
    option.textContent = "Nenhuma interface detectada";
    interfaceSelect.appendChild(option);
  }
  for (const iface of config.interfaces) {
    const option = document.createElement("option");
    option.value = iface;
    option.textContent = iface;
    interfaceSelect.appendChild(option);
  }
}

async function refresh() {
  const [status, summary, classifications, alerts] = await Promise.all([
    requestJson("/api/pipeline/status"),
    requestJson("/api/results/summary"),
    requestJson(
      `/api/results/classifications?limit=${classificationPageSize}&offset=${classificationOffset}`
    ),
    requestJson("/api/alerts?limit=20"),
  ]);

  classificationTotal = status.classification_total || status.classified_count || 0;
  if (classificationTotal && classificationOffset >= classificationTotal) {
    classificationOffset = Math.max(0, Math.floor((classificationTotal - 1) / classificationPageSize) * classificationPageSize);
    await refresh();
    return;
  }

  renderStatus(status);
  renderSummary(summary);
  renderClassifications(classifications);
  renderClassificationPagination(classifications.length);
  renderAlerts(alerts);
}

function renderStatus(status) {
  const label = stateLabels[status.state] || status.state;
  statePill.className = `status-pill ${status.state}`;
  statePill.textContent = label;
  stateText.textContent = status.last_error || buildStatusLine(status);
  pcapCount.textContent = status.pcap_count;
  flowCount.textContent = status.flow_csv_count;
  classifiedCount.textContent = status.classified_count;
  alertCount.textContent = status.alert_count;

  const running = ["starting", "capturing", "pausing", "processing_pending"].includes(status.state);
  startButton.disabled = running || !interfaceSelect.value;
  pauseButton.disabled = !["starting", "capturing"].includes(status.state);
  injectAttackButton.disabled = false;
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
}

function renderClassifications(classifications) {
  classificationsList.innerHTML = "";
  if (!classifications.length) {
    classificationsList.innerHTML = '<p class="empty">Nenhuma classificacao registrada.</p>';
    return;
  }
  const rows = classifications.map((item) => {
    const confidencePercent = confidencePercentValue(item.prediction_confidence);
    return `
      <tr>
        <td><span class="ip-cell">${escapeHtml(item.source_ip || "-")}</span></td>
        <td><span class="ip-cell">${escapeHtml(item.destination_ip || "-")}</span></td>
        <td><span class="ports-cell">${escapeHtml(formatPortPair(item))}</span></td>
        <td><span class="${classBadgeName(item.prediction_label)}">${escapeHtml(item.prediction_label)}</span></td>
        <td>
          <div class="confidence-cell">
            <div class="confidence-meter" title="${escapeHtml(formatConfidence(item.prediction_confidence))}">
              <div style="width: ${confidencePercent}%"></div>
            </div>
            <strong>${formatConfidencePercent(item.prediction_confidence)}</strong>
          </div>
        </td>
      </tr>
    `;
  }).join("");

  classificationsList.innerHTML = `
    <div class="classification-table-wrap">
      <table class="classification-table">
        <thead>
          <tr>
            <th>Origem</th>
            <th>Destino</th>
            <th>Portas</th>
            <th>Classificacao</th>
            <th>Confianca</th>
          </tr>
        </thead>
        <tbody>
          ${rows}
        </tbody>
      </table>
    </div>
  `;
}

function renderClassificationPagination(visibleCount) {
  if (!classificationTotal) {
    classificationPageInfo.textContent = "0 de 0";
    classificationPrev.disabled = true;
    classificationNext.disabled = true;
    return;
  }
  const start = classificationOffset + 1;
  const end = Math.min(classificationOffset + visibleCount, classificationTotal);
  classificationPageInfo.textContent = `${start}-${end} de ${classificationTotal}`;
  classificationPrev.disabled = classificationOffset === 0;
  classificationNext.disabled = classificationOffset + classificationPageSize >= classificationTotal;
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

function formatPortPair(item) {
  const source = item.source_port || "-";
  const destination = item.destination_port || "-";
  return `${source} -> ${destination}`;
}

function confidencePercentValue(value) {
  if (value === null || value === undefined || Number.isNaN(Number(value))) {
    return 0;
  }
  return Math.max(0, Math.min(100, Number(value) * 100));
}

function classBadgeName(label) {
  const normalized = String(label || "").trim().toLowerCase();
  if (["benign", "benigno", "0"].includes(normalized)) {
    return "class-badge benign";
  }
  return "class-badge threat";
}

function formatConfidence(value) {
  if (value === null || value === undefined) {
    return "conf. -";
  }
  return `conf. ${(Number(value) * 100).toFixed(1)}%`;
}

function formatConfidencePercent(value) {
  if (value === null || value === undefined) {
    return "-";
  }
  return `${(Number(value) * 100).toFixed(1)}%`;
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
  const selectedInterface = interfaceSelect.value;
  const ips = ignoredIps.value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
  try {
    await requestJson("/api/pipeline/start", {
      method: "POST",
      body: JSON.stringify({
        network_interface: selectedInterface,
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

injectAttackButton.addEventListener("click", async () => {
  errorText.textContent = "";
  injectAttackButton.disabled = true;
  try {
    await requestJson("/api/testing/inject-attack", { method: "POST" });
    classificationOffset = 0;
    await refresh();
  } catch (error) {
    errorText.textContent = error.message;
  } finally {
    injectAttackButton.disabled = false;
  }
});

classificationPrev.addEventListener("click", async () => {
  classificationOffset = Math.max(0, classificationOffset - classificationPageSize);
  await refresh().catch((error) => {
    errorText.textContent = error.message;
  });
});

classificationNext.addEventListener("click", async () => {
  if (classificationOffset + classificationPageSize >= classificationTotal) {
    return;
  }
  classificationOffset += classificationPageSize;
  await refresh().catch((error) => {
    errorText.textContent = error.message;
  });
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
