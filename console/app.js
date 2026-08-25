"use strict";

const state = {
  token: sessionStorage.getItem("rootcause-token") || "",
  status: null,
  topology: null,
  assets: [],
  incidents: [],
};

const titles = {
  overview: "Resumen",
  topology: "Topología",
  assets: "Activos",
  incidents: "Incidentes",
  system: "Sistema",
};

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];

document.addEventListener("DOMContentLoaded", () => {
  wireNavigation();
  wireTokenDialog();
  $("#refresh-button").addEventListener("click", refresh);
  $("#token-button").addEventListener("click", showTokenDialog);

  if (!state.token) {
    showTokenDialog();
  } else {
    refresh();
  }
  setInterval(refresh, 10000);
});

function wireNavigation() {
  $$(".nav-item").forEach((button) => {
    button.addEventListener("click", () => openView(button.dataset.view));
  });
  $$('[data-open-view]').forEach((button) => {
    button.addEventListener("click", () => openView(button.dataset.openView));
  });
}

function openView(name) {
  $$(".nav-item").forEach((item) => item.classList.toggle("active", item.dataset.view === name));
  $$(".view").forEach((view) => view.classList.toggle("active", view.id === `view-${name}`));
  $("#view-title").textContent = titles[name] || name;
}

function wireTokenDialog() {
  const dialog = $("#token-dialog");
  const input = $("#token-input");
  input.value = state.token;

  $("#save-token").addEventListener("click", (event) => {
    event.preventDefault();
    if (!input.value || input.value.length < 32) {
      input.setCustomValidity("El token debe contener al menos 32 caracteres.");
      input.reportValidity();
      input.setCustomValidity("");
      return;
    }
    state.token = input.value;
    sessionStorage.setItem("rootcause-token", state.token);
    dialog.close();
    refresh();
  });

  $("#local-mode").addEventListener("click", (event) => {
    event.preventDefault();
    state.token = "";
    sessionStorage.removeItem("rootcause-token");
    dialog.close();
    refresh();
  });
}

async function api(path) {
  const headers = { Accept: "application/json" };
  if (state.token) headers.Authorization = `Bearer ${state.token}`;
  const response = await fetch(path, { headers, cache: "no-store" });
  if (response.status === 401) {
    showTokenDialog();
    throw new Error("Token inválido o ausente.");
  }
  if (!response.ok) throw new Error(`Solicitud ${path}: HTTP ${response.status}`);
  return response.json();
}

function showTokenDialog() {
  const dialog = $("#token-dialog");
  if (!dialog.open) dialog.showModal();
}

async function refresh() {
  try {
    const [status, topology, assets, incidents] = await Promise.all([
      api("/api/v1/status"),
      api("/api/v1/topology"),
      api("/api/v1/assets"),
      api("/api/v1/incidents"),
    ]);
    Object.assign(state, { status, topology, assets, incidents });
    render();
    setConnection(true);
    showError("");
  } catch (error) {
    setConnection(false);
    showError(error.message || "No fue posible actualizar la consola.");
  }
}

function render() {
  const status = state.status;
  $("#metric-assets").textContent = number(status.assets_total);
  $("#metric-assets-detail").textContent = `${number(status.assets_online)} en línea`;
  $("#metric-incidents").textContent = number(status.open_incidents);
  $("#metric-critical").textContent = number(status.critical_incidents);
  const availability = status.assets_total
    ? Math.round((status.assets_online / status.assets_total) * 100)
    : 100;
  $("#metric-availability").textContent = `${availability}%`;
  $("#last-update").textContent = `Actualizado ${new Date().toLocaleTimeString("es-CL")}`;
  $("#system-version").textContent = status.version;
  $("#system-protocol").textContent = status.protocol_version;
  $("#system-uptime").textContent = duration(status.uptime_seconds);

  renderTopology($("#overview-topology"), state.topology, true);
  renderTopology($("#full-topology"), state.topology, false);
  $("#overview-empty").hidden = state.assets.length > 0;
  $("#topology-empty").hidden = state.assets.length > 0;
  renderAssets();
  renderIncidents();
}

function renderAssets() {
  const body = $("#assets-body");
  body.replaceChildren();
  if (!state.assets.length) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 7;
    cell.className = "empty-message";
    cell.textContent = "No existen activos registrados.";
    row.append(cell);
    body.append(row);
    return;
  }

  for (const asset of state.assets) {
    const metrics = asset.latest_metrics || {};
    const row = document.createElement("tr");
    appendCell(row, asset.registration.hostname);
    appendCell(row, platformName(asset.registration.platform));
    const statusCell = document.createElement("td");
    const pill = document.createElement("span");
    pill.className = `pill ${asset.status}`;
    pill.textContent = statusName(asset.status);
    statusCell.append(pill);
    row.append(statusCell);
    appendCell(row, percent(metrics.cpu_percent));
    appendCell(row, percent(metrics.memory_percent));
    appendCell(row, percent(metrics.disk_percent));
    appendCell(row, relativeTime(asset.last_seen));
    body.append(row);
  }
}

function renderIncidents() {
  const open = state.incidents.filter((incident) => incident.status !== "resolved");
  renderIncidentList($("#recent-incidents"), open.slice(0, 5), false);
  renderIncidentList($("#all-incidents"), state.incidents, true);
}

function renderIncidentList(container, incidents, detailed) {
  container.replaceChildren();
  if (!incidents.length) {
    const empty = document.createElement("p");
    empty.className = "empty-message";
    empty.textContent = "No existen incidentes para mostrar.";
    container.append(empty);
    return;
  }

  for (const incident of incidents) {
    const card = document.createElement("article");
    card.className = `incident-card ${incident.severity}`;
    const header = document.createElement("div");
    header.className = "incident-header";
    const title = document.createElement("h3");
    title.textContent = incident.title;
    const meta = document.createElement("span");
    meta.className = "incident-meta";
    meta.textContent = `${incident.severity} · ${statusName(incident.status)}`;
    header.append(title, meta);
    const summary = document.createElement("p");
    summary.textContent = incident.summary;
    card.append(header, summary);

    if (detailed) {
      const cause = document.createElement("p");
      cause.textContent = `Causa probable (${Math.round(incident.confidence * 100)}%): ${incident.root_cause}`;
      card.append(cause);
      const evidence = document.createElement("ul");
      evidence.className = "evidence";
      for (const item of incident.evidence || []) {
        const line = document.createElement("li");
        line.textContent = `${item.summary}: ${item.observed_value.toFixed(1)} (umbral ${item.threshold.toFixed(1)})`;
        evidence.append(line);
      }
      card.append(evidence);
    }
    container.append(card);
  }
}

function renderTopology(svg, topology, compact) {
  const width = compact ? 760 : 980;
  const height = compact ? 360 : 620;
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.replaceChildren();
  if (!topology || topology.nodes.length <= 1) return;

  const positions = layoutTopology(topology, width, height);
  const ns = "http://www.w3.org/2000/svg";
  for (const edge of topology.edges) {
    const source = positions.get(edge.source);
    const target = positions.get(edge.target);
    if (!source || !target) continue;
    const path = document.createElementNS(ns, "path");
    const midpoint = (source.x + target.x) / 2;
    path.setAttribute("d", `M ${source.x} ${source.y} C ${midpoint} ${source.y}, ${midpoint} ${target.y}, ${target.x} ${target.y}`);
    path.setAttribute("class", "topology-link");
    svg.append(path);
  }

  for (const node of topology.nodes) {
    const position = positions.get(node.id);
    if (!position) continue;
    const group = document.createElementNS(ns, "g");
    group.setAttribute("class", "topology-node");
    group.setAttribute("transform", `translate(${position.x} ${position.y})`);
    const circle = document.createElementNS(ns, "circle");
    const radius = node.kind === "control-plane" ? 34 : node.kind === "platform-group" ? 27 : 20;
    circle.setAttribute("r", String(radius));
    circle.setAttribute("fill", nodeColor(node));
    circle.setAttribute("stroke", node.risk ? riskColor(node.risk) : "#5c8da0");
    const title = document.createElementNS(ns, "text");
    title.setAttribute("y", String(radius + 18));
    title.textContent = truncate(node.label, compact ? 16 : 22);
    const subtitle = document.createElementNS(ns, "text");
    subtitle.setAttribute("y", String(radius + 31));
    subtitle.setAttribute("class", "node-subtitle");
    subtitle.textContent = node.risk || node.status;
    group.append(circle, title, subtitle);
    svg.append(group);
  }
}

function layoutTopology(topology, width, height) {
  const positions = new Map();
  const root = topology.nodes.find((node) => node.kind === "control-plane");
  const groups = topology.nodes.filter((node) => node.kind === "platform-group");
  const endpoints = topology.nodes.filter((node) => node.kind === "endpoint");
  if (root) positions.set(root.id, { x: width * 0.13, y: height * 0.5 });

  groups.forEach((group, index) => {
    const y = ((index + 1) * height) / (groups.length + 1);
    positions.set(group.id, { x: width * 0.43, y });
    const children = endpoints.filter((endpoint) =>
      topology.edges.some((edge) => edge.source === group.id && edge.target === endpoint.id),
    );
    children.forEach((child, childIndex) => {
      const spread = Math.min(height / Math.max(children.length + 1, 2), 74);
      const start = y - (spread * (children.length - 1)) / 2;
      positions.set(child.id, { x: width * 0.77, y: start + childIndex * spread });
    });
  });
  return positions;
}

function nodeColor(node) {
  if (node.status === "offline") return "#263740";
  if (node.kind === "control-plane") return "#0d746f";
  if (node.kind === "platform-group") return "#164b67";
  return "#153441";
}

function riskColor(risk) {
  return { critical: "#fb4f64", high: "#fb923c", medium: "#facc15", low: "#38a7ff" }[risk] || "#5c8da0";
}

function appendCell(row, value) {
  const cell = document.createElement("td");
  cell.textContent = value;
  row.append(cell);
}

function setConnection(connected) {
  $("#connection-dot").classList.toggle("online", connected);
  $("#connection-text").textContent = connected ? "Servidor conectado" : "Sin conexión";
}

function showError(message) {
  const banner = $("#error-banner");
  banner.hidden = !message;
  banner.textContent = message;
}

function platformName(platform) {
  return { windows: "Windows", linux: "Linux", macos: "macOS", unknown: "Otro" }[platform] || platform;
}

function statusName(status) {
  return { online: "En línea", stale: "Sin señal reciente", offline: "Fuera de línea", open: "Abierto", acknowledged: "Reconocido", resolved: "Resuelto" }[status] || status;
}

function percent(value) {
  return Number.isFinite(value) ? `${value.toFixed(1)}%` : "—";
}

function number(value) {
  return new Intl.NumberFormat("es-CL").format(value || 0);
}

function duration(seconds) {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  return [days ? `${days}d` : "", hours ? `${hours}h` : "", `${minutes}m`].filter(Boolean).join(" ");
}

function relativeTime(value) {
  const seconds = Math.max(0, Math.round((Date.now() - new Date(value).getTime()) / 1000));
  if (seconds < 60) return `hace ${seconds}s`;
  if (seconds < 3600) return `hace ${Math.floor(seconds / 60)}m`;
  return `hace ${Math.floor(seconds / 3600)}h`;
}

function truncate(value, length) {
  return value.length > length ? `${value.slice(0, length - 1)}…` : value;
}
