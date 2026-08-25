"use strict";

/* RootCause Server console.
 *
 * Every node here is built with the DOM API rather than from a string: the
 * Content Security Policy the server sends allows no inline script and no
 * remote origin, and building the tree by hand means a hostname or a process
 * name reported by an agent can never be interpreted as markup. */

const REFRESH_INTERVAL_MS = 10000;
const SVG_NS = "http://www.w3.org/2000/svg";

const state = {
  token: sessionStorage.getItem("rootcause-token") || "",
  status: null,
  exposure: null,
  threats: null,
  assets: [],
  incidents: [],
  topology: null,
  rules: [],
  audit: [],
  incidentFilters: { category: "", status: "open" },
  exposureQuery: "",
  timer: null,
};

const TITLES = {
  panel: "Panel de defensa",
  superficie: "Superficie expuesta",
  amenazas: "Amenazas",
  incidentes: "Incidentes",
  activos: "Activos",
  topologia: "Topología",
  reglas: "Qué detecta",
  sistema: "Sistema",
};

const SEVERITY_LABEL = {
  critical: "Crítico",
  high: "Alto",
  medium: "Medio",
  low: "Bajo",
  info: "Informativo",
};

const CATEGORY_LABEL = {
  intrusion: "Intrusión",
  exposure: "Superficie expuesta",
  integrity: "Integridad",
  availability: "Disponibilidad",
  hygiene: "Higiene",
  resource: "Recursos",
};

const STATUS_LABEL = {
  online: "En línea",
  stale: "Sin señal reciente",
  offline: "Fuera de línea",
  open: "Abierto",
  acknowledged: "Reconocido",
  resolved: "Resuelto",
};

const ROLE_LABEL = {
  "edge-server": "Borde",
  "internal-server": "Interno",
  "database-server": "Base de datos",
  workstation: "Estación",
};

const SCOPE_LABEL = { public: "Público", private: "Red interna", loopback: "Solo local" };
const PLATFORM_LABEL = { windows: "Windows", linux: "Linux", macos: "macOS", unknown: "Otro" };
const STEP_LABEL = { inspect: "Inspeccionar", contain: "Contener", remediate: "Corregir" };

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];

/** Create an element, assigning text, classes and attributes safely. */
function el(tag, options = {}, ...children) {
  const node = document.createElement(tag);
  if (options.className) node.className = options.className;
  if (options.text !== undefined) node.textContent = options.text;
  if (options.attrs) {
    for (const [name, value] of Object.entries(options.attrs)) {
      if (value !== null && value !== undefined) node.setAttribute(name, String(value));
    }
  }
  if (options.on) {
    for (const [event, handler] of Object.entries(options.on)) {
      node.addEventListener(event, handler);
    }
  }
  for (const child of children) {
    if (child) node.append(child);
  }
  return node;
}

function svg(tag, attrs = {}) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [name, value] of Object.entries(attrs)) {
    node.setAttribute(name, String(value));
  }
  return node;
}

function pill(text, variant) {
  return el("span", { className: `pill ${variant}`, text });
}

function severityPill(severity) {
  return pill(SEVERITY_LABEL[severity] || severity, severity);
}

function number(value) {
  return new Intl.NumberFormat("es-CL").format(Number(value) || 0);
}

function percent(value) {
  return Number.isFinite(value) ? `${value.toFixed(1)}%` : "—";
}

function duration(seconds) {
  const total = Number(seconds) || 0;
  const days = Math.floor(total / 86400);
  const hours = Math.floor((total % 86400) / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  return [days ? `${days} d` : "", hours ? `${hours} h` : "", `${minutes} min`]
    .filter(Boolean)
    .join(" ");
}

function relativeTime(value) {
  const stamp = new Date(value).getTime();
  if (!Number.isFinite(stamp)) return "—";
  const seconds = Math.max(0, Math.round((Date.now() - stamp) / 1000));
  if (seconds < 60) return `hace ${seconds} s`;
  if (seconds < 3600) return `hace ${Math.floor(seconds / 60)} min`;
  if (seconds < 86400) return `hace ${Math.floor(seconds / 3600)} h`;
  return `hace ${Math.floor(seconds / 86400)} d`;
}

function absoluteTime(value) {
  const date = new Date(value);
  return Number.isFinite(date.getTime()) ? date.toLocaleString("es-CL") : "—";
}

/* ------------------------------------------------------------------ boot */

document.addEventListener("DOMContentLoaded", () => {
  wireNavigation();
  wireTokenDialog();
  wireIncidentDialog();
  wireFilters();

  $("#refresh-button").addEventListener("click", () => refresh());
  $("#token-button").addEventListener("click", showTokenDialog);
  $("#export-button").addEventListener("click", downloadEvidence);

  if (state.token) {
    refresh();
  } else {
    showTokenDialog();
  }
  state.timer = setInterval(refresh, REFRESH_INTERVAL_MS);
});

function wireNavigation() {
  $$(".nav-item").forEach((button) => {
    button.addEventListener("click", () => openView(button.dataset.view));
  });
  $$("[data-open-view]").forEach((button) => {
    button.addEventListener("click", () => openView(button.dataset.openView));
  });
}

function openView(name) {
  $$(".nav-item").forEach((item) => {
    const active = item.dataset.view === name;
    item.classList.toggle("active", active);
    if (active) {
      item.setAttribute("aria-current", "page");
    } else {
      item.removeAttribute("aria-current");
    }
  });
  $$(".view").forEach((view) => view.classList.toggle("active", view.id === `view-${name}`));
  $("#view-title").textContent = TITLES[name] || name;
}

function wireFilters() {
  $("#incident-category").addEventListener("change", (event) => {
    state.incidentFilters.category = event.target.value;
    renderIncidents();
  });
  $("#incident-status").addEventListener("change", (event) => {
    state.incidentFilters.status = event.target.value;
    renderIncidents();
  });
  $("#exposure-search").addEventListener("input", (event) => {
    state.exposureQuery = event.target.value.trim().toLowerCase();
    renderExposure();
  });
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

function showTokenDialog() {
  const dialog = $("#token-dialog");
  if (!dialog.open) dialog.showModal();
}

/* ------------------------------------------------------------------- api */

function headers() {
  const value = { Accept: "application/json" };
  if (state.token) value.Authorization = `Bearer ${state.token}`;
  return value;
}

async function api(path) {
  const response = await fetch(path, { headers: headers(), cache: "no-store" });
  if (response.status === 401) {
    showTokenDialog();
    throw new Error("Token ausente o inválido.");
  }
  if (response.status === 429) {
    const retry = response.headers.get("retry-after") || "unos segundos";
    throw new Error(`El servidor limitó esta conexión. Reintenta en ${retry} s.`);
  }
  if (!response.ok) throw new Error(`${path}: HTTP ${response.status}`);
  return response.json();
}

async function post(path, body) {
  const response = await fetch(path, {
    method: "POST",
    headers: { ...headers(), "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!response.ok) throw new Error(`${path}: HTTP ${response.status}`);
  return response.json();
}

async function refresh() {
  try {
    const [status, exposure, threats, assets, incidents, topology, audit] = await Promise.all([
      api("/api/v1/status"),
      api("/api/v1/exposure"),
      api("/api/v1/threats"),
      api("/api/v1/assets"),
      api("/api/v1/incidents"),
      api("/api/v1/topology"),
      api("/api/v1/audit?limit=60"),
    ]);
    Object.assign(state, { status, exposure, threats, assets, incidents, topology, audit });
    if (state.rules.length === 0) {
      state.rules = await api("/api/v1/rules");
      renderRules();
    }
    render();
    setConnection(true);
    showError("");
  } catch (error) {
    setConnection(false);
    showError(error.message || "No fue posible actualizar la consola.");
  }
}

async function downloadEvidence() {
  try {
    const response = await fetch("/api/v1/export", { headers: headers(), cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = el("a", { attrs: { href: url, download: "rootcause-evidencia.ndjson" } });
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  } catch (error) {
    showError(`No se pudo descargar la evidencia: ${error.message}`);
  }
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

/* --------------------------------------------------------------- render */

function render() {
  renderPosture();
  renderMetrics();
  renderHardening();
  renderBadges();
  renderIncidents();
  renderTopSources();
  renderExposure();
  renderThreats();
  renderAssets();
  renderTopology();
  renderSystem();
  renderAudit();
  $("#last-update").textContent = `Actualizado ${new Date().toLocaleTimeString("es-CL")}`;
}

function severityForScore(score) {
  if (score >= 90) return "ok";
  if (score >= 75) return "medium";
  if (score >= 55) return "high";
  return "critical";
}

function renderPosture() {
  const posture = state.status?.posture;
  const gauge = $("#posture-gauge");
  gauge.replaceChildren();
  if (!posture) return;

  const radius = 70;
  const circumference = 2 * Math.PI * radius;
  const filled = (Math.max(0, Math.min(100, posture.score)) / 100) * circumference;
  const tone = severityForScore(posture.score);
  const colour = {
    ok: "var(--ok)",
    medium: "var(--medium)",
    high: "var(--high)",
    critical: "var(--critical)",
  }[tone];

  gauge.append(
    svg("circle", { class: "gauge-track", cx: 90, cy: 90, r: radius }),
    svg("circle", {
      class: "gauge-value",
      cx: 90,
      cy: 90,
      r: radius,
      stroke: colour,
      "stroke-dasharray": `${filled} ${circumference - filled}`,
      transform: "rotate(-90 90 90)",
    }),
  );
  const score = svg("text", { class: "gauge-score", x: 90, y: 96 });
  score.textContent = String(posture.score);
  const grade = svg("text", { class: "gauge-grade", x: 90, y: 120 });
  grade.textContent = `NOTA ${posture.grade}`;
  gauge.append(score, grade);

  const open = state.status.open_incidents;
  $("#posture-headline").textContent =
    open === 0
      ? "Sin hallazgos abiertos en la flota"
      : `${number(open)} hallazgo(s) abierto(s) en la flota`;

  const gaps = $("#posture-gaps");
  gaps.replaceChildren();
  for (const gap of posture.uninspected_surfaces || []) {
    gaps.append(el("li", { text: `Sin inspeccionar — ${gap}` }));
  }

  const container = $("#posture-dimensions");
  container.replaceChildren();
  for (const dimension of posture.dimensions || []) {
    const bar = el("div", { className: "dimension-bar" });
    const fill = el("span");
    fill.style.width = `${dimension.score}%`;
    fill.style.background = `var(--${severityForScore(dimension.score)})`;
    bar.append(fill);

    container.append(
      el(
        "div",
        { className: "dimension" },
        el(
          "div",
          { className: "dimension-head" },
          el("span", {
            className: "dimension-name",
            text: CATEGORY_LABEL[dimension.category] || dimension.category,
          }),
          el("span", { className: "dimension-score", text: `${dimension.score}/100` }),
        ),
        bar,
        el("p", { className: "dimension-summary", text: dimension.summary }),
      ),
    );
  }
}

function metricCard(label, value, detail, variant = "") {
  return el(
    "article",
    { className: `metric-card ${variant}`.trim() },
    el("span", { text: label }),
    el("strong", { text: value }),
    el("small", { text: detail }),
  );
}

function renderMetrics() {
  const status = state.status;
  const grid = $("#metrics-grid");
  grid.replaceChildren();
  if (!status) return;

  const availability = status.assets_total
    ? Math.round((status.assets_online / status.assets_total) * 100)
    : 100;

  grid.append(
    metricCard(
      "Activos",
      number(status.assets_total),
      `${number(status.assets_online)} reportando · ${availability}%`,
    ),
    metricCard(
      "Servicios expuestos",
      number(status.exposed_services),
      "Alcanzables fuera de su host",
      status.exposed_services > 0 ? "warn" : "",
    ),
    metricCard(
      "Incidentes abiertos",
      number(status.open_incidents),
      "Requieren evaluación humana",
    ),
    metricCard(
      "Riesgo crítico",
      number(status.critical_incidents),
      "Atender antes que nada",
      status.critical_incidents > 0 ? "danger" : "",
    ),
    metricCard(
      "Orígenes bloqueados",
      number(status.blocked_sources),
      "Por el perímetro de este servidor",
    ),
    metricCard("Reglas activas", number(status.detectors), "Catálogo publicado por el binario"),
  );
}

function renderHardening() {
  const banner = $("#hardening-banner");
  const hardening = state.status?.hardening;
  if (!hardening) {
    banner.hidden = true;
    return;
  }
  const warnings = [];
  if (!hardening.authentication) {
    warnings.push(
      "Esta instancia corre sin token: solo es aceptable en loopback y para desarrollo.",
    );
  }
  if (!hardening.bind_is_loopback) {
    warnings.push(
      "El servidor escucha fuera de loopback: publícalo únicamente detrás de TLS y de una red controlada.",
    );
  }
  banner.hidden = warnings.length === 0;
  banner.textContent = warnings.join(" ");
}

function renderBadges() {
  const setBadge = (id, count, quiet = false) => {
    const badge = $(id);
    badge.hidden = !count;
    badge.textContent = number(count);
    badge.classList.toggle("quiet", quiet);
  };
  const openIncidents = state.incidents.filter((incident) => incident.status !== "resolved");
  setBadge("#badge-incidents", openIncidents.length, openIncidents.every((i) => i.severity !== "critical"));
  setBadge("#badge-exposure", state.exposure?.public_services || 0);
  setBadge("#badge-threats", state.threats?.sources?.length || 0, true);
}

/* ------------------------------------------------------------ incidents */

function incidentCard(incident, detailed) {
  const card = el("button", {
    className: `incident-card ${incident.severity}`,
    attrs: { type: "button" },
    on: { click: () => openIncident(incident) },
  });

  card.append(
    el(
      "div",
      { className: "incident-header" },
      el("h3", { text: incident.title }),
      el(
        "div",
        { className: "incident-meta" },
        severityPill(incident.severity),
        pill(CATEGORY_LABEL[incident.category] || incident.category, "info"),
      ),
    ),
    el("p", { text: incident.summary }),
  );

  const footer = el(
    "div",
    { className: "incident-footer" },
    el("span", { text: STATUS_LABEL[incident.status] || incident.status }),
    el("span", { text: `Confianza ${Math.round(incident.confidence * 100)}%` }),
    el("span", { text: `Visto ${incident.occurrences} vez/veces` }),
    el("span", { text: relativeTime(incident.last_seen) }),
  );
  card.append(footer);

  if (detailed && incident.techniques?.length) {
    const tags = el("div");
    for (const technique of incident.techniques) {
      tags.append(el("span", { className: "tag", text: technique }));
    }
    card.append(tags);
  }
  return card;
}

function renderIncidents() {
  const recent = $("#recent-incidents");
  recent.replaceChildren();
  const open = state.incidents
    .filter((incident) => incident.status !== "resolved")
    .slice(0, 6);
  if (open.length === 0) {
    recent.append(
      el("p", {
        className: "empty-message",
        text: "Nada abierto. Eso puede significar que todo está bien o que aún no llega telemetría.",
      }),
    );
  } else {
    for (const incident of open) recent.append(incidentCard(incident, false));
  }

  const list = $("#all-incidents");
  list.replaceChildren();
  const { category, status } = state.incidentFilters;
  const filtered = state.incidents.filter((incident) => {
    if (category && incident.category !== category) return false;
    if (status === "open" && incident.status === "resolved") return false;
    if (status === "resolved" && incident.status !== "resolved") return false;
    return true;
  });
  if (filtered.length === 0) {
    list.append(el("p", { className: "empty-message", text: "No hay incidentes con ese filtro." }));
    return;
  }
  for (const incident of filtered) list.append(incidentCard(incident, true));
}

function wireIncidentDialog() {
  $("#incident-close").addEventListener("click", () => $("#incident-dialog").close());
}

function openIncident(incident) {
  const dialog = $("#incident-dialog");
  $("#incident-dialog-eyebrow").textContent = (
    CATEGORY_LABEL[incident.category] || incident.category
  ).toUpperCase();
  $("#incident-dialog-title").textContent = incident.title;

  const body = $("#incident-dialog-body");
  body.replaceChildren();

  body.append(
    el(
      "div",
      { className: "drawer-section" },
      el(
        "div",
        { className: "incident-meta" },
        severityPill(incident.severity),
        pill(STATUS_LABEL[incident.status] || incident.status, "info"),
        pill(`Confianza ${Math.round(incident.confidence * 100)}%`, "info"),
      ),
      el("p", { text: incident.summary }),
    ),
    el(
      "div",
      { className: "drawer-section" },
      el("h3", { text: "Causa probable" }),
      el("p", { text: incident.root_cause }),
    ),
  );

  if (incident.evidence?.length) {
    const section = el("div", { className: "drawer-section" }, el("h3", { text: "Evidencia" }));
    for (const item of incident.evidence) {
      const entry = el(
        "div",
        { className: "evidence-item" },
        el("div", { className: "evidence-kind", text: item.kind }),
        el("div", { className: "evidence-summary", text: item.summary }),
      );
      if (item.observed_value !== null && item.observed_value !== undefined) {
        entry.append(
          el("div", {
            className: "evidence-detail",
            text: `observado ${item.observed_value.toFixed(1)} · umbral ${
              item.threshold !== null && item.threshold !== undefined
                ? item.threshold.toFixed(1)
                : "—"
            }`,
          }),
        );
      }
      if (item.detail) {
        entry.append(el("div", { className: "evidence-detail", text: item.detail }));
      }
      entry.append(
        el("div", { className: "evidence-detail", text: `observado ${absoluteTime(item.observed_at)}` }),
      );
      section.append(entry);
    }
    body.append(section);
  }

  if (incident.recommended_actions?.length) {
    const list = el("ul");
    for (const action of incident.recommended_actions) list.append(el("li", { text: action }));
    body.append(
      el("div", { className: "drawer-section" }, el("h3", { text: "Qué hacer" }), list),
    );
  }

  if (incident.runbook?.length) {
    const section = el(
      "div",
      { className: "drawer-section" },
      el("h3", { text: "Runbook revisado" }),
      el("p", {
        className: "dimension-summary",
        text: "RootCause no ejecuta ninguno de estos comandos. Léelos antes de correrlos.",
      }),
    );
    for (const step of incident.runbook) {
      const entry = el(
        "div",
        { className: `runbook-step ${step.kind}` },
        el(
          "div",
          { className: "runbook-head" },
          pill(STEP_LABEL[step.kind] || step.kind, step.kind === "contain" ? "high" : "info"),
          step.platform ? pill(PLATFORM_LABEL[step.platform] || step.platform, "info") : null,
          step.requires_privileges ? pill("Requiere privilegios", "medium") : null,
        ),
        el("p", { text: step.description }),
      );
      if (step.command) {
        const code = el("code", { text: step.command });
        const copy = el("button", {
          className: "icon-button",
          text: "Copiar",
          attrs: { type: "button" },
          on: {
            click: async (event) => {
              try {
                await navigator.clipboard.writeText(step.command);
                event.target.textContent = "Copiado";
              } catch {
                event.target.textContent = "No se pudo copiar";
              }
            },
          },
        });
        entry.append(el("div", { className: "runbook-command" }, code, copy));
      }
      section.append(entry);
    }
    body.append(section);
  }

  if (incident.techniques?.length) {
    const tags = el("div");
    for (const technique of incident.techniques) {
      tags.append(el("span", { className: "tag", text: technique }));
    }
    body.append(
      el("div", { className: "drawer-section" }, el("h3", { text: "MITRE ATT&CK" }), tags),
    );
  }

  const actions = el("div", { className: "status-actions" });
  for (const [value, label] of [
    ["acknowledged", "Marcar como reconocido"],
    ["resolved", "Marcar como resuelto"],
    ["open", "Reabrir"],
  ]) {
    if (incident.status === value) continue;
    actions.append(
      el("button", {
        className: "secondary",
        text: label,
        attrs: { type: "button" },
        on: {
          click: async () => {
            try {
              await post(`/api/v1/incidents/${incident.id}/status`, {
                status: value,
                actor: "console-user",
              });
              dialog.close();
              refresh();
            } catch (error) {
              showError(`No se pudo cambiar el estado: ${error.message}`);
            }
          },
        },
      }),
    );
  }
  body.append(
    el("div", { className: "drawer-section" }, el("h3", { text: "Decisión" }), actions),
  );

  if (!dialog.open) dialog.showModal();
}

/* ------------------------------------------------------------- exposure */

function renderExposure() {
  const report = state.exposure;
  const stats = $("#exposure-stats");
  const body = $("#exposure-body");
  const note = $("#exposure-note");
  stats.replaceChildren();
  body.replaceChildren();

  if (!report) return;

  const critical = report.entries.filter((entry) => entry.severity === "critical").length;
  for (const [label, value] of [
    ["Alcanzables desde cualquier interfaz", number(report.public_services)],
    ["Alcanzables desde la red interna", number(report.private_services)],
    ["De riesgo crítico", number(critical)],
  ]) {
    stats.append(
      el(
        "div",
        { className: "stat" },
        el("span", { className: "stat-label", text: label }),
        el("span", { className: "stat-value", text: value }),
      ),
    );
  }

  const query = state.exposureQuery;
  const entries = report.entries.filter((entry) => {
    if (!query) return true;
    return (
      entry.hostname.toLowerCase().includes(query) ||
      entry.service.toLowerCase().includes(query) ||
      String(entry.port).includes(query)
    );
  });

  if (entries.length === 0) {
    const row = el("tr");
    row.append(
      el("td", {
        className: "empty-message",
        text: "Ningún servicio alcanzable fuera de su host con este filtro.",
        attrs: { colspan: 7 },
      }),
    );
    body.append(row);
  }

  for (const entry of entries) {
    const row = el("tr");
    const severityCell = el("td");
    severityCell.append(severityPill(entry.severity));
    const scopeCell = el("td");
    scopeCell.append(pill(SCOPE_LABEL[entry.scope] || entry.scope, entry.scope));

    row.append(
      severityCell,
      el("td", { text: entry.hostname }),
      el("td", { text: entry.service }),
      el("td", { className: "numeric", text: `${entry.protocol}/${entry.port}` }),
      el("td", { className: "mono", text: entry.address }),
      scopeCell,
      el("td", { className: "mono", text: entry.process || "—" }),
    );
    body.append(row);
  }

  const uninspected = report.uninspected_assets || [];
  note.hidden = uninspected.length === 0;
  note.textContent = uninspected.length
    ? `Sin inspeccionar: ${uninspected.join(", ")}. Un equipo sin superficie reportada no es un equipo sin puertos abiertos.`
    : "";
}

/* -------------------------------------------------------------- threats */

function renderThreats() {
  const report = state.threats;
  const stats = $("#threat-stats");
  const body = $("#threat-body");
  const defense = $("#defense-stats");
  stats.replaceChildren();
  body.replaceChildren();
  defense.replaceChildren();
  if (!report) return;

  for (const [label, value] of [
    ["Intentos fallidos acumulados", number(report.total_failures)],
    ["Orígenes distintos", number(report.distinct_sources)],
  ]) {
    stats.append(
      el(
        "div",
        { className: "stat" },
        el("span", { className: "stat-label", text: label }),
        el("span", { className: "stat-value", text: value }),
      ),
    );
  }

  if (!report.sources.length) {
    const row = el("tr");
    row.append(
      el("td", {
        className: "empty-message",
        text: "Ningún intento de autenticación registrado todavía.",
        attrs: { colspan: 8 },
      }),
    );
    body.append(row);
  }

  for (const source of report.sources) {
    const row = el("tr");
    const severityCell = el("td");
    severityCell.append(severityPill(source.severity));
    row.append(
      severityCell,
      el("td", { className: "mono", text: source.source_address }),
      el("td", { className: "numeric", text: number(source.failures) }),
      el("td", { className: "numeric", text: number(source.successes) }),
      el("td", { text: source.services.join(", ") || "—" }),
      el("td", { text: source.usernames.filter(Boolean).slice(0, 6).join(", ") || "—" }),
      el("td", { text: source.assets.join(", ") || "—" }),
      el("td", { text: relativeTime(source.last_seen) }),
    );
    body.append(row);
  }

  const counters = report.control_plane_defense || [];
  if (!counters.length) {
    defense.append(
      el("p", {
        className: "empty-message",
        text: "El perímetro de este servidor no ha tenido que rechazar nada todavía.",
      }),
    );
  }
  for (const counter of counters) {
    defense.append(
      el(
        "div",
        { className: "stat" },
        el("span", { className: "stat-label", text: counter.reason }),
        el("span", { className: "stat-value", text: number(counter.count) }),
        el("small", { className: "dimension-summary", text: relativeTime(counter.last_seen) }),
      ),
    );
  }
}

function renderTopSources() {
  const container = $("#top-sources");
  container.replaceChildren();
  const sources = (state.threats?.sources || []).slice(0, 6);
  if (!sources.length) {
    container.append(
      el("p", {
        className: "empty-message",
        text: "Sin intentos de autenticación registrados.",
      }),
    );
    return;
  }
  const worst = Math.max(...sources.map((source) => source.failures), 1);
  for (const source of sources) {
    const bar = el("div", { className: "source-bar" });
    const fill = el("span");
    fill.style.width = `${Math.round((source.failures / worst) * 100)}%`;
    bar.append(fill);
    container.append(
      el(
        "div",
        { className: "source-row" },
        el("span", { className: "source-address", text: source.source_address }),
        bar,
        el("span", { className: "source-count", text: `${number(source.failures)} fallidos` }),
      ),
    );
  }
}

/* --------------------------------------------------------------- assets */

function renderAssets() {
  const body = $("#assets-body");
  body.replaceChildren();
  if (!state.assets.length) {
    const row = el("tr");
    row.append(
      el("td", {
        className: "empty-message",
        text: "No hay activos registrados. Ejecuta un agente para incorporar el primero.",
        attrs: { colspan: 10 },
      }),
    );
    body.append(row);
    return;
  }

  for (const asset of state.assets) {
    const metrics = asset.latest_metrics || {};
    const exposed = (asset.security?.listeners || []).filter(
      (socket) => socket.scope !== "loopback",
    ).length;

    const statusCell = el("td");
    statusCell.append(pill(STATUS_LABEL[asset.status] || asset.status, asset.status));

    const postureCell = el("td");
    if (asset.posture) {
      postureCell.append(
        pill(`${asset.posture.score} · ${asset.posture.grade}`, severityForScore(asset.posture.score) === "ok" ? "online" : severityForScore(asset.posture.score)),
      );
    } else {
      postureCell.textContent = "—";
    }

    const row = el("tr");
    row.append(
      el("td", { text: asset.registration.hostname }),
      el("td", { text: ROLE_LABEL[asset.role] || asset.role }),
      el("td", { text: PLATFORM_LABEL[asset.registration.platform] || asset.registration.platform }),
      statusCell,
      postureCell,
      el("td", { className: "numeric", text: number(exposed) }),
      el("td", { className: "numeric", text: percent(metrics.cpu_percent) }),
      el("td", { className: "numeric", text: percent(metrics.memory_percent) }),
      el("td", { className: "numeric", text: percent(metrics.disk_percent) }),
      el("td", { text: relativeTime(asset.last_seen) }),
    );
    body.append(row);
  }
}

/* ------------------------------------------------------------- topology */

function nodeColour(node) {
  if (node.kind === "untrusted") return "#2a1119";
  if (node.kind === "control-plane") return "#0d746f";
  if (node.kind === "zone") return node.zone === "expuesto" ? "#3b1c24" : "#123a4c";
  if (node.status === "offline") return "#1b2830";
  return "#153441";
}

function riskColour(risk) {
  return (
    { critical: "#fb4f64", high: "#fb923c", medium: "#facc15", low: "#38a7ff" }[risk] || "#2b4a5a"
  );
}

function truncate(value, length) {
  return value.length > length ? `${value.slice(0, length - 1)}…` : value;
}

function layoutTopology(topology, width, height) {
  const positions = new Map();
  const zones = topology.nodes.filter((node) => node.kind === "zone");
  const endpoints = topology.nodes.filter((node) => node.kind === "endpoint");

  positions.set("internet", { x: width * 0.1, y: height * 0.25 });
  positions.set("rootcause-server", { x: width * 0.1, y: height * 0.75 });

  zones.forEach((zone, index) => {
    const y = ((index + 1) * height) / (zones.length + 1);
    positions.set(zone.id, { x: width * 0.4, y });
    const children = endpoints.filter((endpoint) =>
      topology.edges.some((edge) => edge.source === zone.id && edge.target === endpoint.id),
    );
    const spread = Math.min(height / Math.max(children.length + 1, 2), 78);
    const start = y - (spread * (children.length - 1)) / 2;
    children.forEach((child, childIndex) => {
      positions.set(child.id, { x: width * 0.76, y: start + childIndex * spread });
    });
  });
  return positions;
}

function renderTopology() {
  const target = $("#full-topology");
  const topology = state.topology;
  const width = 1000;
  const height = 620;
  target.setAttribute("viewBox", `0 0 ${width} ${height}`);
  target.replaceChildren();

  const hasEndpoints = Boolean(topology?.nodes?.some((node) => node.kind === "endpoint"));
  $("#topology-empty").hidden = hasEndpoints;
  if (!topology || !hasEndpoints) return;

  const positions = layoutTopology(topology, width, height);

  for (const edge of topology.edges) {
    const source = positions.get(edge.source);
    const destination = positions.get(edge.target);
    if (!source || !destination) continue;
    const midpoint = (source.x + destination.x) / 2;
    const path = svg("path", {
      d: `M ${source.x} ${source.y} C ${midpoint} ${source.y}, ${midpoint} ${destination.y}, ${destination.x} ${destination.y}`,
      class: `topology-link${edge.risk ? ` risk-${edge.risk}` : ""}`,
    });
    target.append(path);
  }

  for (const node of topology.nodes) {
    const position = positions.get(node.id);
    if (!position) continue;
    const group = svg("g", {
      class: "topology-node",
      transform: `translate(${position.x} ${position.y})`,
    });
    const radius = node.kind === "control-plane" ? 34 : node.kind === "zone" ? 30 : 21;
    group.append(
      svg("circle", {
        r: radius,
        fill: nodeColour(node),
        stroke: node.risk ? riskColour(node.risk) : "#2b4a5a",
        "stroke-width": node.risk ? 3 : 2,
      }),
    );

    const label = svg("text", { y: radius + 18 });
    label.textContent = truncate(node.label, 22);
    group.append(label);

    const subtitleText =
      node.kind === "endpoint"
        ? `${node.exposed_ports} puerto(s) público(s) · ${node.open_incidents} hallazgo(s)`
        : node.kind === "untrusted"
          ? "no confiable"
          : STATUS_LABEL[node.status] || node.status;
    const subtitle = svg("text", { y: radius + 32, class: "node-subtitle" });
    subtitle.textContent = subtitleText;
    group.append(subtitle);
    target.append(group);
  }
}

/* ---------------------------------------------------------------- rules */

function renderRules() {
  const body = $("#rules-body");
  body.replaceChildren();
  for (const rule of state.rules) {
    const row = el("tr");
    const severityCell = el("td");
    severityCell.append(severityPill(rule.severity_ceiling));
    const techniques = el("td");
    for (const technique of rule.techniques) {
      techniques.append(el("span", { className: "tag", text: technique }));
    }
    row.append(
      el("td", { text: rule.category_label }),
      el("td", { className: "mono", text: rule.id }),
      el("td", { text: rule.question }),
      severityCell,
      techniques,
    );
    body.append(row);
  }
}

/* --------------------------------------------------------------- system */

function definitionRow(term, value) {
  return el("div", {}, el("dt", { text: term }), el("dd", { text: value }));
}

function renderSystem() {
  const status = state.status;
  const service = $("#system-service");
  const hardening = $("#system-hardening");
  service.replaceChildren();
  hardening.replaceChildren();
  if (!status) return;

  service.append(
    definitionRow("Versión", status.version),
    definitionRow("Protocolo", status.protocol_version),
    definitionRow("Tiempo activo", duration(status.uptime_seconds)),
    definitionRow("Reglas publicadas", number(status.detectors)),
  );

  const values = status.hardening;
  hardening.append(
    definitionRow("Token exigido", values.authentication ? "Sí" : "No"),
    definitionRow("Escucha", values.bind_is_loopback ? "Solo loopback" : "Fuera de loopback"),
    definitionRow("Límite de tasa", `${number(values.rate_limit_per_minute)} solicitudes/min`),
    definitionRow("Bloqueo tras", `${number(values.lockout_threshold)} fallos`),
    definitionRow("Retención", `${number(values.retention_days)} días`),
  );
}

function renderAudit() {
  const body = $("#audit-body");
  body.replaceChildren();
  if (!state.audit.length) {
    const row = el("tr");
    row.append(
      el("td", {
        className: "empty-message",
        text: "Sin entradas de auditoría todavía.",
        attrs: { colspan: 4 },
      }),
    );
    body.append(row);
    return;
  }
  for (const entry of state.audit) {
    const row = el("tr");
    row.append(
      el("td", { text: absoluteTime(entry.observed_at) }),
      el("td", { text: entry.actor }),
      el("td", { className: "mono", text: entry.action }),
      el("td", { className: "mono", text: entry.target }),
    );
    body.append(row);
  }
}
