"use strict";

const PAGE_SIZE = 20;
const el = (id) => document.getElementById(id);
let apiKey = "";
let incidentOffset = 0;
let eventOffset = 0;
let selected = null;
let revision = 0;
let session = 0;

function element(tag, className, value) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (value !== undefined && value !== null) node.textContent = String(value);
  return node;
}

function date(value) {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? "Unknown time" : parsed.toLocaleString();
}

function notice(value, error = false) {
  el("message").textContent = value;
  el("message").classList.toggle("error", error);
}

async function read(path) {
  const response = await fetch(path, {
    headers: { "X-API-Key": apiKey },
    cache: "no-store",
    redirect: "error",
  });
  if (!response.ok) {
    throw new Error(response.status === 401 ? "API key was rejected." :
      `Could not load data (HTTP ${response.status}).`);
  }
  return response.json();
}

function resetDetail() {
  selected = null;
  revision += 1;
  el("detail").hidden = true;
  el("detail-empty").hidden = false;
}

function showFailure(error) {
  notice(error instanceof Error ? error.message : "Could not load data.", true);
}

async function incidents(offset = 0) {
  const currentSession = session;
  const page = await read(`/v1/incidents?limit=${PAGE_SIZE}&offset=${offset}`);
  if (currentSession !== session) return;
  incidentOffset = offset;
  const list = el("incident-list");
  list.replaceChildren();
  if (!page.length) list.append(element("p", "empty-copy", offset ?
    "No incidents on this page." : "No correlated incidents yet."));
  for (const incident of page) {
    const button = element("button", "incident-card");
    button.type = "button";
    button.setAttribute("aria-pressed", String(selected?.incident_id === incident.incident_id));
    if (selected?.incident_id === incident.incident_id) button.classList.add("selected");
    const top = element("div", "card-top");
    top.append(element("span", "card-title", incident.title));
    const status = element("span", "badge", incident.status);
    if (["open", "closed"].includes(incident.status)) status.classList.add(incident.status);
    top.append(status);
    button.append(top);
    button.append(element("div", "card-subtitle", incident.incident_id));
    button.append(element("div", "card-foot",
      `Severity ${incident.severity}/10 · ${incident.event_ids.length} events · ${date(incident.last_seen)}`));
    button.addEventListener("click", () => selectIncident(incident));
    list.append(button);
  }
  el("incidents-page").textContent = `Page ${Math.floor(offset / PAGE_SIZE) + 1}`;
  el("incidents-prev").disabled = offset === 0;
  el("incidents-next").disabled = page.length < PAGE_SIZE;
  el("workspace").hidden = false;
  el("forget-key").hidden = false;
  notice("");
}

async function selectIncident(incident) {
  selected = incident;
  const current = ++revision;
  eventOffset = 0;
  el("detail-empty").hidden = true;
  el("detail").hidden = false;
  el("selected-title").textContent = incident.title;
  el("selected-meta").textContent =
    `${incident.incident_id} · ${incident.status} · Severity ${incident.severity}/10 · First ${date(incident.first_seen)} · Last ${date(incident.last_seen)}`;
  const entities = el("selected-entities");
  entities.replaceChildren();
  for (const entity of incident.entities) {
    entities.append(element("span", "tag", `${entity.type}: ${entity.value}`));
  }
  const signals = el("selected-signals");
  signals.replaceChildren();
  for (const signal of incident.signals) {
    const card = element("div", "signal");
    card.append(element("strong", "", `${signal.title} · ${signal.mode} · Priority ${signal.priority}/10`));
    card.append(element("span", "", `${signal.rule_id} v${signal.rule_version} · Evidence: ${signal.evidence_event_ids.join(", ")}`));
    signals.append(card);
  }
  el("event-count").textContent = `${incident.event_ids.length} event references`;
  el("event-list").replaceChildren(element("p", "empty-copy", "Loading events…"));
  el("history-list").replaceChildren(element("p", "empty-copy", "Loading history…"));
  for (const button of el("incident-list").querySelectorAll(".incident-card")) {
    button.classList.remove("selected");
    button.setAttribute("aria-pressed", "false");
  }
  const incidentButtons = [...el("incident-list").querySelectorAll(".incident-card")];
  const currentButton = incidentButtons.find((button) =>
    button.querySelector(".card-subtitle")?.textContent === incident.incident_id);
  if (currentButton) {
    currentButton.classList.add("selected");
    currentButton.setAttribute("aria-pressed", "true");
  }
  try {
    await Promise.all([events(0, current), history(current)]);
    if (current === revision) notice("");
  } catch (error) {
    if (current === revision) showFailure(error);
  }
}

async function events(offset, current = revision) {
  const incident = selected;
  if (!incident) return;
  const page = await read(`/v1/incidents/${encodeURIComponent(incident.incident_id)}/events?limit=${PAGE_SIZE}&offset=${offset}`);
  if (current !== revision) return;
  eventOffset = offset;
  const list = el("event-list");
  list.replaceChildren();
  if (!page.length) list.append(element("p", "empty-copy", "No events on this page."));
  for (const event of page) {
    const row = element("article", "event");
    const title = element("div", "event-top");
    title.append(element("span", "event-title", `${event.category} · ${event.source}/${event.event_id}`));
    if (event.outcome) {
      const badge = element("span", "badge", event.outcome);
      if (["failure", "success"].includes(event.outcome)) badge.classList.add(event.outcome);
      title.append(badge);
    }
    row.append(title);
    const rule = event.attributes?.rule_id ? ` · Rule ${event.attributes.rule_id}` : "";
    row.append(element("div", "event-detail",
      `${date(event.event_time)} · Severity ${event.severity}/10${rule}${event.source_ip ? ` · IP ${event.source_ip}` : ""}`));
    list.append(row);
  }
  el("events-page").textContent = `Page ${Math.floor(offset / PAGE_SIZE) + 1}`;
  el("events-prev").disabled = offset === 0;
  el("events-next").disabled = page.length < PAGE_SIZE;
}

async function history(current) {
  const incident = selected;
  if (!incident) return;
  const page = await read(`/v1/incidents/${encodeURIComponent(incident.incident_id)}/history?limit=100`);
  if (current !== revision) return;
  const list = el("history-list");
  list.replaceChildren();
  if (!page.length) list.append(element("p", "empty-copy", "No lifecycle transitions recorded."));
  for (const transition of page) {
    const context = transition.merged_into ? ` · Merged into ${transition.merged_into}` :
      transition.event_id ? ` · Trigger ${transition.event_source}/${transition.event_id}` : "";
    list.append(element("div", "history-item",
      `${date(transition.occurred_at)} · ${transition.action}${context}`));
  }
  if (page.length === 100) list.append(element("p", "empty-copy", "Showing the first 100 transitions."));
}

el("access-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  session += 1;
  apiKey = el("api-key").value.trim();
  el("api-key").value = "";
  resetDetail();
  try {
    await incidents(0);
  } catch (error) {
    apiKey = "";
    el("workspace").hidden = true;
    el("forget-key").hidden = true;
    showFailure(error);
  }
});
el("forget-key").addEventListener("click", () => {
  session += 1;
  apiKey = "";
  resetDetail();
  el("incident-list").replaceChildren();
  el("workspace").hidden = true;
  el("forget-key").hidden = true;
  notice("Key forgotten.");
  el("api-key").focus();
});
el("refresh").addEventListener("click", async () => {
  try { await incidents(incidentOffset); } catch (error) { showFailure(error); }
});
for (const [id, delta] of [["incidents-prev", -PAGE_SIZE], ["incidents-next", PAGE_SIZE]]) {
  el(id).addEventListener("click", async () => {
    try { await incidents(incidentOffset + delta); } catch (error) { showFailure(error); }
  });
}
for (const [id, delta] of [["events-prev", -PAGE_SIZE], ["events-next", PAGE_SIZE]]) {
  el(id).addEventListener("click", async () => {
    try { await events(eventOffset + delta); } catch (error) { showFailure(error); }
  });
}
