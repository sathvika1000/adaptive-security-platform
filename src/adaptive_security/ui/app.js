"use strict";

const PAGE_SIZE = 20;
const el = (id) => document.getElementById(id);
let apiKey = "";
let incidentOffset = 0;
let eventOffset = 0;
let contextOffset = 0;
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
  el("analyst-key").value = "";
  el("close-form").hidden = true;
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
  el("analyst-key").value = "";
  el("close-form").hidden = incident.status !== "open";
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
    card.append(element("span", "", `${signal.rule_id} v${signal.rule_version} · ${signal.evidence_event_ids.length} evidence events`));
    const references = element("details", "evidence-details");
    references.append(element("summary", "", "Evidence references"));
    references.append(element("pre", "", signal.evidence_event_ids.join("\n")));
    card.append(references);
    if (signal.rule_id === "auth.password_spray" && signal.rule_version === 1) {
      const accounts = new Set(incident.entities.filter((e) => e.type === "user")
        .map((e) => e.value.toLowerCase()));
      card.append(element("p", "explanation",
        `This candidate contains failed logons targeting ${accounts.size} distinct accounts. ` +
        "The rule requires at least five accounts from a common IP or explicit source workstation within five minutes. " +
        "This is a historical offline replay finding; active is the stored signal mode, not live deployment. " +
        "Failed attempts do not establish a successful compromise."));
    }
    signals.append(card);
  }
  el("event-count").textContent = `${incident.event_ids.length} event references`;
  el("event-list").replaceChildren(element("p", "empty-copy", "Loading events…"));
  el("history-list").replaceChildren(element("p", "empty-copy", "Loading history…"));
  el("context-list").replaceChildren(element("p", "empty-copy", "Loading context…"));
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
    await Promise.all([events(0, current), context(0, current), history(current)]);
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
  for (const event of page) list.append(eventRow(event));
  el("events-page").textContent = `Page ${Math.floor(offset / PAGE_SIZE) + 1}`;
  el("events-prev").disabled = offset === 0;
  el("events-next").disabled = page.length < PAGE_SIZE;
}

function eventRow(event, supporting = false) {
  const row = element("article", "event");
  const title = element("div", "event-top");
  const user = event.entities.find((e) => e.type === "user")?.value;
  const host = event.entities.find((e) => e.type === "host")?.value;
  const origin = event.source_ip || event.entities.find((e) => e.type === "source_host")?.value;
  const attrs = event.attributes || {};
  let description = event.category;
  if (event.action === "logon") description = `Logon ${event.outcome || "attempt"}${user ? ` · ${user}` : ""}`;
  else if (event.action === "captured_connection") {
    description = `${attrs.protocol?.toUpperCase() || "Network"} · ${event.source_ip}:${attrs.source_port} → ${attrs.destination_ip}:${attrs.destination_port}`;
  } else if (user) description += ` · ${user}`;
  title.append(element("span", "event-title", description));
  if (event.outcome) {
    const badge = element("span", "badge", event.outcome);
    if (["failure", "success"].includes(event.outcome)) badge.classList.add(event.outcome);
    title.append(badge);
  }
  row.append(title);
  const severity = event.severity === 0 && ["otrf", "otrf-network"].includes(event.source) ?
    "Severity unassigned" : `Severity ${event.severity}/10`;
  row.append(element("div", "event-detail", `${date(event.event_time)} · ${severity}`));
  if (host) row.append(element("div", "event-detail", `Endpoint: ${host}`));
  if (origin) row.append(element("div", "event-detail", `Origin: ${origin}`));
  if (supporting) {
    row.append(element("p", "explanation", attrs.explanation || "Supporting context; not detection evidence."));
    row.append(element("div", "event-detail", `${attrs.packet_count} captured packets · ${attrs.matched_host_event_ids?.length || 0} matching host events`));
  }
  const details = element("details", "evidence-details");
  details.append(element("summary", "", "Source record and references"));
  details.append(element("pre", "", JSON.stringify({
    source: event.source, event_id: event.event_id, observed_time: event.observed_time,
    action: event.action, entities: event.entities, attributes: attrs,
  }, null, 2)));
  row.append(details);
  return row;
}

async function context(offset, current = revision) {
  const incident = selected;
  if (!incident) return;
  const list = el("context-list");
  const count = incident.context_event_refs?.length || 0;
  el("context-count").textContent = `${count} network context references`;
  const page = count ? await read(`/v1/incidents/${encodeURIComponent(incident.incident_id)}/context?limit=${PAGE_SIZE}&offset=${offset}`) : [];
  if (current !== revision) return;
  contextOffset = offset;
  list.replaceChildren();
  if (!page.length) list.append(element("p", "empty-copy", "No linked network context on this page."));
  for (const event of page) list.append(eventRow(event, true));
  el("context-page").textContent = `Page ${Math.floor(offset / PAGE_SIZE) + 1}`;
  el("context-prev").disabled = offset === 0;
  el("context-next").disabled = page.length < PAGE_SIZE;
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
    const attribution = transition.actor ? ` · Analyst ${transition.actor}` : "";
    list.append(element("div", "history-item",
      `${date(transition.occurred_at)} · ${transition.action}${attribution}${context}`));
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
el("close-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const incident = selected;
  if (!incident || incident.status !== "open") return;
  const analystKey = el("analyst-key").value;
  if (!window.confirm(`Close ${incident.incident_id}? Review its evidence before confirming.`)) return;
  el("analyst-key").value = "";
  const button = el("close-incident");
  button.disabled = true;
  const currentSession = session;
  const currentRevision = revision;
  try {
    const response = await fetch(`/v1/incidents/${encodeURIComponent(incident.incident_id)}/close`, {
      method: "POST",
      headers: { "X-API-Key": apiKey, "X-Analyst-Key": analystKey },
      cache: "no-store",
      redirect: "error",
    });
    if (!response.ok) throw new Error(response.status === 401 ?
      "Analyst key was rejected." : response.status === 403 ?
      "This analyst key cannot close incidents." :
      `Could not close incident (HTTP ${response.status}).`);
    const updated = await response.json();
    if (currentSession !== session) return;
    await incidents(incidentOffset);
    if (currentSession !== session) return;
    if (currentRevision === revision && selected?.incident_id === incident.incident_id) {
      await selectIncident(updated);
    }
    if (currentSession !== session) return;
    notice(`Closed ${updated.incident_id}.`);
  } catch (error) {
    if (currentSession === session) showFailure(error);
  } finally {
    button.disabled = false;
  }
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

for (const [id, delta] of [["context-prev", -PAGE_SIZE], ["context-next", PAGE_SIZE]]) {
  el(id).addEventListener("click", async () => {
    try { await context(contextOffset + delta); } catch (error) { showFailure(error); }
  });
}
