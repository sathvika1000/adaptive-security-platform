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
let activeView = "live";
let offlineRevision = 0;
let offlineEventRevision = 0;
let offlineCapture = null;
let offlineFinding = null;
let offlineOffset = 0;
let offlineEvidence = true;
let reviewRevision = 0;
let reviewState = null;
let reviewOffset = 0;

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
  if (currentSession !== session || activeView !== "live") return;
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
  el("view-tabs").hidden = false;
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
    if (signal.rule_id === "auth.rc4_service_ticket_burst" && signal.rule_version === 1) {
      const services = new Set(incident.entities.filter((e) => e.type === "service_account")
        .map((e) => e.value.trim().toLowerCase()));
      card.append(element("p", "explanation",
        `This candidate contains successful RC4 ticket requests for ${services.size} distinct service accounts. ` +
        "The rule requires at least five nonmachine services in five minutes from one requester and client IP on one domain controller. " +
        "This is an offline replay finding. Legacy applications can produce the same pattern; " +
        "ticket issuance does not prove password cracking or compromise."));
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
  else if (event.action === "explicit_credentials") description = `Credential attempt${user ? ` · Target: ${user}` : ""}`;
  else if (event.action === "kerberos_preauth") description = `Kerberos preauthentication failure${user ? ` · Target: ${user}` : ""}`;
  else if (event.action === "service_ticket_request") {
    description = `Service ticket · ${attrs.service_name || "Unknown service"}${user ? ` · Requester: ${user}` : ""}`;
  }
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
  const severity = event.severity === 0 && ["otrf", "otrf-network", "evtx"].includes(event.source) ?
    "Severity unassigned" : `Severity ${event.severity}/10`;
  row.append(element("div", "event-detail", `${date(event.event_time)} · ${severity}`));
  if (host) row.append(element("div", "event-detail",
    `${["service_ticket_request", "kerberos_preauth"].includes(event.action) ? "Domain controller" : "Endpoint"}: ${host}`));
  if (origin) row.append(element("div", "event-detail", `Origin: ${origin}`));
  if (event.action === "service_ticket_request") {
    row.append(element("div", "event-detail",
      `Ticket encryption: ${attrs.ticket_encryption_type === 23 ? "RC4 (0x17)" : attrs.ticket_encryption_type ?? "Unknown"} · ` +
      `Ticket status: ${attrs.ticket_status === 0 ? "Issued successfully" : attrs.ticket_status ?? "Unknown"}`));
  }
  if (event.action === "explicit_credentials") {
    const raw = attrs.raw || {};
    const caller = raw.SubjectUserName || raw.SubjectUserSid || "Unknown caller";
    row.append(element("div", "event-detail", `Caller: ${caller} · Session: ${raw.SubjectLogonId || "Unavailable"}`));
    row.append(element("div", "event-detail", `Process: ${raw.ProcessName || "Name unavailable"} · PID: ${raw.ProcessId || "Unavailable"}`));
    row.append(element("div", "event-detail", `Target server: ${raw.TargetServerName || "Unavailable"} · Target logon outcome unrecorded`));
  }
  if (event.action === "kerberos_preauth") {
    const code = Number.isInteger(attrs.kerberos_status) ? `0x${attrs.kerberos_status.toString(16)}` : "Unknown";
    row.append(element("div", "event-detail", `Preauthentication status: ${code}`));
  }
  if (event.source === "evtx") {
    row.append(element("div", "event-detail", `Windows event ${attrs.windows_event_id} · Record ${attrs.evtx_record_id || "Unavailable"}`));
    row.append(element("div", "event-detail", attrs.observation_time_basis || "Collection observation time unavailable"));
  }
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
  resetOffline();
  setView("live");
  try {
    await incidents(0);
  } catch (error) {
    apiKey = "";
    el("workspace").hidden = true;
    el("view-tabs").hidden = true;
    el("forget-key").hidden = true;
    showFailure(error);
  }
});
el("forget-key").addEventListener("click", () => {
  session += 1;
  apiKey = "";
  resetDetail();
  resetOffline();
  el("view-tabs").hidden = true;
  el("offline-workspace").hidden = true;
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

function resetOffline() {
  resetAssessment();
  offlineRevision += 1;
  offlineEventRevision += 1;
  offlineCapture = null;
  offlineFinding = null;
  for (const id of ["offline-captures", "offline-findings", "offline-events"]) el(id).replaceChildren();
  for (const id of ["offline-provenance", "offline-capture-provenance", "offline-meta", "offline-title", "offline-rule", "offline-coverage", "offline-event-scope", "offline-page"]) el(id).textContent = "";
  el("offline-detail").hidden = true;
  el("offline-empty").hidden = false;
}

function setView(view) {
  activeView = view;
  revision += 1;
  offlineRevision += 1;
  offlineEventRevision += 1;
  el("workspace").hidden = view !== "live";
  el("offline-workspace").hidden = view !== "offline";
  el("view-live").setAttribute("aria-pressed", String(view === "live"));
  el("view-offline").setAttribute("aria-pressed", String(view === "offline"));
  el("analyst-key").value = "";
  el("offline-analyst-key").value = "";
  reviewRevision += 1;
}

async function offlineIndex() {
  const current = ++offlineRevision;
  const currentSession = session;
  const run = await read("/v1/offline-review");
  if (current !== offlineRevision || currentSession !== session || activeView !== "offline") return;
  el("offline-captures").replaceChildren();
  if (!run.configured) {
    el("offline-captures").append(element("p", "empty-copy",
      "No offline output is configured. Start the review server with ASP_OFFLINE_REVIEW_PATH pointing to an EVTX evaluation output directory."));
    notice("");
    return;
  }
  el("offline-rule").textContent = `Stored rule: ${run.rule_id} · Live deployment disabled for these rules`;
  el("offline-provenance").textContent = JSON.stringify(run.provenance, null, 2);
  for (const capture of run.captures) {
    const button = element("button", "incident-card");
    button.type = "button";
    button.dataset.captureId = capture.capture_id;
    button.setAttribute("aria-pressed", "false");
    button.append(element("div", "card-title", capture.capture_id));
    button.append(element("div", "card-subtitle", `${capture.partition} · ${capture.label} · ${capture.verdict.replaceAll("_", " ")}`));
    button.append(element("div", "card-foot", `${capture.records} records · ${capture.finding_count} candidate findings`));
    button.addEventListener("click", () => selectOfflineCapture(capture.capture_id));
    el("offline-captures").append(button);
  }
  notice("");
}

async function selectOfflineCapture(identifier) {
  const current = ++offlineRevision;
  const currentSession = session;
  offlineEventRevision += 1;
  resetAssessment();
  el("offline-detail").hidden = true;
  try {
    const capture = await read(`/v1/offline-review/captures/${encodeURIComponent(identifier)}`);
    if (current !== offlineRevision || currentSession !== session || activeView !== "offline") return;
    offlineCapture = capture;
    offlineFinding = capture.findings[0] || null;
    offlineEvidence = Boolean(offlineFinding);
    const summary = capture.summary;
    el("offline-empty").hidden = true;
    el("offline-detail").hidden = false;
    el("offline-title").textContent = summary.capture_id;
    el("offline-meta").textContent = `${summary.partition} · Case label: ${summary.label} · ${summary.verdict.replaceAll("_", " ")} · ${summary.records} records`;
    el("offline-coverage").textContent = summary.selected_event_records === 0 ?
      "No records of the selected Windows event type are present. This capture does not exercise that event family." :
      `${summary.selected_event_records} records of the selected event type are present. Required origins, statuses and distinct-account thresholds still determine eligibility. ` +
      (summary.label === "unlabeled" ? "This capture is excluded from accuracy calculations." :
        "This is a declared capture-level label; individual background records are not automatically labeled.");
    el("offline-capture-provenance").textContent = JSON.stringify(capture.metadata, null, 2);
    for (const button of el("offline-captures").querySelectorAll("button")) {
      button.classList.toggle("selected", button.dataset.captureId === identifier);
      button.setAttribute("aria-pressed", String(button.dataset.captureId === identifier));
    }
    renderOfflineFindings();
    await Promise.all([offlineEvents(0), loadAssessment(0)]);
    if (current === offlineRevision && currentSession === session) notice("");
  } catch (error) {
    if (current === offlineRevision && currentSession === session) showFailure(error);
  }
}

function renderOfflineFindings() {
  const list = el("offline-findings");
  list.replaceChildren();
  if (!offlineCapture.findings.length) list.append(element("p", "empty-copy",
    "No candidate findings in this stored run. This does not establish benign activity."));
  for (const finding of offlineCapture.findings) {
    const button = element("button", "incident-card");
    button.type = "button";
    button.classList.toggle("selected", finding.incident_id === offlineFinding?.incident_id);
    button.setAttribute("aria-pressed", String(finding.incident_id === offlineFinding?.incident_id));
    button.append(element("div", "card-title", finding.title));
    button.append(element("div", "card-subtitle", `${finding.incident_id} · ${finding.event_ids.length} evidence records`));
    button.append(element("div", "card-foot", `${date(finding.first_seen)} → ${date(finding.last_seen)}`));
    const rule = finding.signals[0];
    button.append(element("p", "explanation", `${rule.rule_id} v${rule.rule_version} · Offline candidate. ` +
      (rule.rule_id === "auth.explicit_credential_fanout" ?
        "Five distinct target accounts in five minutes from a common caller/session/process/server. Credential attempts do not prove target logon success or compromise." :
        "Five distinct accounts with bad-password preauthentication failures in five minutes from a common client and domain controller. This does not prove compromise.")));
    button.addEventListener("click", async () => {
      resetAssessment();
      offlineFinding = finding;
      offlineEvidence = true;
      renderOfflineFindings();
      try { await Promise.all([offlineEvents(0), loadAssessment(0)]); } catch (error) { showFailure(error); }
    });
    list.append(button);
  }
}

async function offlineEvents(offset) {
  if (!offlineCapture) return;
  const current = ++offlineEventRevision;
  const currentCapture = offlineRevision;
  const currentSession = session;
  const finding = offlineEvidence ? offlineFinding : null;
  const query = finding ? `&finding_id=${encodeURIComponent(finding.incident_id)}` : "";
  el("offline-evidence").disabled = !offlineFinding;
  el("offline-evidence").setAttribute("aria-pressed", String(Boolean(finding)));
  el("offline-all").setAttribute("aria-pressed", String(!finding));
  el("offline-event-scope").textContent = finding ?
    `Evidence for ${finding.incident_id} · ${finding.event_ids.length} records` :
    `All ${offlineCapture.summary.records} capture records, including unsupported/background events`;
  el("offline-events").replaceChildren(element("p", "empty-copy", "Loading records…"));
  const page = await read(`/v1/offline-review/captures/${encodeURIComponent(offlineCapture.summary.capture_id)}/events?limit=${PAGE_SIZE}&offset=${offset}${query}`);
  if (current !== offlineEventRevision || currentCapture !== offlineRevision || currentSession !== session || activeView !== "offline") return;
  offlineOffset = offset;
  el("offline-events").replaceChildren();
  if (!page.length) el("offline-events").append(element("p", "empty-copy", "No records on this page."));
  for (const event of page) el("offline-events").append(eventRow(event));
  el("offline-page").textContent = `Page ${Math.floor(offset / PAGE_SIZE) + 1}`;
  el("offline-prev").disabled = offset === 0;
  el("offline-next").disabled = offset + page.length >= (finding ? finding.event_ids.length : offlineCapture.summary.records);
}

el("view-live").addEventListener("click", async () => {
  setView("live");
  try { await incidents(incidentOffset); } catch (error) { showFailure(error); }
});
el("view-offline").addEventListener("click", async () => {
  resetOffline();
  setView("offline");
  try { await offlineIndex(); } catch (error) { showFailure(error); }
});
for (const [id, evidence] of [["offline-evidence", true], ["offline-all", false]]) {
  el(id).addEventListener("click", async () => {
    offlineEvidence = evidence;
    try { await offlineEvents(0); } catch (error) { showFailure(error); }
  });
}
for (const [id, delta] of [["offline-prev", -PAGE_SIZE], ["offline-next", PAGE_SIZE]]) {
  el(id).addEventListener("click", async () => {
    try { await offlineEvents(offlineOffset + delta); } catch (error) { showFailure(error); }
  });
}

function resetAssessment() {
  reviewRevision += 1;
  reviewState = null;
  reviewOffset = 0;
  el("offline-review-panel").hidden = true;
  el("offline-note").value = "";
  el("offline-analyst-key").value = "";
  el("offline-disposition").value = "needs_review";
  el("offline-review-history").replaceChildren();
  el("offline-review-current").textContent = "";
  el("offline-review-page").textContent = "";
  el("offline-save-review").disabled = true;
  el("offline-export-review").disabled = true;
}

function assessmentPath() {
  return `/v1/offline-review/captures/${encodeURIComponent(offlineCapture.summary.capture_id)}/findings/${encodeURIComponent(offlineFinding.incident_id)}/reviews`;
}

async function loadAssessment(offset = 0) {
  if (!offlineFinding) return;
  const current = ++reviewRevision;
  const currentCapture = offlineRevision;
  const currentSession = session;
  const path = assessmentPath();
  el("offline-save-review").disabled = true;
  el("offline-export-review").disabled = true;
  const page = await read(`${path}?limit=${PAGE_SIZE}&offset=${offset}`);
  if (current !== reviewRevision || currentCapture !== offlineRevision || currentSession !== session || activeView !== "offline") return;
  reviewState = {path, revision: page.revision, review_key: page.review_key};
  reviewOffset = offset;
  el("offline-review-panel").hidden = false;
  el("offline-save-review").disabled = false;
  el("offline-export-review").disabled = false;
  if (offset === 0) {
    const latest = page.entries[0];
    el("offline-review-current").textContent = latest ?
      `Current assessment: ${latest.disposition.replaceAll("_", " ")} · Revision ${latest.revision}` :
      "No assessment saved. Needs review.";
    el("offline-disposition").value = latest?.disposition || "needs_review";
  }
  el("offline-review-history").replaceChildren();
  for (const entry of page.entries) {
    const row = element("article", "history-item");
    row.append(element("strong", "", `Revision ${entry.revision} · ${entry.disposition.replaceAll("_", " ")}`));
    row.append(element("p", "muted", `${date(entry.occurred_at)} · ${entry.actor || "Shared key (unattributed)"}`));
    row.append(element("p", "review-note", entry.note));
    el("offline-review-history").append(row);
  }
  el("offline-review-page").textContent = `Page ${Math.floor(offset / PAGE_SIZE) + 1}`;
  el("offline-review-prev").disabled = offset === 0;
  el("offline-review-next").disabled = offset + page.entries.length >= page.revision;
}

el("offline-review-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!reviewState || activeView !== "offline") return;
  const state = reviewState;
  const current = reviewRevision;
  const currentSession = session;
  const note = el("offline-note").value.trim();
  if (!note) { notice("Explain the assessment before saving.", true); return; }
  const analystKey = el("offline-analyst-key").value;
  el("offline-analyst-key").value = "";
  el("offline-save-review").disabled = true;
  try {
    const response = await fetch(state.path, {
      method: "POST", cache: "no-store", redirect: "error",
      headers: {"X-API-Key": apiKey, "X-Analyst-Key": analystKey, "Content-Type": "application/json"},
      body: JSON.stringify({disposition: el("offline-disposition").value, note,
        expected_revision: state.revision, review_key: state.review_key}),
    });
    if (current !== reviewRevision || currentSession !== session || activeView !== "offline") return;
    if (response.status === 409) {
      await loadAssessment(0);
      notice("The review or finding changed. Your note is retained; check the latest assessment before saving again.", true);
      return;
    }
    if (!response.ok) throw new Error(response.status === 401 ? "Analyst key was rejected." :
      response.status === 403 ? "This analyst key needs review permission." :
      `Could not save assessment (HTTP ${response.status}).`);
    el("offline-note").value = "";
    await loadAssessment(0);
    if (currentSession === session && activeView === "offline" && reviewState?.path === state.path) notice("Assessment saved; capture labels and detector results are unchanged.");
  } catch (error) {
    if (current === reviewRevision && currentSession === session) showFailure(error);
  } finally {
    if (currentSession === session && reviewState?.path === state.path) el("offline-save-review").disabled = false;
  }
});
for (const [id, delta] of [["offline-review-prev", -PAGE_SIZE], ["offline-review-next", PAGE_SIZE]]) {
  el(id).addEventListener("click", async () => {
    try { await loadAssessment(reviewOffset + delta); } catch (error) { showFailure(error); }
  });
}

el("offline-export-review").addEventListener("click", async () => {
  if (!reviewState || activeView !== "offline") return;
  const state = reviewState;
  const current = reviewRevision;
  const currentSession = session;
  const captureId = offlineCapture.summary.capture_id;
  el("offline-export-review").disabled = true;
  try {
    const path = state.path.replace(/\/reviews$/, "/export");
    const response = await fetch(`${path}?review_key=${encodeURIComponent(state.review_key)}&expected_revision=${state.revision}`, {
      headers: {"X-API-Key": apiKey}, cache: "no-store", redirect: "error",
    });
    if (current !== reviewRevision || currentSession !== session || activeView !== "offline") return;
    if (response.status === 409) {
      await loadAssessment(0);
      notice("The finding or assessment changed. Review the latest history, then export again.", true);
      return;
    }
    if (!response.ok) throw new Error(`Could not export review (HTTP ${response.status}).`);
    const artifact = await response.json();
    if (current !== reviewRevision || currentSession !== session || activeView !== "offline") return;
    const url = URL.createObjectURL(new Blob([JSON.stringify(artifact, null, 2)], {type: "application/json"}));
    const link = document.createElement("a");
    link.href = url;
    link.download = `${captureId}-${state.review_key.slice(0, 12)}-review.json`;
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    notice(artifact.assessment_history.history_truncated ?
      "Export downloaded with the latest 100 revisions; older history is omitted." :
      "Finding review exported with evidence and assessment history.");
  } catch (error) {
    if (current === reviewRevision && currentSession === session) showFailure(error);
  } finally {
    if (currentSession === session && reviewState?.path === state.path) el("offline-export-review").disabled = false;
  }
});
