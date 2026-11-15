const users = {
  alice: "11111111-1111-1111-1111-111111111111",
  bob: "22222222-2222-2222-2222-222222222222"
};

const documents = {
  alice: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
  bob: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
};

const moduleIds = {
  a01Idor: "A01-IDOR",
  a02Crypto: "A02-CRYPTO",
  a03Sqli: "A03-SQLI",
  a04Design: "A04-DESIGN",
  a05S3: "A05-S3",
  a06Components: "A06-COMPONENTS",
  a07Auth: "A07-AUTH",
  a08Integrity: "A08-INTEGRITY",
  a09Logging: "A09-LOGGING",
  a10Ssrf: "A10-SSRF"
};

const moduleStatus = document.querySelector("#moduleStatus");
const modeExplanation = document.querySelector("#modeExplanation");
const moduleDetails = document.querySelector("#moduleDetails");
const responseStatus = document.querySelector("#responseStatus");
const responseBody = document.querySelector("#responseBody");
const documentsList = document.querySelector("#documentsList");
const detectionsList = document.querySelector("#detectionsList");
const documentIdInput = document.querySelector("#documentId");
const objectDocumentIdInput = document.querySelector("#objectDocumentId");
const ssrfTargetUrlInput = document.querySelector("#ssrfTargetUrl");
const searchTermInput = document.querySelector("#searchTerm");
const componentPayloadInput = document.querySelector("#componentPayload");
const defaultPasswordInput = document.querySelector("#defaultPassword");
const packageUrlInput = document.querySelector("#packageUrl");
const finding = document.querySelector("#finding");

const moduleModes = new Map();

onClick("#refreshModules", loadModules);
onClick("#loadDocuments", loadDocuments);
onClick("#readAliceDocument", () => readDocument(documents.alice));
onClick("#readBobDocument", () => readDocument(documents.bob));
onClick("#runIdorProof", () => readDocument(documents.bob, users.alice));
onClick("#readCustomDocument", () => readDocument(documentIdInput.value.trim()));
onClick("#searchDocuments", () => searchDocuments(searchTermInput.value));
onClick("#runCryptoProof", runCryptoProof);
onClick("#runDesignProof", runDesignProof);
onClick("#readAliceObject", () => readObject(documents.alice));
onClick("#readBobObject", () => readObject(documents.bob));
onClick("#runObjectStorageProof", () => readObject(documents.bob, users.alice));
onClick("#readCustomObject", () => readObject(objectDocumentIdInput.value.trim()));
onClick("#fetchTargetUrl", () => fetchTargetUrl(ssrfTargetUrlInput.value.trim()));
onClick("#runComponentProof", () => runComponentProof(componentPayloadInput.value.trim()));
onClick("#runAuthProof", () => runAuthProof(defaultPasswordInput.value.trim()));
onClick("#runIntegrityProof", () => runIntegrityProof(packageUrlInput.value.trim()));
onClick("#runLoggingProof", runLoggingProof);
onClick("#runSsrfProof", () => {
  ssrfTargetUrlInput.value = "http://localstack:4566/_localstack/health";
  fetchTargetUrl(ssrfTargetUrlInput.value);
});
onClick("#loadCloudDetections", loadCloudDetections);
onClick("#runSqlInjection", () => {
  searchTermInput.value = "' OR 1=1 --";
  searchDocuments(searchTermInput.value);
});

for (const input of document.querySelectorAll("input[name='labUser']")) {
  input.addEventListener("change", () => {
    responseStatus.textContent = "Idle";
    responseStatus.className = "badge badge-muted";
    setFinding("The selected user changed. Run a scenario to interpret the result.", "muted");
  });
}

function onClick(selector, handler) {
  document.querySelector(selector).addEventListener("click", handler);
}

function getCurrentUserId() {
  const selected = document.querySelector("input[name='labUser']:checked").value;
  return users[selected];
}

async function request(path, userId = getCurrentUserId()) {
  const response = await fetch(path, {
    headers: {
      "Accept": "application/json",
      "X-Lab-User-Id": userId
    }
  });

  const raw = await response.text();
  let body = raw;

  try {
    body = raw ? JSON.parse(raw) : null;
  } catch {
    body = raw;
  }

  return {
    ok: response.ok,
    status: response.status,
    statusText: response.statusText,
    userId,
    body
  };
}

async function loadModules() {
  setLoading(moduleStatus, "Loading");

  try {
    const result = await request("/api/vulnerabilities");
    const modules = Array.isArray(result.body) ? result.body : [];
    if (modules.length === 0) {
      setBadge(moduleStatus, "No modules", "muted");
      moduleDetails.innerHTML = "";
      return;
    }

    moduleModes.clear();
    for (const module of modules) {
      moduleModes.set(module.id, module.enabled);
    }

    const enabledCount = modules.filter(x => x.enabled).length;
    setBadge(moduleStatus, `${enabledCount}/${modules.length} vulnerable`, enabledCount > 0 ? "on" : "off");
    modeExplanation.innerHTML = buildModeExplanation(modules);
    moduleDetails.replaceChildren(...modules.map(moduleSummary));
  } catch (error) {
    setBadge(moduleStatus, "API error", "off");
    modeExplanation.textContent = "Cannot load module mode from the API.";
    moduleDetails.textContent = error.message;
  }
}

async function loadDocuments() {
  documentsList.textContent = "Loading documents...";

  try {
    const result = await request("/api/vulnerabilities/a01-broken-access-control/documents");
    updateResponse(result);
    renderDocuments(Array.isArray(result.body) ? result.body : []);
    interpretDocumentList(result);
  } catch (error) {
    documentsList.textContent = error.message;
    updateError(error);
  }
}

async function readDocument(documentId, userId = getCurrentUserId()) {
  if (!documentId) {
    updateError(new Error("Document id is required."));
    return;
  }

  try {
    const result = await request(
      `/api/vulnerabilities/a01-broken-access-control/documents/${encodeURIComponent(documentId)}`,
      userId);
    updateResponse(result);
    interpretDocumentRead(result);
  } catch (error) {
    updateError(error);
  }
}

async function searchDocuments(term) {
  const searchTerm = term.trim();
  documentsList.textContent = "Searching documents...";

  try {
    const result = await request(`/api/vulnerabilities/a03-injection/documents/search?term=${encodeURIComponent(searchTerm)}`);
    updateResponse(result);
    renderDocuments(Array.isArray(result.body) ? result.body : []);
    interpretSqlSearch(result, searchTerm);
  } catch (error) {
    documentsList.textContent = error.message;
    updateError(error);
  }
}

async function readObject(documentId, userId = getCurrentUserId()) {
  if (!documentId) {
    updateError(new Error("Document id is required."));
    return;
  }

  try {
    const result = await request(
      `/api/vulnerabilities/a05-security-misconfiguration/objects/${encodeURIComponent(documentId)}`,
      userId);
    updateResponse(result);
    interpretObjectRead(result);
  } catch (error) {
    updateError(error);
  }
}

async function runCryptoProof() {
  await runVulnerabilityScenario("/api/vulnerabilities/a02-cryptographic-failures/secrets/export");
}

async function runDesignProof() {
  await runVulnerabilityScenario("/api/vulnerabilities/a04-insecure-design/emergency-access");
}

async function runComponentProof(payload) {
  await runVulnerabilityScenario(`/api/vulnerabilities/a06-vulnerable-components/render?payload=${encodeURIComponent(payload)}`);
}

async function runAuthProof(password) {
  await runVulnerabilityScenario(`/api/vulnerabilities/a07-identification-authentication/default-login?password=${encodeURIComponent(password)}`);
}

async function runIntegrityProof(packageUrl) {
  await runVulnerabilityScenario(`/api/vulnerabilities/a08-software-data-integrity/update?packageUrl=${encodeURIComponent(packageUrl)}`);
}

async function runLoggingProof() {
  await runVulnerabilityScenario("/api/vulnerabilities/a09-logging-monitoring/admin-export");
}

async function runVulnerabilityScenario(path) {
  try {
    const result = await request(path);
    updateResponse(result);
    interpretVulnerabilityScenario(result);
  } catch (error) {
    updateError(error);
  }
}

async function loadCloudDetections() {
  detectionsList.textContent = "Reading LocalStack CloudWatch Logs...";

  try {
    const result = await request("/api/detections/cloud");
    updateResponse(result);
    renderCloudDetections(result.body);
    interpretCloudDetections(result);
  } catch (error) {
    detectionsList.textContent = error.message;
    updateError(error);
  }
}

async function fetchTargetUrl(targetUrl) {
  if (!targetUrl) {
    updateError(new Error("Target URL is required."));
    return;
  }

  try {
    const result = await request(`/api/vulnerabilities/a10-ssrf/fetch?url=${encodeURIComponent(targetUrl)}`);
    updateResponse(result);
    interpretServerSideFetch(result);
  } catch (error) {
    updateError(error);
  }
}

function renderDocuments(items) {
  if (items.length === 0) {
    documentsList.textContent = "No documents returned for the selected user.";
    return;
  }

  const list = document.createElement("div");
  list.className = "document-list";

  for (const item of items) {
    const card = document.createElement("article");
    card.className = "document-card";

    const title = document.createElement("h3");
    title.textContent = item.title ?? "Untitled document";

    const details = document.createElement("dl");
    details.append(
      documentLine("ID", item.id),
      documentLine("Owner", item.ownerId),
      documentLine("Class", item.classification)
    );

    card.append(title, details);
    list.append(card);
  }

  documentsList.replaceChildren(list);
}

function documentLine(label, value) {
  const row = document.createElement("div");
  row.textContent = `${label}: ${value ?? "n/a"}`;
  return row;
}

function renderCloudDetections(summary) {
  if (!summary || typeof summary !== "object") {
    detectionsList.textContent = "No detection summary returned.";
    return;
  }

  const alerts = Array.isArray(summary.alerts) ? summary.alerts : [];
  const events = Array.isArray(summary.events) ? summary.events : [];
  const list = document.createElement("div");
  list.className = "document-list";

  const header = document.createElement("article");
  header.className = "document-card";
  header.append(
    detectionLine("Source", summary.source),
    detectionLine("Events", summary.eventCount),
    detectionLine("Alerts", summary.alertCount)
  );
  list.append(header);

  for (const alert of alerts.slice(0, 8)) {
    const card = document.createElement("article");
    card.className = "document-card alert-card";
    card.append(
      detectionLine("Rule", alert.ruleId),
      detectionLine("Severity", alert.severity),
      detectionLine("Type", alert.eventType),
      detectionLine("User", getUserLabel(alert.userId)),
      detectionLine("Owner", getUserLabel(alert.ownerId)),
      detectionLine("Target", alert.targetId),
      detectionLine("Message", alert.message)
    );
    list.append(card);
  }

  if (alerts.length === 0 && events.length === 0) {
    detectionsList.textContent = "No cloud audit events found yet. Run a vulnerable scenario first.";
    return;
  }

  if (alerts.length === 0) {
    const card = document.createElement("article");
    card.className = "document-card";
    card.textContent = "Cloud events exist, but no detection alerts matched the current rules.";
    list.append(card);
  }

  detectionsList.replaceChildren(list);
}

function detectionLine(label, value) {
  const row = document.createElement("div");
  const labelElement = document.createElement("strong");
  labelElement.textContent = `${label}: `;
  row.append(labelElement, document.createTextNode(value ?? "n/a"));
  return row;
}

function detailRow(label, value) {
  const row = document.createElement("div");
  row.className = "detail-row";

  const labelElement = document.createElement("strong");
  labelElement.textContent = label;

  const valueElement = document.createElement("span");
  valueElement.textContent = value ?? "n/a";

  row.append(labelElement, valueElement);
  return row;
}

function updateResponse(result) {
  const mode = result.ok ? "on" : result.status === 404 ? "off" : "muted";
  setBadge(responseStatus, `${result.status} ${result.statusText}`, mode);
  responseBody.textContent = JSON.stringify(result.body, null, 2) || "No response body.";
}

function updateError(error) {
  setBadge(responseStatus, "Error", "off");
  responseBody.textContent = error.message;
  setFinding(error.message, "confirmed");
}

function interpretDocumentRead(result) {
  if (result.status === 404) {
    setFinding(
      "Access was denied or the document was not found. For a cross-user request this is the expected safe behavior.",
      "safe");
    return;
  }

  if (!result.ok || !result.body || typeof result.body !== "object") {
    setFinding("The response cannot be interpreted as a lab document.", "muted");
    return;
  }

  const sameOwner = result.body.ownerId === result.userId;
  const userLabel = getUserLabel(result.userId);
  const ownerLabel = getUserLabel(result.body.ownerId);

  if (sameOwner) {
    setFinding(
      `<strong>Normal access.</strong> ${userLabel} received a document owned by ${ownerLabel}. HTTP 200 is expected here.`,
      "safe");
    return;
  }

  setFinding(
    `<strong>IDOR confirmed.</strong> ${userLabel} received a document owned by ${ownerLabel}. In vulnerable mode this intentionally returns HTTP 200; after disabling the vulnerability it should return HTTP 404.`,
    "confirmed");
}

function interpretDocumentList(result) {
  if (!Array.isArray(result.body)) {
    setFinding("The list response cannot be interpreted.", "muted");
    return;
  }

  const leakedDocuments = result.body.filter(x => x.ownerId && x.ownerId !== result.userId);

  if (leakedDocuments.length === 0) {
    setFinding(
      "The list only contains documents owned by the selected user. That is the expected safe behavior.",
      "safe");
    return;
  }

  setFinding(
    `<strong>List leak visible.</strong> The selected user can see ${leakedDocuments.length} document(s) owned by another user. In vulnerable mode this intentionally returns HTTP 200.`,
    "confirmed");
}

function interpretSqlSearch(result, searchTerm) {
  if (!Array.isArray(result.body)) {
    setFinding("The SQL search response cannot be interpreted.", "muted");
    return;
  }

  const leakedDocuments = result.body.filter(x => x.ownerId && x.ownerId !== result.userId);
  const isInjectionPayload = searchTerm.includes("'") || searchTerm.includes("--") || /\bor\b/i.test(searchTerm);

  if (leakedDocuments.length > 0) {
    setFinding(
      `<strong>SQL injection confirmed.</strong> The search returned ${leakedDocuments.length} document(s) owned by another user. Payload: <code>${escapeHtml(searchTerm)}</code>.`,
      "confirmed");
    return;
  }

  if (isInjectionPayload && moduleModes.get(moduleIds.a03Sqli) === false) {
    setFinding(
      "The injection payload did not bypass owner filtering. That is the expected safe behavior for A03 disabled.",
      "safe");
    return;
  }

  setFinding(
    "The SQL search returned only documents owned by the selected user. This is normal unless the test expected an injection bypass.",
    "safe");
}

function interpretObjectRead(result) {
  if (result.status === 404) {
    setFinding(
      "The S3 object was not returned. For a cross-user object request this is the expected safe behavior.",
      "safe");
    return;
  }

  if (!result.ok || !result.body || typeof result.body !== "object") {
    setFinding("The response cannot be interpreted as a LocalStack S3 object result.", "muted");
    return;
  }

  const sameOwner = result.body.ownerId === result.userId;
  const userLabel = getUserLabel(result.userId);
  const ownerLabel = getUserLabel(result.body.ownerId);
  const location = `${result.body.bucketName}/${result.body.objectKey}`;

  if (sameOwner) {
    setFinding(
      `<strong>Normal object access.</strong> ${userLabel} received a LocalStack S3 object owned by ${ownerLabel}. Object: <code>${escapeHtml(location)}</code>.`,
      "safe");
    return;
  }

  setFinding(
    `<strong>A05 object storage issue confirmed.</strong> ${userLabel} received a LocalStack S3 object for a document owned by ${ownerLabel}. Object: <code>${escapeHtml(location)}</code>. In safe mode this should return HTTP 404.`,
    "confirmed");
}

function interpretCloudDetections(result) {
  if (!result.ok || !result.body || typeof result.body !== "object") {
    setFinding("The cloud detection response cannot be interpreted.", "muted");
    return;
  }

  const alertCount = result.body.alertCount ?? 0;
  const eventCount = result.body.eventCount ?? 0;

  if (alertCount > 0) {
    setFinding(
      `<strong>Cloud detection triggered.</strong> LocalStack CloudWatch Logs contain ${eventCount} event(s) and ${alertCount} alert(s).`,
      "confirmed");
    return;
  }

  setFinding(
    `LocalStack CloudWatch Logs contain ${eventCount} event(s), but no alert rule matched.`,
    "safe");
}

function interpretServerSideFetch(result) {
  if (!result.body || typeof result.body !== "object") {
    setFinding("The SSRF response cannot be interpreted.", "muted");
    return;
  }

  if (result.body.blocked) {
    setFinding(
      `<strong>SSRF blocked.</strong> The server refused to fetch <code>${escapeHtml(result.body.targetUrl)}</code>. Reason: ${escapeHtml(result.body.blockReason)}.`,
      "safe");
    return;
  }

  if (!result.body.fetched) {
    setFinding(
      `<strong>Server-side fetch failed.</strong> ${escapeHtml(result.body.blockReason || "The target could not be fetched.")}`,
      "muted");
    return;
  }

  const isInternalTarget = ["localstack", "localhost"].includes((result.body.host ?? "").toLowerCase()) ||
    /^(127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[0-1])\.)/.test(result.body.host ?? "");

  if (isInternalTarget) {
    setFinding(
      `<strong>SSRF confirmed.</strong> The server fetched internal host <code>${escapeHtml(result.body.host)}</code> and returned HTTP ${result.body.statusCode}. In safe mode this should be blocked.`,
      "confirmed");
    return;
  }

  setFinding(
    `<strong>Server-side fetch completed.</strong> The server fetched external host <code>${escapeHtml(result.body.host)}</code> with HTTP ${result.body.statusCode}.`,
    "safe");
}

function interpretVulnerabilityScenario(result) {
  if (!result.body || typeof result.body !== "object") {
    setFinding("The OWASP scenario response cannot be interpreted.", "muted");
    return;
  }

  const body = result.body;
  const cloudText = body.cloudEventWritten
    ? "A CloudWatch Logs event was written."
    : "No CloudWatch Logs event was written.";

  if (body.scenarioId === moduleIds.a09Logging && body.exploited && !body.cloudEventWritten) {
    setFinding(
      `<strong>A09 logging failure confirmed.</strong> The sensitive action completed without detection telemetry. ${escapeHtml(body.evidence)}`,
      "confirmed");
    return;
  }

  if (body.exploited) {
    setFinding(
      `<strong>${escapeHtml(body.scenarioId)} confirmed.</strong> ${escapeHtml(body.evidence)} ${cloudText}`,
      "confirmed");
    return;
  }

  if (body.blocked) {
    setFinding(
      `<strong>${escapeHtml(body.scenarioId)} blocked.</strong> ${escapeHtml(body.safeControl)} ${cloudText}`,
      "safe");
    return;
  }

  setFinding(
    `<strong>${escapeHtml(body.scenarioId)} control path.</strong> ${escapeHtml(body.evidence)} ${cloudText}`,
    "safe");
}

function buildModeExplanation(modules) {
  const vulnerable = modules.filter(x => x.enabled).map(x => x.id);
  const safe = modules.filter(x => !x.enabled).map(x => x.id);
  const vulnerableText = vulnerable.length > 0 ? vulnerable.join(", ") : "none";
  const safeText = safe.length > 0 ? safe.join(", ") : "none";

  return `<strong>Current lab mode.</strong> Vulnerable: ${escapeHtml(vulnerableText)}. Safe: ${escapeHtml(safeText)}.`;
}

function moduleSummary(module) {
  const wrapper = document.createElement("div");
  wrapper.className = "module-summary";

  const title = document.createElement("strong");
  title.textContent = `${module.id} - ${module.name}`;

  const status = document.createElement("button");
  status.type = "button";
  status.className = `toggle ${module.enabled ? "is-on" : ""}`;
  status.setAttribute("aria-pressed", String(module.enabled));
  status.textContent = module.enabled ? "Vulnerable" : "Safe";
  status.addEventListener("click", () => updateVulnerability(module.id, !module.enabled));

  const description = document.createElement("p");
  description.textContent = module.description;

  const route = document.createElement("small");
  route.textContent = module.route;

  wrapper.append(title, status, description, route);
  return wrapper;
}

async function updateVulnerability(moduleId, enabled) {
  try {
    const response = await fetch(`/api/vulnerabilities/${encodeURIComponent(moduleId)}/enabled`, {
      method: "PUT",
      headers: {
        "Accept": "application/json",
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ enabled })
    });

    if (!response.ok) {
      throw new Error(`Toggle failed with HTTP ${response.status}.`);
    }

    setFinding(
      `<strong>${moduleId} switched to ${enabled ? "vulnerable" : "safe"} mode.</strong> Run the scenario again to verify behavior.`,
      enabled ? "confirmed" : "safe");
    await loadModules();
  } catch (error) {
    updateError(error);
  }
}

function escapeHtml(value) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function getUserLabel(userId) {
  if (userId === users.alice) {
    return "Alice";
  }

  if (userId === users.bob) {
    return "Bob";
  }

  return userId ?? "unknown user";
}

function setFinding(message, mode) {
  finding.innerHTML = message;
  finding.className = `finding finding-${mode}`;
}

function setLoading(element, label) {
  element.textContent = label;
  element.className = "badge badge-muted";
}

function setBadge(element, label, mode) {
  element.textContent = label;
  element.className = `badge badge-${mode}`;
}

loadModules();
