"use strict";

/* ChartCraft clinician chart view — vanilla JS, no deps.
   Talks to the FHIR-ish backend served from the same origin. */

const API = ""; // same-origin; backend serves this page at /

/* ---------- tiny DOM helpers ---------- */
const $ = (sel) => document.querySelector(sel);
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
};

/* ---------- app state ---------- */
let patients = [];
let selectedId = null;

/* ---------- fetch helpers ---------- */
/* Raised when a data request comes back 401 — the session is gone. Callers
   should swallow it quietly (the session-expired bounce already ran) rather
   than painting their own error over the login screen. */
function authError(path) {
  const e = new Error(`Unauthorized: ${path}`);
  e.isAuth = true;
  return e;
}

async function apiGet(path) {
  const res = await fetch(API + path, {
    credentials: "same-origin",
    headers: { Accept: "application/json" },
  });
  if (res.status === 401) { handleSessionExpired(); throw authError(path); }
  if (res.status === 403) { handlePendingSession(); throw authError(path); }
  if (!res.ok) throw new Error(`GET ${path} → ${res.status}`);
  return res.json();
}

async function apiPost(type, resource) {
  const res = await fetch(API + "/" + type, {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(resource),
  });
  if (res.status === 401) { handleSessionExpired(); throw authError("/" + type); }
  if (res.status === 403) { handlePendingSession(); throw authError("/" + type); }
  if (!res.ok) throw new Error(`POST /${type} → ${res.status}`);
  return res.json();
}

/* Bundle → array of resources, tolerant of shape */
function entries(bundle) {
  if (!bundle || !Array.isArray(bundle.entry)) return [];
  return bundle.entry.map((e) => (e && e.resource) ? e.resource : e).filter(Boolean);
}

/* ---------- FHIR field extraction (all guarded) ---------- */
function patientName(p) {
  const n = p?.name?.[0];
  if (!n) return "Unknown patient";
  if (n.text) return n.text;
  const given = Array.isArray(n.given) ? n.given.join(" ") : (n.given || "");
  const family = n.family || "";
  const full = `${given} ${family}`.trim();
  return full || "Unknown patient";
}

function fmtDate(d) {
  if (!d) return null;
  // Expecting YYYY-MM-DD; render readable without timezone drift.
  const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(d);
  if (!m) return d;
  const months = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
  return `${months[+m[2] - 1]} ${+m[3]}, ${m[1]}`;
}

function ageFrom(birthDate) {
  const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(birthDate || "");
  if (!m) return null;
  const bd = new Date(+m[1], +m[2] - 1, +m[3]);
  if (isNaN(bd)) return null;
  const now = new Date();
  let age = now.getFullYear() - bd.getFullYear();
  const mo = now.getMonth() - bd.getMonth();
  if (mo < 0 || (mo === 0 && now.getDate() < bd.getDate())) age--;
  return age >= 0 && age < 150 ? age : null;
}

function cap(s) { return s ? s.charAt(0).toUpperCase() + s.slice(1) : s; }

/* ---------- UTF-8-safe base64 ---------- */
function encodeNote(text) {
  const bytes = new TextEncoder().encode(text || "");
  let bin = "";
  // chunk to avoid blowing the call stack on long notes
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
  }
  return btoa(bin);
}

function decodeNote(data) {
  if (!data) return "";
  try {
    const bin = atob(data);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return new TextDecoder().decode(bytes);
  } catch (_e) {
    // not valid base64 — fall back to the raw string rather than crashing
    return typeof data === "string" ? data : "";
  }
}

function fmtDateTime(d) {
  if (!d) return null;
  const dt = new Date(d);
  if (isNaN(dt)) return fmtDate(d) || d;
  // build the date from LOCAL components so a late-evening save doesn't show tomorrow
  const months = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
  const date = `${months[dt.getMonth()]} ${dt.getDate()}, ${dt.getFullYear()}`;
  let h = dt.getHours();
  const min = String(dt.getMinutes()).padStart(2, "0");
  const ap = h >= 12 ? "PM" : "AM";
  h = h % 12 || 12;
  return `${date}, ${h}:${min} ${ap}`;
}

/* ---------- note skeletons ---------- */
const SIGNING_CLINICIAN = "Dr. (signing clinician)";

function settingLine(setting) {
  if (setting === "ICU") return "Setting: Intensive Care Unit";
  if (setting === "Skilled nursing facility") return "Setting: Skilled Nursing Facility";
  return "Setting: Outpatient Clinic";
}

function noteSkeleton(type, setting) {
  const hdr = `${type}  —  ${setting === "ICU" ? "Intensive Care Unit"
    : setting === "Skilled nursing facility" ? "Skilled Nursing Facility"
    : "Outpatient Clinic"}\n${"=".repeat(52)}\n\n`;

  if (type === "H&P") {
    const courseHint = setting === "ICU"
      ? "(reason for ICU admission, acuity, lines/drips, ventilation)"
      : setting === "Skilled nursing facility"
      ? "(reason for SNF admission, prior level of care, goals)"
      : "(reason for today's visit)";
    return hdr +
`CHIEF COMPLAINT:
\t${courseHint}

HISTORY OF PRESENT ILLNESS:
\t

PAST MEDICAL / SURGICAL HISTORY:
\t

MEDICATIONS:
\t

ALLERGIES:
\t

REVIEW OF SYSTEMS:
\t

PHYSICAL EXAM:
\tVitals:
\tGeneral:
${setting === "ICU" ? "\tLines/Devices: \n\tVentilator/O2: \n" : ""}
ASSESSMENT & PLAN:
\t1.
\t2.

${settingLine(setting)}
`;
  }

  if (type === "Discharge summary") {
    const course = setting === "ICU"
      ? "HOSPITAL COURSE (ICU):\n\t(critical illness course, major events, de-escalation)"
      : setting === "Skilled nursing facility"
      ? "FACILITY COURSE:\n\t(therapy progress, functional status, response to treatment)"
      : "COURSE:\n\t(interval course since last visit)";
    return hdr +
`ADMISSION DIAGNOSIS:
\t

DISCHARGE DIAGNOSIS:
\t

${course}

DISCHARGE MEDICATIONS:
\t

FOLLOW-UP:
\t

${settingLine(setting)}
`;
  }

  // Progress note (SOAP)
  const objHint = setting === "ICU"
    ? "Vitals / hemodynamics: \n\tVent/O2: \n\tDrips: \n\tI/O: \n\tExam: "
    : setting === "Skilled nursing facility"
    ? "Vitals: \n\tInterval nursing/therapy notes: \n\tExam: "
    : "Vitals: \n\tExam: ";
  return hdr +
`SUBJECTIVE:
\t

OBJECTIVE:
\t${objHint}

ASSESSMENT:
\t

PLAN:
\t1.
\t2.

${settingLine(setting)}
`;
}

/* ---------- banner ---------- */
function showBanner(msg, kind) {
  const b = $("#banner");
  b.textContent = msg;
  b.className = "banner" + (kind ? " " + kind : "");
  b.hidden = false;
}
function hideBanner() { $("#banner").hidden = true; }
function setConn(ok) {
  const c = $("#conn-status");
  c.className = "conn " + (ok ? "ok" : "err");
  c.title = ok ? "Connected" : "API unreachable";
}

/* ---------- rendering: patient list ---------- */
function renderPatientList() {
  const ul = $("#patient-list");
  ul.innerHTML = "";
  $("#patient-count").textContent = patients.length ? String(patients.length) : "";
  $("#patient-list-empty").hidden = patients.length > 0;

  patients.forEach((p) => {
    const li = el("li", "patient-item");
    li.dataset.id = p.id;
    if (p.id === selectedId) li.classList.add("active");
    li.appendChild(el("div", "pi-name", patientName(p)));
    const bits = [];
    if (p.gender) bits.push(cap(p.gender));
    const dob = fmtDate(p.birthDate);
    if (dob) bits.push(dob);
    li.appendChild(el("div", "pi-sub", bits.join("  •  ") || "—"));
    li.addEventListener("click", () => selectPatient(p.id));
    ul.appendChild(li);
  });
}

/* ---------- rendering: list cards ---------- */
function renderList(containerSel, items, mapper, emptyMsg) {
  const ul = $(containerSel);
  ul.innerHTML = "";
  if (!items.length) {
    ul.appendChild(el("li", "data-empty", emptyMsg));
    return;
  }
  items.forEach((it) => {
    const { main, sub, val } = mapper(it);
    const li = el("li", "data-item");
    const left = el("div");
    left.appendChild(el("div", "di-main", main || "—"));
    if (sub) left.appendChild(el("div", "di-sub", sub));
    li.appendChild(left);
    if (val) li.appendChild(el("div", "di-val", val));
    ul.appendChild(li);
  });
}

function renderChart(patient, conditions, meds, allergies, observations) {
  $("#empty-state").hidden = true;
  $("#chart").hidden = false;

  $("#pt-name").textContent = patientName(patient);

  const meta = $("#pt-meta");
  meta.innerHTML = "";
  const addMeta = (label, value) => {
    if (!value) return;
    const wrap = el("span", "demo-item");
    wrap.appendChild(el("span", "demo-label", label));
    wrap.appendChild(el("span", null, value));
    meta.appendChild(wrap);
  };
  addMeta("Sex", cap(patient?.gender) || "Unknown");
  const dob = fmtDate(patient?.birthDate);
  const age = ageFrom(patient?.birthDate);
  addMeta("DOB", dob ? (age != null ? `${dob} (${age} yr)` : dob) : "Unknown");
  addMeta("MRN", patient?.id || "—");

  // Problem list
  renderList("#list-problems", conditions, (c) => ({
    main: c?.code?.text || c?.code?.coding?.[0]?.display || "Unspecified condition",
    sub: c?.clinicalStatus?.coding?.[0]?.code ? cap(c.clinicalStatus.coding[0].code) : null,
    val: fmtDate(c?.recordedDate) || null,
  }), "No active problems recorded.");
  $("#count-problems").textContent = conditions.length;

  // Medications
  renderList("#list-meds", meds, (m) => ({
    main: m?.medicationCodeableConcept?.text
       || m?.medicationCodeableConcept?.coding?.[0]?.display
       || "Unspecified medication",
    sub: m?.dosageInstruction?.[0]?.text || null,
    val: m?.status ? cap(m.status) : null,
  }), "No medications on file.");
  $("#count-meds").textContent = meds.length;

  // Allergies
  renderList("#list-allergies", allergies, (a) => ({
    main: a?.code?.text || a?.code?.coding?.[0]?.display || "Unspecified allergen",
    sub: a?.reaction?.[0]?.manifestation?.[0]?.text
      || (a?.criticality ? cap(a.criticality) + " criticality" : null),
    val: null,
  }), "No known allergies.");
  $("#count-allergies").textContent = allergies.length;

  // Observations / vitals
  renderList("#list-vitals", observations, (o) => {
    let val = null;
    if (o?.valueQuantity && o.valueQuantity.value != null) {
      val = `${o.valueQuantity.value}${o.valueQuantity.unit ? " " + o.valueQuantity.unit : ""}`;
    } else if (o?.valueString) {
      val = o.valueString;
    }
    return {
      main: o?.code?.text || o?.code?.coding?.[0]?.display || "Observation",
      sub: fmtDate(o?.effectiveDateTime) || null,
      val,
    };
  }, "No observations recorded.");
  $("#count-vitals").textContent = observations.length;
}

/* ---------- loaders ---------- */
async function loadPatients() {
  try {
    const bundle = await apiGet("/Patient");
    patients = entries(bundle);
    setConn(true);
    hideBanner();
    renderPatientList();

    if (patients.length === 0) {
      selectedId = null;
      showEmptyState();
    } else if (!selectedId || !patients.some((p) => p.id === selectedId)) {
      // auto-select first patient for a useful default view
      selectPatient(patients[0].id);
    }
  } catch (err) {
    if (err && err.isAuth) return; // session-expired bounce already handled
    setConn(false);
    showBanner("Could not reach the ChartCraft API. Is the server running? " + err.message, "err");
  }
}

function showEmptyState() {
  $("#chart").hidden = true;
  $("#empty-state").hidden = false;
}

async function selectPatient(id) {
  // Guard unsaved note text BEFORE mutating any state, so a cancel leaves the
  // current patient (and the list highlight) exactly as they were.
  if (noteIsDirty() &&
      !confirm("You have an unsaved note. Switch patients and discard it?")) {
    return;
  }

  selectedId = id;
  // reflect selection in list
  document.querySelectorAll(".patient-item").forEach((li) => {
    li.classList.toggle("active", li.dataset.id === id);
  });

  // Reset per-patient transient panels so patient A's note/superbill
  // never lingers under patient B.
  resetNotePanels();
  closeSuperbill();

  try {
    const q = `?patient=${encodeURIComponent(id)}`;
    const [patient, condB, medB, algB, obsB, docB] = await Promise.all([
      apiGet("/Patient/" + encodeURIComponent(id)),
      apiGet("/Condition" + q).catch(() => null),
      apiGet("/MedicationRequest" + q).catch(() => null),
      apiGet("/AllergyIntolerance" + q).catch(() => null),
      apiGet("/Observation" + q).catch(() => null),
      apiGet("/DocumentReference" + q).catch(() => null),
    ]);
    hideBanner();
    renderChart(patient, entries(condB), entries(medB), entries(algB), entries(obsB));
    renderNotes(entries(docB));
  } catch (err) {
    if (err && err.isAuth) return; // session-expired bounce already handled
    showBanner("Could not load this patient's chart. " + err.message, "err");
  }
}

/* ---------- notes: extraction ---------- */
function noteType(doc) {
  return doc?.type?.text
    || doc?.type?.coding?.[0]?.display
    || "Note";
}
function noteSetting(doc) {
  return doc?.context?.related?.[0]?.display || null;
}
function noteBody(doc) {
  return decodeNote(doc?.content?.[0]?.attachment?.data);
}
function noteAuthor(doc) {
  return doc?.author?.[0]?.display || null;
}

/* ---------- notes: rendering ---------- */
function renderNotes(docs) {
  // most recent first
  const sorted = docs.slice().sort((a, b) => String(b?.date || "").localeCompare(String(a?.date || "")));
  $("#count-notes").textContent = sorted.length;

  const ul = $("#list-notes");
  ul.innerHTML = "";
  if (!sorted.length) {
    ul.appendChild(el("li", "data-empty", "No notes yet. Use “New note” to document a visit."));
    return;
  }
  sorted.forEach((doc) => {
    const li = el("li", "data-item note-item");
    const left = el("div");
    left.appendChild(el("div", "di-main", noteType(doc)));
    const setting = noteSetting(doc);
    if (setting) left.appendChild(el("div", "di-sub", setting));
    li.appendChild(left);
    const when = fmtDateTime(doc?.date);
    if (when) li.appendChild(el("div", "di-val", when));
    li.addEventListener("click", () => openNote(doc));
    ul.appendChild(li);
  });
}

function openNote(doc) {
  const detail = $("#note-detail");
  $("#note-detail-title").textContent = noteType(doc);
  const metaBits = [];
  const setting = noteSetting(doc);
  if (setting) metaBits.push(setting);
  const when = fmtDateTime(doc?.date);
  if (when) metaBits.push(when);
  const author = noteAuthor(doc);
  if (author) metaBits.push(author);
  $("#note-detail-meta").textContent = metaBits.join("  •  ");
  $("#note-detail-body").textContent = noteBody(doc) || "(empty note)";
  detail.hidden = false;
  detail.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function resetNotePanels() {
  const ed = $("#note-editor");
  if (ed) ed.hidden = true;
  // Clear the editor text so patient A's note never lingers in the hidden DOM
  // while patient B is shown (and so noteIsDirty() reads clean after a switch).
  const txt = $("#note-text");
  if (txt) txt.value = "";
  lastSkeleton = "";
  const det = $("#note-detail");
  if (det) det.hidden = true;
  // Clear the opened-note content so patient PHI doesn't linger in the hidden
  // detail panel (devtools-recoverable after a patient switch or logout).
  const dTitle = $("#note-detail-title");
  if (dTitle) dTitle.textContent = "";
  const dMeta = $("#note-detail-meta");
  if (dMeta) dMeta.textContent = "";
  const dBody = $("#note-detail-body");
  if (dBody) dBody.textContent = "";
  const msg = $("#note-save-msg");
  if (msg) msg.textContent = "";
}

/* ---------- notes: editor ---------- */
let lastSkeleton = "";

/* True when the editor is open and holds text the user would lose on a refill
   or a patient switch: visible, non-empty, and no longer the generated skeleton. */
function noteIsDirty() {
  const ed = $("#note-editor");
  if (!ed || ed.hidden) return false;
  const current = $("#note-text").value || "";
  return !!current.trim() && current !== lastSkeleton;
}

function fillSkeleton() {
  const type = $("#note-type").value;
  const setting = $("#note-setting").value;
  lastSkeleton = noteSkeleton(type, setting);
  $("#note-text").value = lastSkeleton;
}

/* Clinics don't admit/discharge, so "Discharge summary" is incoherent for an
   outpatient clinic. Disable that option for the clinic setting (keep all three
   for ICU and SNF); if it was the active choice, fall back to "Progress note". */
function gateNoteTypes() {
  const setting = $("#note-setting").value;
  const typeSel = $("#note-type");
  const dischargeOpt = Array.from(typeSel.options)
    .find((o) => o.value === "Discharge summary");
  if (!dischargeOpt) return;
  const clinic = setting === "Outpatient clinic";
  dischargeOpt.disabled = clinic;
  dischargeOpt.hidden = clinic;
  if (clinic && typeSel.value === "Discharge summary") {
    typeSel.value = "Progress note";
  }
}

function openEditor() {
  $("#note-detail").hidden = true;
  $("#note-save-msg").textContent = "";
  gateNoteTypes();
  fillSkeleton();
  const ed = $("#note-editor");
  ed.hidden = false;
  ed.scrollIntoView({ behavior: "smooth", block: "nearest" });
  $("#note-text").focus();
}

function closeEditor() {
  $("#note-editor").hidden = true;
  $("#note-save-msg").textContent = "";
}

async function saveNote() {
  if (!selectedId) return;
  // Pin the patient this save belongs to. `selectedId` can change mid-await if
  // the user switches charts; everything below must use `pid`, not the global.
  const pid = selectedId;
  const type = $("#note-type").value;
  const setting = $("#note-setting").value;
  const text = $("#note-text").value || "";

  const btn = $("#btn-save-note");
  btn.disabled = true;
  $("#note-save-msg").textContent = "Saving…";

  const body = {
    resourceType: "DocumentReference",
    status: "current",
    type: { text: type },
    subject: { reference: "Patient/" + pid },
    date: new Date().toISOString(),
    author: [{ display: SIGNING_CLINICIAN }],
    content: [{ attachment: { contentType: "text/plain", data: encodeNote(text) } }],
    context: { related: [{ display: setting }] },
  };

  try {
    const saved = await apiPost("DocumentReference", body);
    // The user may have switched patients during the POST — don't render this
    // note under whoever is on screen now.
    if (selectedId !== pid) return;
    closeEditor();
    // refresh the notes list, then show the just-saved note
    const docB = await apiGet("/DocumentReference?patient=" + encodeURIComponent(pid)).catch(() => null);
    if (selectedId !== pid) return;
    renderNotes(entries(docB));
    openNote(saved && saved.resourceType ? saved : body);
  } catch (err) {
    if (err && err.isAuth) return; // session-expired bounce already handled
    $("#note-save-msg").textContent = "Could not save: " + err.message;
  } finally {
    btn.disabled = false;
  }
}

/* ---------- sample patient demo ---------- */
function ref(type, id) { return { reference: `${type}/${id}` }; }

async function loadSamplePatient() {
  const btns = [$("#btn-sample"), $("#btn-sample-empty")];
  btns.forEach((b) => b && (b.disabled = true));
  showBanner("Creating sample patient…", "info");

  try {
    const patientBody = {
      resourceType: "Patient",
      name: [{ use: "official", given: ["Eleanor", "M"], family: "Whitfield" }],
      gender: "female",
      birthDate: "1958-04-12",
    };
    const patient = await apiPost("Patient", patientBody);
    const pid = patient?.id;
    if (!pid) throw new Error("Server did not return a patient id.");

    const subject = ref("Patient", pid);

    const conditions = [
      { resourceType: "Condition", subject, recordedDate: "2016-09-20",
        clinicalStatus: { coding: [{ code: "active" }] },
        code: { text: "Essential hypertension", coding: [{ code: "I10", display: "Essential hypertension" }] } },
      { resourceType: "Condition", subject, recordedDate: "2019-02-11",
        clinicalStatus: { coding: [{ code: "active" }] },
        code: { text: "Type 2 diabetes mellitus", coding: [{ code: "E11.9", display: "Type 2 diabetes mellitus" }] } },
      { resourceType: "Condition", subject, recordedDate: "2021-06-03",
        clinicalStatus: { coding: [{ code: "active" }] },
        code: { text: "Hyperlipidemia", coding: [{ code: "E78.5", display: "Hyperlipidemia" }] } },
    ];

    const meds = [
      { resourceType: "MedicationRequest", status: "active", intent: "order", subject,
        medicationCodeableConcept: { text: "Lisinopril 10 mg tablet" },
        dosageInstruction: [{ text: "1 tablet by mouth once daily" }] },
      { resourceType: "MedicationRequest", status: "active", intent: "order", subject,
        medicationCodeableConcept: { text: "Metformin 500 mg tablet" },
        dosageInstruction: [{ text: "1 tablet by mouth twice daily with meals" }] },
      { resourceType: "MedicationRequest", status: "active", intent: "order", subject,
        medicationCodeableConcept: { text: "Atorvastatin 20 mg tablet" },
        dosageInstruction: [{ text: "1 tablet by mouth at bedtime" }] },
    ];

    const allergies = [
      { resourceType: "AllergyIntolerance", patient: subject, criticality: "high",
        code: { text: "Penicillin" },
        reaction: [{ manifestation: [{ text: "Hives" }] }] },
      { resourceType: "AllergyIntolerance", patient: subject, criticality: "low",
        code: { text: "Sulfa drugs" },
        reaction: [{ manifestation: [{ text: "Rash" }] }] },
    ];

    const observations = [
      { resourceType: "Observation", status: "final", subject, effectiveDateTime: "2026-11-10",
        code: { text: "Blood pressure (systolic)" }, valueQuantity: { value: 138, unit: "mmHg" } },
      { resourceType: "Observation", status: "final", subject, effectiveDateTime: "2026-11-10",
        code: { text: "Heart rate" }, valueQuantity: { value: 72, unit: "bpm" } },
      { resourceType: "Observation", status: "final", subject, effectiveDateTime: "2026-11-10",
        code: { text: "Hemoglobin A1c" }, valueQuantity: { value: 7.1, unit: "%" } },
    ];

    // Post children sequentially so the demo chart reads in a stable, clinical order.
    // Tolerate unimplemented endpoints without aborting the whole demo.
    const post = (type, body) => apiPost(type, body).catch((e) => {
      console.warn(`Skipping ${type}:`, e.message);
      return null;
    });

    const children = [
      ...conditions.map((c) => ["Condition", c]),
      ...meds.map((m) => ["MedicationRequest", m]),
      ...allergies.map((a) => ["AllergyIntolerance", a]),
      ...observations.map((o) => ["Observation", o]),
    ];
    for (const [type, body] of children) {
      await post(type, body);
    }

    await loadPatients();
    selectedId = pid;
    await selectPatient(pid);
    hideBanner();
  } catch (err) {
    if (!(err && err.isAuth)) { // session-expired bounce already handled
      showBanner("Could not create the sample patient. " + err.message, "err");
    }
  } finally {
    btns.forEach((b) => b && (b.disabled = false));
  }
}

/* ---------- superbill ---------- */
function closeSuperbill() {
  const sb = $("#superbill");
  if (sb) sb.hidden = true;
  // Wipe the rendered superbill (patient name/DOB/dx) from the DOM, not just hide it.
  const sheet = $("#superbill-sheet");
  if (sheet) sheet.innerHTML = "";
  document.body.classList.remove("printing-superbill");
}

function renderSuperbillError(msg) {
  const sheet = $("#superbill-sheet");
  sheet.innerHTML = "";
  const box = el("div", "superbill-error", msg);
  sheet.appendChild(box);
  // hide the Print button when there's nothing to print
  $("#btn-print-superbill").hidden = true;
}

function renderSuperbill(data) {
  const sheet = $("#superbill-sheet");
  sheet.innerHTML = "";
  $("#btn-print-superbill").hidden = false;

  const pt = data?.patient || {};
  const name = pt.name || "Unknown patient";
  const dob = fmtDate(pt.birthDate);

  // Header
  const head = el("div", "sb-head");
  head.appendChild(el("div", "sb-brand", "ChartCraft"));
  head.appendChild(el("div", "sb-doc-title", "Superbill / Statement of Services"));
  sheet.appendChild(head);

  const idRow = el("div", "sb-idrow");
  const mkField = (label, value) => {
    const f = el("div", "sb-field");
    f.appendChild(el("span", "sb-field-label", label));
    f.appendChild(el("span", "sb-field-val", value || "—"));
    return f;
  };
  idRow.appendChild(mkField("Patient", name));
  idRow.appendChild(mkField("Date of birth", dob || "—"));
  idRow.appendChild(mkField("Patient ID", pt.id || "—"));
  idRow.appendChild(mkField("Generated", fmtDate(data?.date) || data?.date || "—"));
  sheet.appendChild(idRow);

  // Diagnoses
  const dxSection = el("div", "sb-section");
  dxSection.appendChild(el("div", "sb-section-title", "Diagnoses"));
  const dxList = el("ul", "sb-dx-list");
  const diagnoses = Array.isArray(data?.diagnoses) ? data.diagnoses : [];
  if (!diagnoses.length) {
    dxList.appendChild(el("li", "sb-dx-empty", "No diagnoses recorded."));
  } else {
    diagnoses.forEach((d) => {
      dxList.appendChild(el("li", null, d?.text || "Unspecified diagnosis"));
    });
  }
  dxSection.appendChild(dxList);
  sheet.appendChild(dxSection);

  // Charge
  const chSection = el("div", "sb-section");
  chSection.appendChild(el("div", "sb-section-title", "Charge"));
  // Honesty banner: this is a placeholder E/M code, never a real billable charge.
  // Border + bold text (not a background fill) so it survives print color-stripping.
  chSection.appendChild(
    el("div", "sb-charge-badge", "SAMPLE CHARGE — NOT FOR CLAIM SUBMISSION")
  );
  const charge = data?.charge || {};
  const chargeRow = el("div", "sb-charge");
  const cpt = el("div", "sb-cpt");
  cpt.appendChild(el("span", "sb-cpt-label", "CPT"));
  cpt.appendChild(el("span", "sb-cpt-code", charge.cpt || "—"));
  chargeRow.appendChild(cpt);
  chargeRow.appendChild(el("div", "sb-charge-desc", charge.description || "—"));
  chSection.appendChild(chargeRow);
  sheet.appendChild(chSection);

  // Explanatory note
  if (data?.note) {
    const noteSection = el("div", "sb-section sb-note");
    noteSection.appendChild(el("div", "sb-section-title", "Note"));
    noteSection.appendChild(el("div", "sb-note-body", data.note));
    sheet.appendChild(noteSection);
  }
}

async function generateSuperbill() {
  if (!selectedId) return;
  const sb = $("#superbill");
  sb.hidden = false;
  $("#superbill-sheet").innerHTML = "";
  $("#btn-print-superbill").hidden = true;
  const loading = el("div", "superbill-loading", "Generating superbill…");
  $("#superbill-sheet").appendChild(loading);
  sb.scrollIntoView({ behavior: "smooth", block: "start" });

  try {
    // append $superbill raw — encodeURIComponent would turn $ into %24
    const data = await apiGet("/Patient/" + encodeURIComponent(selectedId) + "/$superbill");
    renderSuperbill(data);
  } catch (err) {
    if (err && err.isAuth) { closeSuperbill(); return; } // bounced to login
    const notFound = /→\s*404/.test(err.message);
    renderSuperbillError(
      notFound
        ? "This patient could not be found; the chart may have been removed. Reload the patient list and try again."
        : "Could not generate the superbill. " + err.message
    );
  }
}

function printSuperbill() {
  document.body.classList.add("printing-superbill");
  window.print();
  // cleanup after the print dialog closes
  setTimeout(() => document.body.classList.remove("printing-superbill"), 0);
}

/* ---------- auth / login gate ---------- */
let currentUser = null;

/* Dedicated fetch for /auth/* — unlike apiGet/apiPost, a 401 here is expected
   (logged-out on load, or bad credentials) and must NOT trigger the
   session-expired bounce. Returns the raw Response so callers can branch on
   status (204 logout has no JSON body). */
function authFetch(path, body) {
  const opts = {
    credentials: "same-origin",
    headers: { Accept: "application/json" },
  };
  if (body !== undefined) {
    opts.method = "POST";
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  return fetch(API + path, opts);
}

function showLoginMsg(msg, kind) {
  const m = $("#login-msg");
  if (!m) return;
  m.textContent = msg || "";
  m.className = "login-msg" + (kind ? " " + kind : "");
  m.hidden = !msg;
}

/* Tear down all in-memory + on-screen PHI so one session's chart never lingers
   under the next state. Shared by the login bounce AND the enrollment bounce
   (a 403 routes a pending session here from a loaded chart). */
function clearPatientState() {
  currentUser = null;
  patients = [];
  selectedId = null;

  // Clear the patient list + per-patient panels.
  const ul = $("#patient-list");
  if (ul) ul.innerHTML = "";
  const pc = $("#patient-count");
  if (pc) pc.textContent = "";
  // Wipe the chart's PHI from the DOM (not just hide it) so it isn't
  // devtools-recoverable on a shared workstation after logout / session-expiry.
  const ptName = $("#pt-name");
  if (ptName) ptName.textContent = "";
  const ptMeta = $("#pt-meta");
  if (ptMeta) ptMeta.textContent = "";
  ["#list-problems", "#list-meds", "#list-allergies", "#list-vitals", "#list-notes"]
    .forEach((sel) => { const n = $(sel); if (n) n.innerHTML = ""; });
  ["#count-problems", "#count-meds", "#count-allergies", "#count-vitals", "#count-notes"]
    .forEach((sel) => { const n = $(sel); if (n) n.textContent = "0"; });
  resetNotePanels();
  closeSuperbill();
  const chart = $("#chart");
  if (chart) chart.hidden = true;
  const empty = $("#empty-state");
  if (empty) empty.hidden = false;
  hideBanner();

  // Header: hide user chrome.
  $("#user-name").hidden = true;
  $("#user-name").textContent = "";
  $("#btn-logout").hidden = true;
  $("#btn-sample").hidden = true;

  $("#app-layout").hidden = true;
}

/* Swap to the login screen and tear down any in-memory patient state so one
   session's chart never lingers under the next sign-in. */
function showLogin(message, kind) {
  clearPatientState();
  hideMfaScreen();

  // Show the login card; reset to the sign-in form.
  $("#login-screen").hidden = false;
  showRegister(false);
  // Clear identity + password + code fields so the prior clinician's
  // username/display name doesn't linger on the login card for the next person.
  ["#login-username", "#register-username", "#register-displayname",
   "#login-password", "#register-password", "#login-totp"]
    .forEach((sel) => { const f = $(sel); if (f) f.value = ""; });
  showLoginMsg(message, kind || "info");
}

/* ---------- MFA enrollment screen ---------- */
/* A session that is authenticated-but-pending (password done, TOTP not yet
   enrolled) can only reach the enroll/confirm endpoints — not the chart. */
let mfaEnrolling = false; // in-flight guard so parallel 403s don't re-POST enroll

function showMfaMsg(msg, kind) {
  const m = $("#mfa-msg");
  if (!m) return;
  m.textContent = msg || "";
  m.className = "login-msg" + (kind ? " " + kind : "");
  m.hidden = !msg;
}

/* Blank the QR + secret so this credential doesn't linger in the DOM once we
   leave the screen (same rationale as the PHI wipes). */
function hideMfaScreen() {
  const qr = $("#mfa-qr");
  if (qr) qr.removeAttribute("src");
  const secret = $("#mfa-secret");
  if (secret) secret.textContent = "";
  const code = $("#mfa-code");
  if (code) code.value = "";
  showMfaMsg("", null);
  const scr = $("#mfa-screen");
  if (scr) scr.hidden = true;
}

/* Route a pending session to the enrollment screen and fetch its QR/secret.
   Wipes any loaded chart first (the 403 path arrives from a live chart). */
async function showEnroll(user) {
  // Already on the enroll screen with a QR in flight/shown → don't re-enter
  // (selectPatient fires six parallel fetches; six 403s must not mean six
  // enroll POSTs, each rotating the secret and invalidating the shown QR).
  const scr = $("#mfa-screen");
  if (scr && !scr.hidden) return;

  const pendingUser = user || currentUser || null;
  clearPatientState();           // wipe PHI + hide the app
  $("#login-screen").hidden = true;
  currentUser = pendingUser;     // keep identity for the confirm → showApp merge

  if (scr) scr.hidden = false;
  const qr = $("#mfa-qr");
  if (qr) qr.removeAttribute("src");
  const secret = $("#mfa-secret");
  if (secret) secret.textContent = "";
  $("#mfa-code").value = "";

  if (mfaEnrolling) return;
  mfaEnrolling = true;
  showMfaMsg("Preparing your setup code…", "info");
  try {
    const res = await authFetch("/auth/totp/enroll", {});
    if (res.status === 401) { showLogin("Your session ended, please sign in again.", "info"); return; }
    if (!res.ok) {
      showMfaMsg("Could not start setup (error " + res.status + "). Reload and try again.", "err");
      return;
    }
    const data = await res.json().catch(() => null);
    if (!data) { showMfaMsg("Could not read the setup code. Reload and try again.", "err"); return; }
    if (qr && data.qrPngBase64) qr.src = "data:image/png;base64," + data.qrPngBase64;
    if (secret) secret.textContent = data.secret || "";
    showMfaMsg("", null);
    $("#mfa-code").focus();
  } catch (err) {
    showMfaMsg("Could not reach the server. Is it running?", "err");
  } finally {
    mfaEnrolling = false;
  }
}

/* Called from apiGet/apiPost on a 403 — a pending session hit a PHI route.
   Shouldn't happen if the gate is right, but route to enrollment defensively. */
function handlePendingSession() {
  const scr = $("#mfa-screen");
  if (scr && !scr.hidden) return; // already enrolling
  showEnroll(currentUser);
}

async function confirmMfa(e) {
  if (e) e.preventDefault();
  const code = ($("#mfa-code").value || "").replace(/\s+/g, "");
  if (!code) { showMfaMsg("Enter the 6-digit code from your authenticator app.", "err"); return; }
  const btn = $("#btn-mfa-confirm");
  btn.disabled = true;
  showMfaMsg("Verifying…", "info");
  try {
    const res = await authFetch("/auth/totp/confirm", { code });
    if (res.status === 400) {
      $("#mfa-code").value = "";
      showMfaMsg("That code didn't match, try the current one.", "err");
      return;
    }
    if (res.status === 401) { showLogin("Your session ended, please sign in again.", "info"); return; }
    if (!res.ok) { showMfaMsg("Could not verify (error " + res.status + "). Try again.", "err"); return; }
    // 200 → fully authenticated. Merge rather than re-hit /auth/me.
    const confirmed = await res.json().catch(() => null);
    const user = Object.assign({}, currentUser, confirmed,
      { mfaEnrolled: true, authLevel: "full" });
    hideMfaScreen();
    showApp(user);
  } catch (err) {
    showMfaMsg("Could not reach the server. Is it running?", "err");
  } finally {
    btn.disabled = false;
  }
}

/* Route to the right screen for a freshly-authenticated user: a pending session
   (or one without MFA enrolled) must enroll before reaching the chart. */
function routeUser(user) {
  if (user && user.authLevel === "full" && user.mfaEnrolled !== false) {
    showApp(user);
  } else {
    showEnroll(user);
  }
}

/* Enter the app for an authenticated user. */
function showApp(user) {
  currentUser = user || null;
  $("#login-screen").hidden = true;
  $("#mfa-screen").hidden = true;
  $("#app-layout").hidden = false;

  const un = $("#user-name");
  un.textContent = (user && user.displayName) || (user && user.username) || "Signed in";
  un.hidden = false;
  $("#btn-logout").hidden = false;
  $("#btn-sample").hidden = false;

  showLoginMsg("", null);
  loadPatients();
}

/* Called from apiGet/apiPost on a 401 — the session ended mid-use. */
function handleSessionExpired() {
  // Only bounce once; if we're already on the login screen, do nothing.
  if ($("#login-screen") && !$("#login-screen").hidden) return;
  showLogin("Your session ended, please sign in again.", "info");
}

function showRegister(on) {
  const login = $("#login-form");
  const reg = $("#register-form");
  if (!login || !reg) return;
  login.hidden = !!on;
  reg.hidden = !on;
}

async function doLogin(e) {
  if (e) e.preventDefault();
  const username = ($("#login-username").value || "").trim();
  const password = $("#login-password").value || "";
  const totp = ($("#login-totp").value || "").replace(/\s+/g, "");
  if (!username || !password) {
    showLoginMsg("Please enter a username and password.", "err");
    return;
  }
  const btn = $("#btn-login");
  btn.disabled = true;
  showLoginMsg("Signing in…", "info");
  try {
    const res = await authFetch("/auth/login", { username, password, totp });
    if (res.status === 401) {
      // The client can't tell whether this account requires a code, so keep the
      // message generic — don't reveal which factor failed.
      $("#login-password").value = "";
      $("#login-totp").value = "";
      showLoginMsg("Invalid credentials or code.", "err");
      return;
    }
    if (!res.ok) {
      showLoginMsg("Could not sign in (error " + res.status + "). Please try again.", "err");
      return;
    }
    const user = await res.json().catch(() => null);
    routeUser(user);
  } catch (err) {
    showLoginMsg("Could not reach the server. Is it running?", "err");
  } finally {
    btn.disabled = false;
  }
}

async function doRegister(e) {
  if (e) e.preventDefault();
  const username = ($("#register-username").value || "").trim();
  const password = $("#register-password").value || "";
  const displayName = ($("#register-displayname").value || "").trim();
  if (!username || !password || !displayName) {
    showLoginMsg("Please fill in every field.", "err");
    return;
  }
  const btn = $("#btn-register");
  btn.disabled = true;
  showLoginMsg("Creating account…", "info");
  try {
    const res = await authFetch("/auth/register", { username, password, displayName });
    if (res.status === 403) {
      // An account already exists — fall back to sign-in.
      showRegister(false);
      $("#login-username").value = username;
      $("#login-password").value = "";
      showLoginMsg("An account already exists — please sign in.", "err");
      return;
    }
    if (!res.ok && res.status !== 201) {
      showLoginMsg("Could not create the account (error " + res.status + ").", "err");
      return;
    }
    const user = await res.json().catch(() => null);
    // A fresh account is authLevel:"pending" — routeUser sends it to enrollment.
    routeUser(user);
  } catch (err) {
    showLoginMsg("Could not reach the server. Is it running?", "err");
  } finally {
    btn.disabled = false;
  }
}

async function doLogout() {
  const btn = $("#btn-logout");
  btn.disabled = true;
  try {
    await authFetch("/auth/logout", {}).catch(() => null);
  } finally {
    btn.disabled = false;
    showLogin("You've been signed out.", "info");
  }
}

/* On load: probe the session and gate the app accordingly. */
async function checkAuth() {
  try {
    const res = await authFetch("/auth/me");
    if (res.ok) {
      const user = await res.json().catch(() => null);
      routeUser(user);
    } else {
      // 401 (or anything non-OK) → show the login screen.
      showLogin("", null);
    }
  } catch (err) {
    showLogin("Could not reach the server. Is it running?", "err");
  }
}

/* ---------- init ---------- */
function init() {
  $("#btn-sample").addEventListener("click", loadSamplePatient);
  $("#btn-sample-empty").addEventListener("click", loadSamplePatient);

  // Notes
  $("#btn-new-note").addEventListener("click", openEditor);
  $("#btn-cancel-note").addEventListener("click", closeEditor);
  $("#btn-save-note").addEventListener("click", saveNote);
  $("#btn-regen-skeleton").addEventListener("click", fillSkeleton);
  $("#btn-close-note").addEventListener("click", () => { $("#note-detail").hidden = true; });
  // re-fill skeleton on type/setting change, but don't silently clobber edits
  const maybeRefill = () => {
    // Unedited (still the last-generated skeleton) or empty → refill freely.
    if (!noteIsDirty()) {
      fillSkeleton();
      return;
    }
    if (confirm("Replace the current note text with a fresh skeleton for this type and setting? Your edits will be lost.")) {
      fillSkeleton();
    }
  };
  $("#note-type").addEventListener("change", maybeRefill);
  // Gate the type options for the new setting BEFORE refilling, so a forced
  // fallback (e.g. Discharge → Progress on switching to clinic) regenerates the
  // correct skeleton.
  $("#note-setting").addEventListener("change", () => {
    gateNoteTypes();
    maybeRefill();
  });

  // Superbill
  $("#btn-superbill").addEventListener("click", generateSuperbill);
  $("#btn-print-superbill").addEventListener("click", printSuperbill);
  $("#btn-close-superbill").addEventListener("click", closeSuperbill);

  // Auth
  $("#login-form").addEventListener("submit", doLogin);
  $("#register-form").addEventListener("submit", doRegister);
  $("#link-show-register").addEventListener("click", () => { showLoginMsg("", null); showRegister(true); });
  $("#link-show-login").addEventListener("click", () => { showLoginMsg("", null); showRegister(false); });
  $("#btn-logout").addEventListener("click", doLogout);

  // MFA enrollment
  $("#mfa-form").addEventListener("submit", confirmMfa);
  $("#btn-mfa-logout").addEventListener("click", doLogout);

  // Gate the app on the session before loading any patient data.
  checkAuth();
}

document.addEventListener("DOMContentLoaded", init);
