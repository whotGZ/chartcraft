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
async function apiGet(path) {
  const res = await fetch(API + path, { headers: { Accept: "application/json" } });
  if (!res.ok) throw new Error(`GET ${path} → ${res.status}`);
  return res.json();
}

async function apiPost(type, resource) {
  const res = await fetch(API + "/" + type, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(resource),
  });
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
    setConn(false);
    showBanner("Could not reach the ChartCraft API. Is the server running? " + err.message, "err");
  }
}

function showEmptyState() {
  $("#chart").hidden = true;
  $("#empty-state").hidden = false;
}

async function selectPatient(id) {
  selectedId = id;
  // reflect selection in list
  document.querySelectorAll(".patient-item").forEach((li) => {
    li.classList.toggle("active", li.dataset.id === id);
  });

  try {
    const q = `?patient=${encodeURIComponent(id)}`;
    const [patient, condB, medB, algB, obsB] = await Promise.all([
      apiGet("/Patient/" + encodeURIComponent(id)),
      apiGet("/Condition" + q).catch(() => null),
      apiGet("/MedicationRequest" + q).catch(() => null),
      apiGet("/AllergyIntolerance" + q).catch(() => null),
      apiGet("/Observation" + q).catch(() => null),
    ]);
    hideBanner();
    renderChart(patient, entries(condB), entries(medB), entries(algB), entries(obsB));
  } catch (err) {
    showBanner("Could not load this patient's chart. " + err.message, "err");
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
    showBanner("Could not create the sample patient. " + err.message, "err");
  } finally {
    btns.forEach((b) => b && (b.disabled = false));
  }
}

/* ---------- init ---------- */
function init() {
  $("#btn-sample").addEventListener("click", loadSamplePatient);
  $("#btn-sample-empty").addEventListener("click", loadSamplePatient);
  loadPatients();
}

document.addEventListener("DOMContentLoaded", init);
