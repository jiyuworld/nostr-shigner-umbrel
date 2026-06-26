"use strict";
const CSRF = document.querySelector('meta[name="csrf-token"]').content;
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
const el = (t, c, text) => {
  const e = document.createElement(t);
  if (c) e.className = c;
  // textContent (not innerHTML): values like client-chosen name/source/perms
  // are untrusted and must never be parsed as HTML. No caller passes markup.
  if (text != null) e.textContent = text;
  return e;
};

async function api(path) {
  const r = await fetch(path, { headers: { Accept: "application/json" } });
  if (r.status === 401) {
    onAuthLost();
    throw new Error("authentication required");
  }
  if (!r.ok)
    throw new Error((await r.json().catch(() => ({}))).error || r.statusText);
  return r.json();
}
async function post(path, body) {
  const r = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-CSRF-Token": CSRF },
    body: JSON.stringify(body || {}),
  });
  const data = await r.json().catch(() => ({}));
  if (r.status === 401 && !path.startsWith("/api/auth/")) {
    onAuthLost();
    throw new Error(data.error || "authentication required");
  }
  if (!r.ok) throw new Error(data.error || r.statusText);
  return data;
}

function currentTheme() {
  return document.documentElement.dataset.theme || "dark";
}
function applyTheme(t) {
  document.documentElement.dataset.theme = t;
  try {
    localStorage.setItem("nostr-shigner-theme", t);
  } catch (e) {}
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.content = t === "light" ? "#f3f4f7" : "#0e1014";
  $("#themeBtn").textContent = t === "light" ? "🌙" : "☀️";
  $$("#themeSeg button").forEach((b) =>
    b.classList.toggle("on", b.dataset.themeSet === t),
  );
}
$("#themeBtn").onclick = () =>
  applyTheme(currentTheme() === "light" ? "dark" : "light");
$$("#themeSeg button").forEach(
  (b) => (b.onclick = () => applyTheme(b.dataset.themeSet)),
);
applyTheme(currentTheme());

function goTab(name) {
  $$(".tab-panel").forEach((p) =>
    p.classList.toggle("active", p.dataset.tab === name),
  );
  $$(".tabbtn").forEach((b) => {
    const on = b.dataset.go === name;
    b.classList.toggle("active", on);
    b.setAttribute("aria-selected", on ? "true" : "false");
  });
  window.scrollTo(0, 0);
  renderWarn();
}
$$(".tabbtn").forEach((b) => (b.onclick = () => goTab(b.dataset.go)));

let toastT;
function toast(msg, kind) {
  const t = $("#toast");
  t.textContent = msg;
  t.className = "toast show " + (kind || "");
  clearTimeout(toastT);
  toastT = setTimeout(() => {
    t.className = "toast " + (kind || "");
  }, 3200);
}

let modalOnClose = null;
function modal({ title, bodyNodes, actions, onClose }) {
  const back = $("#modalBack");
  modalOnClose = onClose || null;
  $("#modalTitle").textContent = title;
  const body = $("#modalBody");
  body.innerHTML = "";
  (bodyNodes || []).forEach((n) => body.appendChild(n));
  const act = $("#modalActions");
  act.innerHTML = "";
  actions.forEach((a) => {
    const b = el("button", "btn " + (a.cls || ""), a.label);
    b.onclick = () => a.onClick(closeModal);
    act.appendChild(b);
  });
  back.hidden = false;
  const first = body.querySelector("input");
  if (first) first.focus();
}
function closeModal() {
  $("#modalBack").hidden = true;
  const cb = modalOnClose;
  modalOnClose = null;
  if (cb)
    try {
      cb();
    } catch (e) {}
}
$("#modalBack").addEventListener("click", (e) => {
  if (e.target === $("#modalBack")) closeModal();
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") closeModal();
});

function pwInput(ph) {
  const i = el("input", "input mono");
  i.type = "password";
  i.placeholder = ph || "password";
  i.autocomplete = "off";
  return i;
}
function para(txt) {
  return Object.assign(document.createElement("p"), { textContent: txt });
}

// permsSummary mirrors the backend summary: a short human-readable line of the
// currently granted permissions for a client.
function permsSummary(p) {
  if (!p) return "all allowed";
  const on = [];
  if (p.get_public_key) on.push("pubkey");
  if (p.sign_event)
    on.push(
      p.sign_event_kinds && p.sign_event_kinds.length
        ? "sign (kind " + p.sign_event_kinds.join(",") + ")"
        : "sign",
    );
  if (p.nip04_encrypt || p.nip04_decrypt) on.push("nip04");
  if (p.nip44_encrypt || p.nip44_decrypt) on.push("nip44");
  if (p.get_relays) on.push("relays");
  return on.length ? on.join(" · ") : "none";
}

let state = {};
function setSeal(kind, label, sub) {
  $("#seal").className = "seal seal--" + kind;
  $("#stateLabel").textContent = label;
  $("#stateSub").textContent = sub || "";
}

const warnings = Object.create(null);

function setWarn(tab, html) {
  if (html) warnings[tab] = html;
  else delete warnings[tab];
  renderWarn();
}

function renderWarn() {
  const box = $("#warnBox");
  if (!box) return;
  const active = $(".tab-panel.active");
  const msg = active ? warnings[active.dataset.tab] : null;
  box.textContent = msg || "";
  box.hidden = !msg;
}

async function refresh() {
  let s;
  try {
    s = await api("/api/status");
  } catch (e) {
    setSeal("unknown", "disconnected", "no response from server");
    return;
  }
  state = s;

  if (!s.hasKey) setSeal("nokey", "no key");
  else if (s.running) setSeal("armed", "running", "(pid " + s.pid + ")");
  else setSeal("locked", "off", "key: ■ saved · daemon: □ stopped");

  const npub = $("#npub");
  const npubRow = $("#npubRow");
  if (s.npub) {
    npubRow.hidden = false;
    npub.textContent = s.npub;
  } else npubRow.hidden = true;

  setWarn(
    "status",
    !s.hasKey
      ? "no private key saved."
      : s.relayCount === 0
        ? "no relays."
        : null,
  );
  setWarn("key", !s.hasKey ? "add a private key." : null);
  setWarn("relays", s.relayCount === 0 ? "add a relay." : null);

  setWarn("clients", s.clientsCount === 0 ? "no connected clients." : null);

  renderArm(s);
  $("#cardNc").hidden = !s.running;
  $("#cardBunker").hidden = !(s.running && s.hasUri);
  if (!$("#cardBunker").hidden) loadBunker();

  $("#clientCount").textContent = s.clientsCount;
  $("#navClients").hidden = !(s.clientsCount > 0);
  $("#persistToggle").checked = !!s.persistSecret;

  renderKey(s);
  renderRelays(s.relays || [], s.relayDial || {});
  renderClients();
  if ($("#logDetails").open) loadLog();
}

function renderArm(s) {
  const hint = $("#armHint"),
    box = $("#armControls");
  box.innerHTML = "";
  if (s.running) {
    hint.textContent = "responds to signing requests from connected clients.";
    const btn = el("button", "btn btn--danger btn--block", "stop daemon");
    btn.onclick = stopDaemon;
    box.appendChild(btn);
    return;
  }
  hint.textContent = "";
  const btn = el("button", "btn btn--green btn--block", "start daemon");
  btn.disabled = !s.hasKey || s.relayCount === 0;
  btn.onclick = startDaemonFlow;
  box.appendChild(btn);
}

function startDaemonFlow() {
  const pw = pwInput("ncryptsec password");
  modal({
    title: "start daemon",
    bodyNodes: [pw],
    actions: [
      { label: "cancel", cls: "btn--ghost", onClick: (c) => c() },
      {
        label: "start",
        cls: "btn--green",
        onClick: async (c) => {
          if (!pw.value) {
            toast("enter your password", "err");
            return;
          }
          c();
          toast("starting…");
          try {
            await post("/api/daemon/start", { password: pw.value });
            toast("daemon started", "ok");
          } catch (e) {
            toast(e.message, "err");
          } finally {
            pw.value = "";
            refresh();
          }
        },
      },
    ],
  });
  pw.addEventListener("keydown", (e) => {
    if (e.key === "Enter") $("#modalActions").lastChild.click();
  });
}

function stopDaemon() {
  modal({
    title: "stop signer",
    bodyNodes: [
      para(
        "if you stop the daemon, it will no longer respond to signing requests from connected clients.",
      ),
    ],
    actions: [
      { label: "cancel", cls: "btn--ghost", onClick: (c) => c() },
      {
        label: "stop",
        cls: "btn--danger",
        onClick: async (c) => {
          c();
          try {
            await post("/api/daemon/stop");
            toast("stopped", "ok");
          } catch (e) {
            toast(e.message, "err");
          }
          refresh();
        },
      },
    ],
  });
}

async function loadBunker() {
  try {
    const b = await api("/api/bunker");
    $("#qrWrap").innerHTML = b.svg || "";
    $("#bunkerUri").textContent = b.uri;
  } catch (e) {}
}

function renderKey(s) {
  const box = $("#keyBody");
  box.innerHTML = "";
  if (!s.hasKey) {
    box.append(
      el(
        "p",
        "card__hint",
        "· the plaintext nsec is never written to disk.<br/>· only the ncryptsec encrypted with your password (nip-49) is stored.",
      ),
    );
    const row = el("div", "btnrow");
    const gen = el("button", "btn", "generate new key");
    gen.onclick = () => keyAddFlow(false);
    const imp = el("button", "btn btn--ghost", "import existing key");
    imp.onclick = () => keyAddFlow(true);
    row.append(gen, imp);
    box.append(row);
    return;
  }
  box.append(el("p", "card__hint"));
  const row = el("div", "btnrow");
  const reveal = el("button", "btn btn--ghost", "view backup (ncryptsec)");
  reveal.onclick = revealFlow;
  const replace = el("button", "btn btn--ghost", "replace key");
  replace.onclick = () => keyAddFlow("replace");
  const del = el("button", "btn btn--danger", "delete key");
  del.onclick = deleteKeyFlow;
  if (s.running) {
    replace.disabled = true;
    del.disabled = true;
  }
  row.append(reveal, replace, del);
  box.append(row);
  if (s.running)
    box.append(
      el(
        "p",
        "card__hint",
        "stop the daemon first to replace or delete the key.",
      ),
    );
}

function keyAddFlow(mode) {
  const replace = mode === "replace";
  let pick = mode === true ? "import" : "gen";
  const seg = el("div", "seg");
  const bGen = el("button", "", "generate");
  const bImp = el("button", "", "import");
  const secret = el("input", "input mono");
  secret.placeholder = "nsec1… / ncryptsec1… / 64-char hex";
  secret.autocomplete = "off";
  secret.spellcheck = false;
  const pw = pwInput("enter password");
  const fields = el("div");

  function render() {
    bGen.classList.toggle("on", pick === "gen");
    bImp.classList.toggle("on", pick === "import");
    fields.innerHTML = "";
    if (pick === "import") fields.append(secret);
    fields.append(pw);
    const note = el(
      "small",
      "",
      pick === "import"
        ? "if you paste an ncryptsec it's only verified with that password. if you paste an nsec/hex it's re-encrypted with this password."
        : "generates a new key, then encrypts and stores it with this password.",
    );
    note.style.color = "var(--muted)";
    fields.append(note);
    const f = fields.querySelector("input");
    if (f) f.focus();
  }
  bGen.onclick = () => {
    pick = "gen";
    render();
  };
  bImp.onclick = () => {
    pick = "import";
    render();
  };
  seg.append(bGen, bImp);

  const body = [];
  if (replace) body.push(seg);
  body.push(fields);
  render();

  modal({
    title: replace
      ? "replace key"
      : pick === "import"
        ? "import existing key"
        : "generate new key",
    bodyNodes: body,
    actions: [
      { label: "cancel", cls: "btn--ghost", onClick: (c) => c() },
      {
        label: "save",
        onClick: async (c) => {
          if (!pw.value) {
            toast("enter your password", "err");
            return;
          }
          try {
            if (pick === "import") {
              if (!secret.value.trim()) {
                toast("enter a key", "err");
                return;
              }
              await post("/api/key/import", {
                secret: secret.value.trim(),
                password: pw.value,
                replace,
              });
            } else {
              await post("/api/key/generate", { password: pw.value, replace });
            }
            c();
            toast("key saved", "ok");
          } catch (e) {
            toast(e.message, "err");
          } finally {
            pw.value = "";
            secret.value = "";
            refresh();
          }
        },
      },
    ],
  });
}

function revealFlow() {
  const pw = pwInput("ncryptsec password");
  modal({
    title: "view backup",
    bodyNodes: [pw],
    actions: [
      { label: "cancel", cls: "btn--ghost", onClick: (c) => c() },
      {
        label: "show",
        onClick: async (c) => {
          try {
            const r = await post("/api/key/reveal", { password: pw.value });
            const code = el("code", "mono uri");
            code.textContent = r.ncryptsec;
            code.style.display = "block";
            const copy = el(
              "button",
              "btn btn--ghost btn--block",
              "copy to clipboard",
            );
            copy.onclick = () =>
              copyText(r.ncryptsec).then((ok) =>
                toast(ok ? "copied" : "copy failed", ok ? "ok" : "err"),
              );
            modal({
              title: "backup (ncryptsec)",
              bodyNodes: [code, copy],
              actions: [
                { label: "close", cls: "btn--ghost", onClick: (c2) => c2() },
              ],
            });
          } catch (e) {
            toast(e.message, "err");
          } finally {
            pw.value = "";
          }
        },
      },
    ],
  });
}

function deleteKeyFlow() {
  modal({
    title: "delete key",
    bodyNodes: [
      para(
        "the stored key (ncryptsec) will be permanently deleted. without a backup it cannot be recovered.",
      ),
    ],
    actions: [
      { label: "cancel", cls: "btn--ghost", onClick: (c) => c() },
      {
        label: "delete",
        cls: "btn--danger",
        onClick: async (c) => {
          try {
            await post("/api/key/delete", { confirm: true });
            c();
            toast("deleted", "ok");
          } catch (e) {
            toast(e.message, "err");
          }
          refresh();
        },
      },
    ],
  });
}

function renderRelays(relays, dialMap = {}) {
  const list = $("#relayList");
  list.innerHTML = "";
  if (!relays.length) {
    list.append(el("div", "empty", "no relays."));
    return;
  }
  relays.forEach((r) => {
    const row = el("div", "row");
    const m = el("div", "row__main");
    m.append(el("div", "row__name mono", r));
    // If this relay is advertised but dialed at an internal address, show it.
    let host = r;
    try {
      host = new URL(r).host.toLowerCase();
    } catch {}
    const internal = dialMap[host];
    if (internal) {
      m.append(el("div", "row__sub mono", `↳ dials ${internal}`));
    }
    const x = el("button", "row__x", "delete");
    x.onclick = async () => {
      try {
        await post("/api/relays/remove", { relay: r });
        refresh();
      } catch (e) {
        toast(e.message, "err");
      }
    };
    row.append(m, x);
    list.append(row);
  });
}
async function addRelay() {
  const v = $("#relayInput").value.trim();
  if (!v) return;
  try {
    const r = await post("/api/relays/add", { relays: v });
    $("#relayInput").value = "";
    if (r.skipped && r.skipped.length)
      toast("skipped: " + r.skipped.join(", "), "err");
    else toast("added", "ok");
    refresh();
  } catch (e) {
    toast(e.message, "err");
  }
}
$("#relayBtn").onclick = addRelay;
$("#relayInput").addEventListener("keydown", (e) => {
  if (e.key === "Enter") addRelay();
});

// Local relay helper: a co-located relay needs two addresses because the same
// relay is reached differently by the client and the daemon.
//   advertise — client-reachable, goes into the bunker URI (e.g. ws://umbrel:4848)
//   internal  — the relay container the daemon dials (e.g. nostr-relay_relay_1:8080)
// The server stores `advertise` as the relay and rewrites it to `internal` only
// at dial time, so a local-only relay can work for login.
async function addLocalRelay() {
  const advertise = $("#localRelayAdvertise").value.trim();
  const internal = $("#localRelayInternal").value.trim();
  if (!advertise || !internal) {
    toast("fill in both advertise and internal", "err");
    return;
  }
  try {
    const r = await post("/api/relays/add-local", { advertise, internal });
    $("#localRelayAdvertise").value = "";
    // restore the default internal address rather than clearing it
    const internalInput = $("#localRelayInternal");
    internalInput.value = internalInput.defaultValue;
    toast(
      `local relay added (${r.advertise} → ${r.internal}) — restart the daemon`,
      "ok",
    );
    refresh();
  } catch (e) {
    toast(e.message, "err");
  }
}
$("#localRelayBtn").onclick = addLocalRelay;
$("#localRelayInternal").addEventListener("keydown", (e) => {
  if (e.key === "Enter") addLocalRelay();
});
$("#localRelayAdvertise").addEventListener("keydown", (e) => {
  if (e.key === "Enter") $("#localRelayInternal").focus();
});

async function renderClients() {
  let data;
  try {
    data = await api("/api/clients");
  } catch {
    return;
  }
  const list = $("#clientList");
  list.innerHTML = "";
  if (!data.clients.length) {
    list.append(el("div", "empty", "no connected clients."));
    return;
  }
  data.clients.forEach((c) => {
    const row = el("div", "row row--tappable");
    const m = el("div", "row__main");
    m.append(el("div", "row__name", c.name || "(no name)"));
    m.append(el("div", "row__sub", `pubkey: ${c.pubkey}`));
    m.append(
      el("div", "row__perms", `granted: ${permsSummary(c.permissions)}`),
    );
    row.append(m);
    if (c.source) row.append(el("span", "tag", c.source));
    if (data.running) {
      const x = el("button", "row__x", "revoke");
      x.onclick = (e) => {
        e.stopPropagation();
        revokeFlow(c);
      };
      row.append(x);
    }
    row.onclick = () => clientPermsFlow(c, data.running);
    list.append(row);
  });
}

// PERM_DEFS drives the per-client permission switches. Keys match the JSON
// fields of the backend clientPerms struct.
const PERM_DEFS = [
  {
    key: "get_public_key",
    label: "read public key (get_public_key)",
    desc: "lets the client read this signer's public key (npub).",
  },
  {
    key: "sign_event",
    label: "sign event (sign_event)",
    desc: "signs nostr events such as posts and reactions. the most essential permission.",
  },
  {
    key: "nip04_encrypt",
    label: "NIP-04 encrypt (nip04_encrypt)",
    desc: "encrypts messages using the legacy DM scheme.",
  },
  {
    key: "nip04_decrypt",
    label: "NIP-04 decrypt (nip04_decrypt)",
    desc: "decrypts messages received with the legacy DM scheme.",
  },
  {
    key: "nip44_encrypt",
    label: "NIP-44 encrypt (nip44_encrypt)",
    desc: "encrypts messages using the latest standard scheme.",
  },
  {
    key: "nip44_decrypt",
    label: "NIP-44 decrypt (nip44_decrypt)",
    desc: "decrypts messages received with the latest standard scheme.",
  },
  {
    key: "get_relays",
    label: "read relay list (get_relays)",
    desc: "lets the client read and sync the relay list this signer uses.",
  },
];

function permSwitch(def, checked) {
  const wrap = el("label", "switch");
  const input = el("input");
  input.type = "checkbox";
  input.checked = !!checked;
  input.dataset.permKey = def.key;
  const track = el("span", "switch__track");
  track.append(el("span", "switch__thumb"));
  const text = el("span", "switch__text");
  text.append(
    Object.assign(document.createElement("b"), { textContent: def.label }),
  );
  text.append(
    Object.assign(document.createElement("small"), { textContent: def.desc }),
  );
  wrap.append(input, track, text);
  return wrap;
}

function clientPermsFlow(c, running) {
  const perms = c.permissions || {};
  const wrap = el("div", "permform");

  const meta = el("div", "permform__meta");
  meta.append(el("div", "kv__k", "pubkey"));
  meta.append(el("div", "permform__pub mono", c.pubkey));
  if (c.permsRequested)
    meta.append(
      el("div", "permform__req", `requested perms: ${c.permsRequested}`),
    );
  wrap.append(meta);

  const switches = el("div", "permform__list");
  PERM_DEFS.forEach((d) => switches.append(permSwitch(d, perms[d.key])));
  wrap.append(switches);

  // sign_event kind restriction (optional, comma-separated kinds)
  const kindWrap = el("div", "field");
  kindWrap.append(
    Object.assign(el("label", "field__label"), {
      textContent: "allowed event kinds — leave empty to allow all",
    }),
  );
  const kindInput = el("input", "input mono");
  kindInput.type = "text";
  kindInput.placeholder = "e.g. 1, 7, 30023";
  kindInput.value = (perms.sign_event_kinds || []).join(", ");
  kindInput.id = "permKinds";
  kindWrap.append(kindInput);
  wrap.append(kindWrap);

  if (!running)
    wrap.append(
      el(
        "p",
        "permform__note",
        "the daemon is stopped. changes are saved and applied on the next start.",
      ),
    );

  modal({
    title: c.name || "(no name)",
    bodyNodes: [wrap],
    actions: [
      { label: "cancel", cls: "btn--ghost", onClick: (cl) => cl() },
      {
        label: "save",
        cls: "btn--green",
        onClick: async (cl) => {
          const next = {};
          $$("input[data-perm-key]", wrap).forEach((i) => {
            next[i.dataset.permKey] = i.checked;
          });
          const kinds = kindInput.value
            .split(",")
            .map((s) => parseInt(s.trim(), 10))
            .filter((n) => Number.isInteger(n) && n >= 0);
          if (kinds.length) next.sign_event_kinds = kinds;
          cl();
          toast("saving perms…");
          try {
            const r = await post("/api/clients/perms", {
              pubkey: c.pubkey,
              perms: next,
            });
            toast(
              r.applied ? "perms updated" : "slow response — check the log",
              r.applied ? "ok" : "err",
            );
          } catch (e) {
            toast(e.message, "err");
          }
          refresh();
        },
      },
    ],
  });
}

function revokeFlow(c) {
  modal({
    title: "revoke connection",
    bodyNodes: [
      para(
        "revoke %s's connection. further requests from this client will be rejected.".replace(
          "%s",
          c.name || "this client",
        ),
      ),
    ],
    actions: [
      { label: "cancel", cls: "btn--ghost", onClick: (cl) => cl() },
      {
        label: "revoke",
        cls: "btn--danger",
        onClick: async (cl) => {
          cl();
          toast("revoking…");
          try {
            const r = await post("/api/clients/revoke", { pubkey: c.pubkey });
            toast(
              r.removed ? "revoked" : "slow response — check the log",
              r.removed ? "ok" : "err",
            );
          } catch (e) {
            toast(e.message, "err");
          }
          refresh();
        },
      },
    ],
  });
}

function parseNostrConnect(uri) {
  let u;
  try {
    u = new URL((uri || "").trim());
  } catch {
    return null;
  }
  if (u.protocol !== "nostrconnect:") return null;
  const p = u.searchParams;
  let name = p.get("name") || "";
  let url = p.get("url") || "";
  let image = p.get("image") || "";
  const perms = p.get("perms") || "";

  const metaRaw = p.get("metadata");
  if (metaRaw)
    try {
      const m = JSON.parse(metaRaw);
      name = name || m.name || "";
      url = url || m.url || "";
      image = image || m.image || "";
    } catch {}
  return {
    pubkey: u.hostname || "",
    relays: p.getAll("relay").filter(Boolean),
    name,
    url,
    image,
    perms,
  };
}

function shortKey(k) {
  return k && k.length > 24 ? k.slice(0, 12) + "…" + k.slice(-8) : k;
}

function kvRow(label, valueNode) {
  const r = el("div", "kv");
  r.append(el("div", "kv__k", label));
  const v = el("div", "kv__v");
  if (typeof valueNode === "string") v.textContent = valueNode;
  else if (Array.isArray(valueNode)) valueNode.forEach((n) => v.append(n));
  else v.append(valueNode);
  r.append(v);
  return r;
}

function confirmAndConnect(uri, sourceInput) {
  const info = parseNostrConnect(uri);
  if (!info) {
    toast("not a valid nostrconnect:// code", "err");
    return;
  }

  const box = el("div", "ncinfo");
  box.append(kvRow("app", info.name || "(no name)"));
  if (info.url) {
    const urlNode = el("div", "kv__line mono");
    urlNode.textContent = info.url;
    box.append(kvRow("url", urlNode));
  }

  if (info.relays.length) {
    const lines = info.relays.map((r) => {
      const n = el("div", "kv__line mono");
      n.textContent = r;
      return n;
    });
    box.append(kvRow("relays", lines));
  } else {
    const warn = el("div", "kv__line kv__line--warn");
    warn.textContent = "no relay info";
    box.append(kvRow("relays", warn));
  }

  if (info.perms) {
    const chips = el("div", "chips");
    info.perms
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean)
      .forEach((t) => chips.append(el("span", "chip", t)));
    box.append(kvRow("perms", chips));
  }

  if (info.pubkey) {
    const pk = el("div", "kv__line mono");
    pk.textContent = shortKey(info.pubkey);
    pk.title = info.pubkey;
    box.append(kvRow("pubkey", pk));
  }

  const status = el("div", "ncstatus");
  status.hidden = true;

  modal({
    title: "connect client",
    bodyNodes: [box, status],
    actions: [
      { label: "cancel", cls: "btn--ghost", onClick: (c) => c() },
      { label: "connect", cls: "btn--green", onClick: (c) => doConnect(c) },
    ],
  });

  const actEl = $("#modalActions");
  const cancelBtn = actEl.children[0];
  const connectBtn = actEl.children[1];

  async function doConnect(close) {
    connectBtn.disabled = true;
    cancelBtn.disabled = true;
    status.hidden = false;
    status.className = "ncstatus";
    status.innerHTML = "connecting" + '<span class="cursor">█</span>';
    try {
      const r = await post("/api/nostrconnect", { uri });
      if (sourceInput) sourceInput.value = "";
      close();
      toast(
        r.ack ? "connected (ack sent)" : "sent — confirm in the client",
        r.ack ? "ok" : "",
      );
      refresh();
    } catch (e) {
      status.className = "ncstatus ncstatus--err";
      status.textContent = e.message || "connection failed";
      connectBtn.disabled = false;
      cancelBtn.disabled = false;
    }
  }
}

function submitNc(input) {
  const v = input.value.trim();
  if (!v) return;
  confirmAndConnect(v, input);
}
function wireNc(inputSel, btnSel) {
  const input = $(inputSel),
    btn = $(btnSel);
  if (!input || !btn) return;
  btn.onclick = () => submitNc(input);
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") submitNc(input);
  });
}
wireNc("#ncInput", "#ncBtn");
wireNc("#ncInputStatus", "#ncBtnStatus");

$("#persistToggle").addEventListener("change", async (e) => {
  try {
    await post("/api/settings", { persistSecret: e.target.checked });
    toast("saved", "ok");
  } catch (err) {
    toast(err.message, "err");
    e.target.checked = !e.target.checked;
  }
});

async function copyText(text) {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch (e) {}
  try {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.top = "-1000px";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    ta.setSelectionRange(0, ta.value.length);
    const ok = document.execCommand("copy");
    document.body.removeChild(ta);
    return ok;
  } catch (e) {
    return false;
  }
}

document.addEventListener("click", (e) => {
  const b = e.target.closest("[data-copy]");
  if (!b) return;
  const t = $(b.getAttribute("data-copy"));
  if (!t) return;
  copyText(t.textContent).then((ok) =>
    toast(ok ? "copied" : "copy failed", ok ? "ok" : "err"),
  );
});

async function loadLog() {
  try {
    const r = await api("/api/log?n=200");
    $("#logBox").textContent = (r.lines || []).join("\n") || "(no log)";
  } catch {}
}
$("#logDetails").addEventListener("toggle", (e) => {
  if (e.target.open) loadLog();
});

/* ---------- web authentication ---------- */
let authReady = false;
let refreshTimer = null;

function startRefreshLoop() {
  if (refreshTimer) return;
  refresh();
  refreshTimer = setInterval(refresh, 5000);
}
function stopRefreshLoop() {
  if (refreshTimer) {
    clearInterval(refreshTimer);
    refreshTimer = null;
  }
}

function showAuthGate(mode) {
  // mode: "setup" (first run) or "login"
  stopRefreshLoop();
  closeModal();
  const gate = $("#authGate");
  const isSetup = mode === "setup";
  $("#authTitle").textContent = isSetup ? "set password" : "log in";
  $("#authHint").textContent = isSetup
    ? "set a password to protect this web control panel. at least 8 characters."
    : "enter your password to continue.";
  $("#authBtn").textContent = isSetup ? "set password" : "log in";
  $("#authForm").hidden = false;
  $("#authPw2").hidden = !isSetup;
  $("#authPw").value = "";
  $("#authPw2").value = "";
  $("#authPw").autocomplete = isSetup ? "new-password" : "current-password";
  hideAuthErr();
  gate.dataset.mode = mode;
  gate.hidden = false;
  setTimeout(() => $("#authPw").focus(), 50);
}
function hideAuthGate() {
  $("#authGate").hidden = true;
}
function showAuthErr(msg) {
  const e = $("#authErr");
  e.textContent = msg;
  e.hidden = false;
}
function hideAuthErr() {
  $("#authErr").hidden = true;
}

function onAuthLost() {
  if (!authReady) return;
  authReady = false;
  showAuthGate("login");
}

async function enterApp() {
  authReady = true;
  hideAuthGate();
  startRefreshLoop();
}

async function checkAuth() {
  let st;
  try {
    st = await api("/api/auth/status");
  } catch {
    showAuthGate("login");
    showAuthErr("can't reach the server. please try again shortly.");
    return;
  }
  if (!st.configured) {
    showAuthGate("setup");
  } else if (!st.authenticated) {
    showAuthGate("login");
  } else {
    enterApp();
  }
}

$("#authForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  hideAuthErr();
  const mode = $("#authGate").dataset.mode;
  const pw = $("#authPw").value;
  const btn = $("#authBtn");
  if (mode === "setup") {
    if (pw.length < 8)
      return showAuthErr("password must be at least 8 characters.");
    if (pw !== $("#authPw2").value)
      return showAuthErr("passwords don't match.");
  } else if (!pw) {
    return showAuthErr("enter your password.");
  }
  btn.disabled = true;
  try {
    await post(mode === "setup" ? "/api/auth/setup" : "/api/auth/login", {
      password: pw,
    });
    $("#authPw").value = "";
    $("#authPw2").value = "";
    enterApp();
  } catch (err) {
    showAuthErr(err.message);
  } finally {
    btn.disabled = false;
  }
});

$("#logoutBtn").onclick = async () => {
  try {
    await post("/api/auth/logout", {});
  } catch {}
  authReady = false;
  showAuthGate("login");
};

$("#pwChangeBtn").onclick = async () => {
  const cur = $("#pwCurrent").value;
  const next = $("#pwNext").value;
  const next2 = $("#pwNext2").value;
  if (!cur) return toast("enter your current password.", "err");
  if (next.length < 8)
    return toast("new password must be at least 8 characters.", "err");
  if (next !== next2) return toast("new passwords don't match.", "err");
  try {
    await post("/api/auth/password", { current: cur, next: next });
    $("#pwCurrent").value = "";
    $("#pwNext").value = "";
    $("#pwNext2").value = "";
    toast("password changed", "ok");
  } catch (e) {
    toast(e.message, "err");
  }
};

checkAuth();
