/* Cerberus — interface.
 *
 * This layer only renders. It holds no key, derives nothing, and receives a
 * secret only in response to an explicit user action (reveal, copy, auto-type).
 * Everything else is in Rust, behind the IPC.
 */

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;
const dialog = window.__TAURI__.dialog;

// A secret revealed on screen is re-masked automatically after this delay. JS
// strings cannot be wiped deterministically (they live in the WebView2 heap
// until the GC runs); shrinking the display window limits exposure to a memory
// dump or a glance over the shoulder.
const REVEAL_TIMEOUT_MS = 20000;

/* ── interface state ─────────────────────────────────────────────────────── */
const ui = {
  vaultPath: null,
  keyfiles: [],
  pattern: { size: 5, points: [] },
  folder: null,
  inTrash: false,
  selected: null,
  entries: [],
  folders: [],
  query: "",
  totpTimer: null,
  /** Facteurs exigés par le coffre sélectionné, lus dans son en-tête. */
  required: null,
  /** Parts Shamir fournies au déverrouillage. */
  shareFiles: [],
  shareHex: [],
};

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

/* ── utilitaires ─────────────────────────────────────────────────────────── */

/* Errors surface from the Rust core in English. They are refined into friendlier
 * user-facing wording here, the one place that speaks to the user. An unknown
 * error is shown as-is rather than hidden. */
const MESSAGES = [
  [/supply at least one authentication factor/i,
   "Enter at least one authentication factor (password, PIN, key file, or pattern)."],
  [/unable to unlock/i, "Cannot unlock: check your factors."],
  [/the vault is locked/i, "The vault is locked."],
  [/a PIN cannot be the only factor.*/i,
   "A PIN alone is refused: add a key file or a password."],
  [/the master password must be at least 8 characters/i,
   "The master password must be at least 8 characters."],
  [/the PIN must be between 4 and 32 digits/i, "The PIN must be between 4 and 32 digits."],
  [/the PIN must contain digits only/i, "The PIN must contain digits only."],
  [/a key file must be at least 32 bytes/i, "A key file must be at least 32 bytes."],
  [/the pattern must link at least (\d+) dots/i, "The pattern must link at least $1 dots."],
  [/this pattern only carries about (\d+) bits.*/i,
    "This pattern only carries about $1 bits: enlarge the grid, add dots, " +
    "or combine it with another factor."],
  [/a standalone pattern must use an irregular 8x8 path with at least 14 dots.*/i,
   "A standalone pattern must be irregular, on an 8×8 grid, link at least 14 dots, " +
   "span most of the grid, and change direction often."],
  [/a standalone pattern requires the paranoid Argon2id profile/i,
   "A standalone pattern requires the paranoid Argon2id profile."],
  [/a file already exists at that location/i, "A file already exists at that location."],
  [/the file is not a Cerberus vault/i, "This file is not a Cerberus vault."],
  [/too many failed attempts: wait (\d+) s/i, "Too many failed attempts: wait $1 s."],
  [/unknown entry/i, "Entry not found."],
  [/this entry has no TOTP/i, "This entry has no TOTP."],
  [/auto-type is only implemented on Windows/i, "Auto-type only exists on Windows."],
  [/wrong gate phrase/i, "Incorrect gate phrase."],
  [/a gate phrase is required/i, "A gate phrase is required."],
  [/the gate phrase must be at least 6 characters/i, "The gate phrase must be at least 6 characters."],
  [/the configuration is unreadable/i, "Unreadable configuration."],
  [/at least 2 shares are needed.*/i, "At least 2 shares are needed to reconstruct."],
  [/not a Cerberus share/i, "This file is not a Cerberus share."],
  [/share checksum failed.*/i, "Invalid share: a character was probably mistyped."],
];

function humanise(error) {
  const raw = String(error?.message ?? error);
  for (const [pattern, replacement] of MESSAGES) {
    if (pattern.test(raw)) return raw.replace(pattern, replacement);
  }
  return raw;
}

function toast(message, kind = "") {
  const el = document.createElement("div");
  el.className = `toast ${kind}`;
  el.textContent = kind === "err" ? humanise(message) : message;
  $("#toast-host").append(el);
  setTimeout(() => el.remove(), 4200);
}

/** Inserts text without ever interpreting it as HTML. */
function text(tag, className, content) {
  const el = document.createElement(tag);
  if (className) el.className = className;
  if (content !== undefined) el.textContent = content;
  return el;
}

function showError(message) {
  const box = $("#lock-error");
  box.textContent = humanise(message);
  box.hidden = false;
}

/** Factors currently entered, with a way to clear them one by one. */
function activeFactors() {
  const list = [];
  if ($("#in-password").value) {
    list.push({ kind: "password", label: "Password" });
  }
  if ($("#in-pin").value) {
    list.push({ kind: "pin", label: "PIN" });
  }
  if (ui.keyfiles.length) {
    list.push({
      kind: "keyfile",
      label: `${ui.keyfiles.length} key file${ui.keyfiles.length > 1 ? "s" : ""}`,
    });
  }
  if (ui.pattern.points.length) {
    list.push({
      kind: "pattern",
      label: `Pattern ${ui.pattern.size}×${ui.pattern.size} · ${ui.pattern.points.length} pts`,
    });
  }
  const shareCount = ui.shareFiles.length + ui.shareHex.length;
  if (shareCount > 0) {
    list.push({ kind: "shares", label: `${shareCount} Shamir share${shareCount > 1 ? "s" : ""}` });
  }
  return list;
}

function factorSummary() {
  return activeFactors().map((f) => f.label.toLowerCase());
}

function clearFactor(kind) {
  if (kind === "password") $("#in-password").value = "";
  if (kind === "pin") $("#in-pin").value = "";
  if (kind === "keyfile") { ui.keyfiles = []; renderKeyfiles(); }
  if (kind === "pattern") { ui.pattern.points = []; drawPattern(); updatePatternInfo(); }
  if (kind === "shares") { ui.shareFiles = []; ui.shareHex = []; renderShares(); }
  refreshStrength();
}

/** Bandeau permanent : montre que les facteurs s'additionnent, pas qu'on en choisit un. */
function renderRecap() {
  const factors = activeFactors();
  const chips = $("#recap-chips");
  chips.replaceChildren();
  $("#recap-empty").hidden = factors.length > 0;

  factors.forEach((factor, i) => {
    if (i > 0) chips.append(text("span", "recap-plus", "+"));
    const chip = text("li", "chip");
    chip.append(text("span", null, factor.label));
    const remove = text("button", null, "✕");
    remove.title = `Retirer : ${factor.label}`;
    remove.addEventListener("click", () => clearFactor(factor.kind));
    chip.append(remove);
    chips.append(chip);
  });
}

function clearError() {
  $("#lock-error").hidden = true;
}

/** Couleur d'avatar dérivée du titre : stable, purement décorative. */
function avatarColour(title) {
  let hash = 0;
  for (const ch of title) hash = (hash * 31 + ch.codePointAt(0)) >>> 0;
  return `hsl(${hash % 360} 62% 46%)`;
}

function formatDate(unix) {
  if (!unix) return "—";
  return new Date(unix * 1000).toLocaleDateString("fr-FR", {
    year: "numeric", month: "short", day: "numeric",
  });
}

/* ── collecte des facteurs ───────────────────────────────────────────────── */

function collectFactors() {
  const factors = { keyfiles: ui.keyfiles };
  const password = $("#in-password").value;
  const pin = $("#in-pin").value;
  if (password) factors.password = password;
  if (pin) factors.pin = pin;
  if (ui.pattern.points.length > 0) {
    factors.pattern = { size: ui.pattern.size, points: ui.pattern.points };
  }
  if (ui.shareFiles.length > 0) factors.share_files = ui.shareFiles;
  if (ui.shareHex.length > 0) factors.share_hex = ui.shareHex;
  return factors;
}

/** Vrai lorsque le schéma est l'unique secret fourni. Le moteur Rust refait
 * impérativement ce contrôle : cette fonction ne sert qu'au retour visuel. */
function isStandalonePattern(factors) {
  return Boolean(factors.pattern) &&
    !factors.password && !factors.pin &&
    (factors.keyfiles?.length ?? 0) === 0 &&
    (factors.share_files?.length ?? 0) === 0 &&
    (factors.share_hex?.length ?? 0) === 0;
}

function renderShares() {
  const list = $("#share-list");
  list.replaceChildren();
  const total = ui.shareFiles.length + ui.shareHex.length;

  ui.shareFiles.forEach((path, i) => {
    const li = text("li", "chip");
    li.append(text("span", null, "📄 " + path.split(/[\\/]/).pop()));
    const rm = text("button", null, "✕");
    rm.addEventListener("click", () => { ui.shareFiles.splice(i, 1); renderShares(); refreshStrength(); });
    li.append(rm);
    list.append(li);
  });
  ui.shareHex.forEach((_, i) => {
    const li = text("li", "chip");
    li.append(text("span", null, `⌨ part saisie ${i + 1}`));
    const rm = text("button", null, "✕");
    rm.addEventListener("click", () => { ui.shareHex.splice(i, 1); renderShares(); refreshStrength(); });
    li.append(rm);
    list.append(li);
  });

  $("#share-info").textContent = total === 0
    ? "Fournis au moins le nombre de parts requis (K)."
    : `${total} part${total > 1 ? "s" : ""} fournie${total > 1 ? "s" : ""}.`;
}

function filledMap() {
  return {
    password: $("#in-password").value.length > 0,
    pin: $("#in-pin").value.length > 0,
    keyfile: ui.keyfiles.length > 0,
    pattern: ui.pattern.points.length > 0,
    shares: ui.shareFiles.length + ui.shareHex.length > 0,
  };
}

/** Marque les onglets renseignés, et — sur un coffre existant — ceux qui manquent.
 *
 * Le fichier déclare en clair quels facteurs il exige, donc l'afficher ne
 * révèle rien qu'un attaquant ne puisse lire lui-même dans l'en-tête.
 */
function markFilledTabs() {
  const filled = filledMap();
  $$("#factor-tabs .tab").forEach((tab) => {
    const kind = tab.dataset.factor;
    const required = ui.required?.[kind] === true;
    tab.classList.toggle("filled", filled[kind]);
    tab.classList.toggle("required", required);
    tab.classList.toggle("missing", required && !filled[kind]);
  });
}

/** Facteurs exigés par le coffre ouvert mais pas encore saisis. */
function missingRequired() {
  if (!ui.required) return [];
  const filled = filledMap();
  const names = {
    password: "mot de passe", pin: "PIN",
    keyfile: "fichier-clé", pattern: "schéma",
  };
  return Object.keys(names).filter((k) => ui.required[k] && !filled[k]).map((k) => names[k]);
}

/** Estime l'entropie en bits *localement*, sans transmettre les facteurs.
 *
 * Un audit indépendant a noté que l'ancienne jauge envoyait mot de passe / PIN /
 * schéma au backend à chaque frappe (plusieurs copies temporaires en RAM avant
 * même la tentative d'ouverture). Ici on ne lit que la *forme* — longueur, jeu
 * de caractères, taille de grille — jamais les valeurs, et rien ne quitte le
 * webview tant que l'utilisateur n'a pas cliqué sur « Déverrouiller ». C'est
 * une estimation indicative ; le vrai verdict reste le MAC côté Rust.
 */
function estimateBitsLocally() {
  let bits = 0;
  const pw = $("#in-password").value;
  if (pw) {
    let alphabet = 0;
    if (/[a-z]/.test(pw)) alphabet += 26;
    if (/[A-Z]/.test(pw)) alphabet += 26;
    if (/[0-9]/.test(pw)) alphabet += 10;
    if (/[^a-zA-Z0-9]/.test(pw)) alphabet += 33;
    if (/[^\x00-\x7F]/.test(pw)) alphabet += 100;
    const unique = new Set(pw).size;
    const repetition = Math.max(unique / pw.length, 0.3);
    bits += pw.length * Math.log2(alphabet || 1) * repetition;
  }
  const pin = $("#in-pin").value;
  if (pin) bits += pin.length * Math.log2(10);
  if (ui.pattern.points.length > 0) {
    const n = ui.pattern.size * ui.pattern.size;
    for (let i = 0; i < ui.pattern.points.length; i++) bits += Math.log2(Math.max(n - i, 1));
  }
  // Un fichier-clé apporte beaucoup d'entropie ; on ne peut pas la mesurer ici
  // sans lire son contenu, donc on crédite une valeur forfaitaire prudente.
  bits += ui.keyfiles.length * 128;
  if (ui.shareFiles.length + ui.shareHex.length > 0) bits += 128;
  return bits;
}

/** Met à jour la jauge de robustesse — calcul purement local, aucun IPC. */
function refreshStrength() {
  markFilledTabs();
  renderRecap();
  const filled = filledMap();
  const empty = !filled.password && !filled.pin && !filled.pattern &&
    !filled.keyfile && !filled.shares;

  const fill = $("#strength-fill");
  const label = $("#strength-text");

  if (empty) {
    fill.style.width = "0%";
    label.textContent = window.i18n.t("strength.none", "Aucun facteur saisi");
    label.className = "hint";
    return;
  }

  const bits = estimateBitsLocally();
  const ratio = Math.min(bits / 128, 1);
  fill.style.width = `${Math.max(ratio * 100, 4)}%`;
  fill.style.background =
    bits < 50 ? "var(--danger)" : bits < 80 ? "var(--warn)" : "var(--ok)";

  const missing = missingRequired();
  if (missing.length > 0) {
    label.textContent = `Ce coffre exige aussi : ${missing.join(", ")}`;
    label.className = "hint warn";
  } else if (isStandalonePattern(collectFactors())) {
    const basicShape = ui.pattern.size === 8 && ui.pattern.points.length >= 14;
    label.textContent = basicShape
      ? `Schéma seul — ≈ ${Math.round(bits)} bits ; forme irrégulière et profil paranoïaque requis`
      : "Schéma seul : grille 8×8, au moins 14 points, large couverture et forme irrégulière requises";
    label.className = `hint ${basicShape ? "" : "warn"}`.trim();
  } else {
    label.textContent = `${factorSummary().join(" + ")} — ≈ ${Math.round(bits)} bits (estimation)`;
    label.className = "hint";
  }
}

/* ── grille de schéma (réutilisable) ─────────────────────────────────────── */

/* Fabrique un éditeur de schéma lié à un canvas et un état donnés. Utilisé par
 * l'écran de déverrouillage et par l'éditeur de sécurité (rekey), chacun avec
 * son propre canvas et son propre état, sans variables globales partagées. */
function makePatternEditor({ canvas, sizeSelect, infoEl, clearBtn, state, onChange }) {
  const ctx = canvas.getContext("2d");
  let drawing = false;

  function dotPositions() {
    const n = state.size;
    const pad = 34;
    const step = (canvas.width - pad * 2) / (n - 1);
    const dots = [];
    for (let row = 0; row < n; row++) {
      for (let col = 0; col < n; col++) {
        dots.push({ x: pad + col * step, y: pad + row * step, index: row * n + col });
      }
    }
    return dots;
  }

  function draw() {
    const dots = dotPositions();
    const n = state.size;
    const radius = Math.max(4, 26 / n + 3);
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    if (state.points.length > 1) {
      ctx.strokeStyle = "#6366f1";
      ctx.lineWidth = Math.max(2, 14 / n);
      ctx.lineCap = "round";
      ctx.lineJoin = "round";
      ctx.beginPath();
      state.points.forEach((index, i) => {
        const d = dots[index];
        if (i === 0) ctx.moveTo(d.x, d.y);
        else ctx.lineTo(d.x, d.y);
      });
      ctx.stroke();
    }
    for (const dot of dots) {
      const order = state.points.indexOf(dot.index);
      ctx.beginPath();
      ctx.arc(dot.x, dot.y, radius, 0, Math.PI * 2);
      ctx.fillStyle = order >= 0 ? "#6366f1" : "#262c3a";
      ctx.fill();
      if (order === 0) {
        ctx.strokeStyle = "#0ea5e9";
        ctx.lineWidth = 2;
        ctx.stroke();
      }
    }
  }

  function dotAt(x, y) {
    const radius = Math.max(10, 40 / state.size + 8);
    return dotPositions().find((d) => Math.hypot(d.x - x, d.y - y) <= radius);
  }

  function canvasPoint(event) {
    const rect = canvas.getBoundingClientRect();
    return {
      x: ((event.clientX - rect.left) / rect.width) * canvas.width,
      y: ((event.clientY - rect.top) / rect.height) * canvas.height,
    };
  }

  function extend(event) {
    const { x, y } = canvasPoint(event);
    const dot = dotAt(x, y);
    if (!dot || state.points.includes(dot.index)) return;
    state.points.push(dot.index);
    draw();
    updateInfo();
  }

  function updateInfo() {
    if (!infoEl) return;
    const count = state.points.length;
    const n = state.size;
    const minimum = Math.max(5, n);
    if (count === 0) {
      infoEl.textContent = "Aucun point";
      infoEl.className = "hint";
      return;
    }
    let bits = 0;
    for (let i = 0; i < count; i++) bits += Math.log2(n * n - i);
    infoEl.textContent = `${count} point${count > 1 ? "s" : ""} · ≈ ${Math.round(bits)} bits`;
    infoEl.className = count < minimum ? "hint warn" : "hint";
    if (count < minimum) infoEl.textContent += ` · minimum ${minimum}`;
  }

  canvas.addEventListener("pointerdown", (e) => {
    drawing = true;
    canvas.setPointerCapture(e.pointerId);
    state.points = [];
    extend(e);
  });
  canvas.addEventListener("pointermove", (e) => drawing && extend(e));
  canvas.addEventListener("pointerup", () => { drawing = false; onChange && onChange(); });
  canvas.addEventListener("pointercancel", () => { drawing = false; });

  if (sizeSelect) {
    sizeSelect.addEventListener("change", (e) => {
      state.size = Number(e.target.value);
      state.points = [];
      draw();
      updateInfo();
      onChange && onChange();
    });
  }
  if (clearBtn) {
    clearBtn.addEventListener("click", () => {
      state.points = [];
      draw();
      updateInfo();
      onChange && onChange();
    });
  }

  draw();
  updateInfo();
  return { draw, updateInfo };
}

// Éditeur de schéma de l'écran de déverrouillage.
const lockPattern = makePatternEditor({
  canvas: $("#pattern-canvas"),
  sizeSelect: $("#grid-size"),
  infoEl: $("#pattern-info"),
  clearBtn: $("#btn-pattern-clear"),
  state: ui.pattern,
  onChange: refreshStrength,
});
const drawPattern = lockPattern.draw;
const updatePatternInfo = lockPattern.updateInfo;

/* ── modes de facteurs : cases à cocher, panneaux empilés ─────────────────────
 *
 * Les modes ne s'excluent pas : on coche ceux qu'on veut (mot de passe, schéma…)
 * et TOUS leurs champs s'affichent en même temps, empilés, pour les renseigner
 * d'un coup. Cocher = afficher + utiliser ; décocher = masquer + effacer ce
 * facteur (sinon un champ caché mais rempli serait exigé à l'insu de l'utilisateur).
 */

function isFactorEnabled(kind) {
  return $(`#factor-tabs .tab[data-factor="${kind}"]`)?.classList.contains("active") ?? false;
}

function setFactorEnabled(kind, on, { clearOnOff = true } = {}) {
  const tab = $(`#factor-tabs .tab[data-factor="${kind}"]`);
  const panel = $(`.factor-panel[data-panel="${kind}"]`);
  if (!tab || !panel) return;
  tab.classList.toggle("active", on);
  tab.setAttribute("aria-pressed", on ? "true" : "false");
  panel.classList.toggle("active", on);
  if (on && kind === "pattern") drawPattern();
  if (!on && clearOnOff) clearFactor(kind);
  refreshStrength();
}

$$("#factor-tabs .tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    setFactorEnabled(tab.dataset.factor, !tab.classList.contains("active"));
  });
});

// Mode par défaut visible au démarrage : le mot de passe.
setFactorEnabled("password", true, { clearOnOff: false });

// Débrayé : envoyer le mot de passe en IPC à chaque frappe (potentiellement
// des dizaines de fois par seconde) l'exposait plus souvent que nécessaire.
// Un correctif indépendant a signalé ce point ; 200 ms après la dernière
// frappe suffit largement pour une jauge réactive.
let strengthDebounce = null;
function refreshStrengthDebounced() {
  clearTimeout(strengthDebounce);
  strengthDebounce = setTimeout(refreshStrength, 200);
}
$("#in-password").addEventListener("input", refreshStrengthDebounced);
$("#in-pin").addEventListener("input", refreshStrengthDebounced);

$("#btn-eye").addEventListener("click", () => {
  const input = $("#in-password");
  input.type = input.type === "password" ? "text" : "password";
});

/* ── parts Shamir (déverrouillage) ───────────────────────────────────────── */

$("#btn-add-share-file").addEventListener("click", async () => {
  const picked = await dialog.open({
    multiple: true,
    title: "Choisir des fichiers de part",
    filters: [{ name: "Part Cerberus", extensions: ["cbvshare"] }],
  });
  if (!picked) return;
  for (const p of [].concat(picked)) {
    if (!ui.shareFiles.includes(p)) ui.shareFiles.push(p);
  }
  renderShares();
  refreshStrength();
});

$("#btn-add-share-hex").addEventListener("click", () => {
  const val = $("#in-share-hex").value.trim();
  if (!val) return;
  ui.shareHex.push(val);
  $("#in-share-hex").value = "";
  renderShares();
  refreshStrength();
});
$("#in-share-hex").addEventListener("keydown", (e) => {
  if (e.key === "Enter") { e.preventDefault(); $("#btn-add-share-hex").click(); }
});

/* ── fichiers-clés ───────────────────────────────────────────────────────── */

function renderKeyfiles() {
  const list = $("#keyfile-list");
  list.replaceChildren();
  ui.keyfiles.forEach((path, i) => {
    const li = text("li", "chip");
    li.append(text("span", null, path.split(/[\\/]/).pop()));
    const remove = text("button", null, "✕");
    remove.title = path;
    remove.addEventListener("click", () => {
      ui.keyfiles.splice(i, 1);
      renderKeyfiles();
      refreshStrength();
    });
    li.append(remove);
    list.append(li);
  });
}

$("#btn-add-keyfile").addEventListener("click", async () => {
  const picked = await dialog.open({ multiple: true, title: "Choisir un ou plusieurs fichiers-clés" });
  if (!picked) return;
  for (const p of [].concat(picked)) {
    if (!ui.keyfiles.includes(p)) ui.keyfiles.push(p);
  }
  renderKeyfiles();
  refreshStrength();
});

$("#btn-new-keyfile").addEventListener("click", async () => {
  const path = await dialog.save({
    title: "Enregistrer le nouveau fichier-clé",
    defaultPath: "cerberus.key",
  });
  if (!path) return;
  try {
    await invoke("generate_keyfile", { path });
    ui.keyfiles.push(path);
    renderKeyfiles();
    refreshStrength();
    toast("Fichier-clé généré. Sauvegardez-le : sans lui, le coffre est irrécupérable.", "ok");
  } catch (e) {
    toast(String(e), "err");
  }
});

/* ── sélection et déverrouillage du coffre ───────────────────────────────── */

$("#btn-browse").addEventListener("click", async () => {
  const path = await dialog.open({
    title: "Ouvrir un coffre",
    filters: [{ name: "Coffre Cerberus", extensions: ["cbv"] }],
  });
  if (!path) return;
  await selectVault(path);
});

async function selectVault(path, { silent = false } = {}) {
  ui.vaultPath = path;
  $("#vault-path").value = path;
  clearError();
  try {
    const peek = await invoke("vault_peek", { path });
    if (peek.factors_known) {
      // Coffre v1 : l'en-tête déclare encore ses facteurs en clair.
      ui.required = {
        password: peek.needs_password,
        pin: peek.needs_pin,
        keyfile: peek.needs_keyfile,
        pattern: peek.needs_pattern,
      };
      const needed = [
        peek.needs_password && "mot de passe",
        peek.needs_pin && "PIN",
        peek.needs_keyfile && "fichier-clé",
        peek.needs_pattern && "schéma",
      ].filter(Boolean);
      $("#vault-meta").textContent =
        `Requis : ${needed.join(" + ")} · ${peek.cascade.join(" → ")} · Argon2id ${peek.kdf_memory_mib} Mio`;
      // Affiche d'emblée TOUS les modes exigés par ce coffre, empilés, prêts à
      // saisir — pas seulement le premier.
      Object.keys(ui.required).forEach((k) => {
        if (ui.required[k]) setFactorEnabled(k, true, { clearOnOff: false });
      });
    } else {
      // Coffre v2 : facteurs et cascade chiffrés. On ne peut rien pré-afficher,
      // c'est le but. L'utilisateur saisit ce qu'il sait, le MAC tranchera.
      ui.required = null;
      $("#vault-meta").textContent =
        `Facteurs masqués (chiffrés) · Argon2id ${peek.kdf_memory_mib} Mio · ` +
        `saisissez vos facteurs`;
    }
    refreshStrength();
  } catch (e) {
    ui.required = null;
    $("#vault-meta").textContent = "";
    // Auto-reprise au démarrage : un coffre récent déplacé ou supprimé ne doit
    // pas cracher une erreur à l'écran — il n'y a pas eu d'action utilisateur.
    // On efface juste la pré-sélection périmée en silence.
    if (silent) {
      ui.vaultPath = null;
      $("#vault-path").value = "";
      return;
    }
    showError(String(e));
  }
}

$("#btn-unlock").addEventListener("click", unlock);

document.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && $("#screen-lock").classList.contains("active")) unlock();
  if (e.key === "Escape" && !$("#screen-help").hidden) return closeHelp();
  if (e.key === "Escape" && !$("#modal-host").hidden) closeModal();
  if (!$("#screen-main").classList.contains("active")) return;
  // Ctrl+L : verrouillage immédiat. Ctrl+S : écriture immédiate.
  if (e.ctrlKey && e.key.toLowerCase() === "l") {
    e.preventDefault();
    lockVault();
  }
  if (e.ctrlKey && e.key.toLowerCase() === "s") {
    e.preventDefault();
    clearTimeout(saveTimer);
    save().then(() => toast("Coffre enregistré", "ok"));
  }
});

// Dernier filet : la fenêtre se ferme avec des modifications en attente.
window.addEventListener("beforeunload", () => {
  if (!$("#save-state").hidden) {
    clearTimeout(saveTimer);
    save();
  }
});

async function unlock() {
  if (!ui.vaultPath) return showError("Sélectionnez d'abord un coffre.");
  clearError();
  const button = $("#btn-unlock");
  button.disabled = true;
  button.textContent = "Dérivation…";
  try {
    const info = await invoke("vault_unlock", { path: ui.vaultPath, input: collectFactors() });
    await enterVault(info);
  } catch (e) {
    showError(String(e));
    const delay = await invoke("unlock_delay_remaining");
    if (delay.milliseconds > 0) countdownRetry(delay.milliseconds);
  } finally {
    button.disabled = false;
    button.textContent = "Déverrouiller";
  }
}

function countdownRetry(ms) {
  const button = $("#btn-unlock");
  button.disabled = true;
  const end = Date.now() + ms;
  const tick = () => {
    const left = Math.ceil((end - Date.now()) / 1000);
    if (left <= 0) {
      button.disabled = false;
      button.textContent = "Déverrouiller";
      return;
    }
    button.textContent = `Patientez ${left} s`;
    setTimeout(tick, 250);
  };
  tick();
}

/** Efface tout ce que l'écran de déverrouillage a pu retenir. */
function clearFactorInputs() {
  $("#in-password").value = "";
  $("#in-pin").value = "";
  ui.pattern.points = [];
  ui.keyfiles = [];
  ui.shareFiles = [];
  ui.shareHex = [];
  renderKeyfiles();
  renderShares();
  drawPattern();
  updatePatternInfo();
  refreshStrength();
}

async function enterVault(info) {
  // Un coffre tout juste créé n'a jamais été « peeké » : mémoriser son chemin
  // permet de relire ses facteurs exigés au prochain verrouillage.
  ui.vaultPath = info.path;
  $("#vault-path").value = info.path;
  clearFactorInputs();
  $("#screen-lock").classList.remove("active");
  $("#screen-main").classList.add("active");
  $("#vault-name").textContent = info.name;
  $("#vault-cascade").textContent = info.cascade.join(" → ");
  ui.folder = null;
  ui.selected = null;
  await Promise.all([loadFolders(), loadEntries()]);
  renderDetail(null);
  startSessionTimer();
}

async function lockVault() {
  // Ne jamais verrouiller sur une modification non écrite : la clé disparaît
  // avec la session, et avec elle la possibilité de sauvegarder.
  clearTimeout(saveTimer);
  if (!$("#save-state").hidden) await save();
  invoke("vault_lock").finally(() => {
    stopSessionTimer();
    ui.entries = [];
    ui.folders = [];
    ui.selected = null;
    $("#entry-list").replaceChildren();
    $("#screen-main").classList.remove("active");
    $("#screen-lock").classList.add("active");
    closeModal();
    // Relit l'en-tête pour réafficher les facteurs exigés.
    if (ui.vaultPath) selectVault(ui.vaultPath);
  });
}

$("#btn-lock").addEventListener("click", lockVault);

/* ── minuteries de session ───────────────────────────────────────────────── */

let sessionTimer = null;
let clipboardTimer = null;
let activeSinceTick = false;

["pointerdown", "keydown", "wheel"].forEach((evt) =>
  document.addEventListener(evt, () => { activeSinceTick = true; }, { passive: true })
);

function startSessionTimer() {
  stopSessionTimer();
  sessionTimer = setInterval(async () => {
    try {
      const remaining = await invoke("session_tick", { active: activeSinceTick });
      activeSinceTick = false;
      const pill = $("#lock-countdown");
      if (remaining !== null && remaining <= 60) {
        pill.hidden = false;
        pill.textContent = `Verrouillage dans ${remaining} s`;
      } else {
        pill.hidden = true;
      }
    } catch {
      // Rust a verrouillé pour inactivité.
      toast("Coffre verrouillé après inactivité", "ok");
      lockVault();
    }
  }, 5000);

  clipboardTimer = setInterval(async () => {
    try {
      if (await invoke("clipboard_tick")) toast("Presse-papier effacé", "ok");
    } catch { /* le presse-papier peut être verrouillé par une autre application */ }
  }, 1000);
}

function stopSessionTimer() {
  clearInterval(sessionTimer);
  clearInterval(clipboardTimer);
  clearInterval(ui.totpTimer);
  $("#lock-countdown").hidden = true;
}

/* ── dossiers ────────────────────────────────────────────────────────────── */

async function loadFolders() {
  ui.folders = await invoke("folders_list");
  const tree = $("#folder-tree");
  tree.replaceChildren();

  const all = text("div", `folder${ui.folder === null && !ui.inTrash ? " active" : ""}`);
  all.append(text("span", null, "🗂"), text("span", "grow", window.i18n.t("sidebar.allEntries", "Toutes les entrées")));
  all.append(text("span", "count", String(ui.entries.length)));
  all.addEventListener("click", () => {
    ui.inTrash = false;
    ui.folder = null;
    loadEntries();
    loadFolders();
  });
  tree.append(all);

  const roots = ui.folders.filter((f) => f.parent !== null);
  const render = (folder, depth) => {
    const el = text("div", `folder${ui.folder === folder.id ? " active" : ""}`);
    el.style.paddingLeft = `${10 + depth * 14}px`;
    el.append(text("span", null, "📁"), text("span", "grow", folder.name));
    el.append(text("span", "count", String(folder.entry_count)));

    const del = text("button", "del", "✕");
    del.title = "Supprimer ce dossier";
    del.addEventListener("click", async (e) => {
      e.stopPropagation();
      const ok = await dialog.confirm(
        `Supprimer « ${folder.name} », ses sous-dossiers et toutes leurs entrées ?`,
        { title: "Suppression définitive", kind: "warning" }
      );
      if (!ok) return;
      const removed = await invoke("folder_delete", { id: folder.id });
      if (ui.folder === folder.id) ui.folder = null;
      toast(`Dossier supprimé (${removed} entrée${removed > 1 ? "s" : ""})`, "ok");
      markDirty();
      await loadFolders();
      await loadEntries();
    });
    el.append(del);

    el.addEventListener("click", () => {
      ui.inTrash = false;
      ui.folder = folder.id;
      loadEntries();
      loadFolders();
    });
    tree.append(el);

    ui.folders.filter((f) => f.parent === folder.id).forEach((child) => render(child, depth + 1));
  };
  roots.filter((f) => ui.folders.find((p) => p.id === f.parent)?.parent === null)
       .forEach((f) => render(f, 0));

  // Corbeille, toujours en bas.
  const trashed = await invoke("trash_list");
  const bin = text("div", `folder trash-folder${ui.inTrash ? " active" : ""}`);
  bin.append(text("span", null, "🗑"), text("span", "grow", window.i18n.t("sidebar.trash", "Corbeille")));
  bin.append(text("span", "count", String(trashed.length)));
  bin.addEventListener("click", () => {
    ui.inTrash = true;
    ui.folder = null;
    loadEntries();
    loadFolders();
  });
  tree.append(bin);
}

$("#btn-new-folder").addEventListener("click", () => {
  openModal("Nouveau dossier", (body, foot) => {
    const field = text("div", "field");
    field.append(text("label", null, "Nom du dossier"));
    const input = document.createElement("input");
    input.type = "text";
    input.placeholder = "Travail";
    field.append(input);
    body.append(field);
    setTimeout(() => input.focus(), 50);

    const create = text("button", "btn primary", "Créer");
    create.addEventListener("click", async () => {
      if (!input.value.trim()) return;
      const root = ui.folders.find((f) => f.parent === null);
      const parent = ui.folder ?? root.id;
      await invoke("folder_create", { parent, name: input.value.trim() });
      markDirty();
      closeModal();
      await loadFolders();
    });
    input.addEventListener("keydown", (e) => e.key === "Enter" && create.click());
    foot.append(cancelButton(), create);
  });
});

/* ── entrées ─────────────────────────────────────────────────────────────── */

async function loadEntries() {
  ui.entries = ui.inTrash
    ? await invoke("trash_list")
    : await invoke("entries_list", { folder: ui.folder, query: ui.query || null });

  const list = $("#entry-list");
  list.replaceChildren();

  if (ui.inTrash && ui.entries.length > 0) {
    const bar = text("li", "trash-bar");
    bar.append(text("span", "grow hint",
      "Les entrées restent ici jusqu'à ce que vous vidiez la corbeille."));
    const empty = text("button", "btn danger small", "Vider");
    empty.addEventListener("click", async () => {
      const ok = await dialog.confirm(
        `Détruire définitivement ${ui.entries.length} entrée(s) ? Cette action est irréversible.`,
        { title: "Vider la corbeille", kind: "warning" }
      );
      if (!ok) return;
      const purged = await invoke("trash_empty");
      markDirty();
      ui.selected = null;
      toast(`${purged} entrée(s) détruite(s)`, "ok");
      await loadEntries();
      await loadFolders();
      renderDetail(null);
    });
    bar.append(empty);
    list.append(bar);
  }

  if (ui.entries.length === 0) {
    const empty = text("li", "entry");
    empty.append(text("span", "muted",
      ui.inTrash ? "La corbeille est vide" : ui.query ? "Aucun résultat" : "Aucune entrée"));
    list.append(empty);
    return;
  }

  for (const entry of ui.entries) {
    const li = text("li", `entry${ui.selected === entry.id ? " active" : ""}`);

    const avatar = text("div", "entry-avatar", (entry.title[0] ?? "?").toUpperCase());
    avatar.style.background = avatarColour(entry.title);

    const middle = text("div", "grow");
    middle.append(text("div", "entry-title", entry.title));
    middle.append(text("div", "entry-sub", entry.username || entry.url || "—"));

    const flags = text("div", "entry-flags");
    if (entry.has_totp) flags.append(text("span", "flag totp", "TOTP"));
    if (entry.expired) flags.append(text("span", "flag expired", "expiré"));

    li.append(avatar, middle, flags);
    li.addEventListener("click", () => selectEntry(entry.id));
    list.append(li);
  }
}

$("#search").addEventListener("input", (e) => {
  ui.query = e.target.value;
  loadEntries();
});

async function selectEntry(id) {
  ui.selected = id;
  await loadEntries();
  renderDetail(ui.entries.find((e) => e.id === id));
}

function kvRow(key, value, options = {}) {
  const row = text("div", "kv-row");
  row.append(text("div", "kv-key", key));
  const val = text("div", `kv-val${options.mono ? " mono" : ""}`, value);
  row.append(val);
  if (options.actions) {
    const actions = text("div", "kv-actions");
    options.actions.forEach((a) => actions.append(a));
    row.append(actions);
  }
  return { row, val };
}

function actionButton(label, title, handler) {
  const b = text("button", "btn ghost small", label);
  b.title = title;
  b.addEventListener("click", handler);
  return b;
}

function renderDetail(entry) {
  clearInterval(ui.totpTimer);
  const host = $("#detail");
  host.replaceChildren();

  if (!entry) {
    const empty = text("div", "empty");
    empty.append(text("p", null, window.i18n.t("detail.selectEntry", "Sélectionnez une entrée")));
    host.append(empty);
    return;
  }

  const head = text("div", "detail-head");
  const avatar = text("div", "entry-avatar", (entry.title[0] ?? "?").toUpperCase());
  avatar.style.background = avatarColour(entry.title);
  avatar.style.width = avatar.style.height = "44px";
  head.append(avatar);
  const titles = text("div", "grow");
  titles.append(text("h2", null, entry.title));
  titles.append(text("div", "muted tiny", entry.url || "—"));
  head.append(titles);
  const actions = text("div", "detail-actions");

  if (entry.trashed) {
    // Dans la corbeille, seules deux actions ont du sens.
    actions.append(actionButton(window.i18n.t("detail.restore", "Restaurer"), "Sortir de la corbeille", async () => {
      await invoke("entry_restore", { id: entry.id });
      markDirty();
      ui.inTrash = false;
      ui.folder = null;
      toast(`« ${entry.title} » restaurée`, "ok");
      await loadEntries();
      await loadFolders();
      await selectEntry(entry.id);
    }));
    const purge = actionButton(window.i18n.t("detail.destroy", "Détruire"), "Suppression définitive", async () => {
      const ok = await dialog.confirm(
        `Détruire définitivement « ${entry.title} » ? Cette action est irréversible.`,
        { title: "Suppression définitive", kind: "warning" }
      );
      if (!ok) return;
      await invoke("entry_purge", { id: entry.id });
      markDirty();
      ui.selected = null;
      await loadEntries();
      await loadFolders();
      renderDetail(null);
    });
    purge.classList.add("danger");
    actions.append(purge);
    head.append(actions);
    host.append(head);
    host.append(renderFields(entry));
    return;
  }

  actions.append(actionButton(window.i18n.t("detail.edit", "Modifier"), "Modifier cette entrée", () => entryForm(entry)));
  actions.append(actionButton("QR", "Afficher un QR code de cette entrée",
                              () => entryQrMenu(entry)));
  actions.append(actionButton(window.i18n.t("detail.autotype", "Saisie auto"), "Taper dans la fenêtre active",
                              () => autotypeMenu(entry)));
  // Envoi à la corbeille : réversible, donc pas de confirmation bloquante.
  const del = actionButton(window.i18n.t("detail.delete", "Supprimer"), "Déplacer vers la corbeille", async () => {
    await invoke("entry_delete", { id: entry.id });
    markDirty();
    ui.selected = null;
    toast(`« ${entry.title} » déplacée vers la corbeille`, "ok");
    await loadEntries();
    await loadFolders();
    renderDetail(null);
  });
  del.classList.add("danger");
  actions.append(del);
  head.append(actions);
  host.append(head);

  const kv = text("div", "kv");

  const user = kvRow("Identifiant", entry.username || "—", {
    actions: entry.username ? [copyButton(entry.id, "username")] : [],
  });
  kv.append(user.row);

  const masked = "•".repeat(Math.min(entry.password_length, 24));
  const pw = kvRow("Mot de passe", entry.has_password ? masked : "—", { mono: true });
  if (entry.has_password) {
    let shown = false;
    let hideTimer = null;
    const eye = actionButton("👁", "Afficher", async () => {
      shown = !shown;
      clearTimeout(hideTimer);
      if (shown) {
        const secret = await invoke("entry_reveal", { id: entry.id, field: "password" });
        // The user may have clicked "hide" again while the IPC was in flight;
        // don't re-insert the secret over their explicit re-masking.
        if (!shown) return;
        pw.val.textContent = secret;
        hideTimer = setTimeout(() => { pw.val.textContent = masked; shown = false; }, REVEAL_TIMEOUT_MS);
      } else {
        pw.val.textContent = masked;
      }
    });
    const actions = text("div", "kv-actions");
    actions.append(eye, copyButton(entry.id, "password"));
    pw.row.append(actions);
  }
  kv.append(pw.row);

  if (entry.url) kv.append(kvRow("URL", entry.url).row);
  if (entry.tags.length) kv.append(kvRow("Étiquettes", entry.tags.join(", ")).row);
  kv.append(kvRow("Modifié le", formatDate(entry.modified_at)).row);
  if (entry.expires_at) {
    const exp = kvRow("Expire le", formatDate(entry.expires_at));
    if (entry.expired) exp.val.style.color = "var(--danger)";
    kv.append(exp.row);
  }
  if (entry.history_count > 0) {
    kv.append(kvRow("Historique", `${entry.history_count} ancien(s) mot(s) de passe`, {
      actions: [actionButton("Voir", "Afficher l'historique", () => showHistory(entry))],
    }).row);
  }
  host.append(kv);
  renderCustomFields(host, entry);

  if (entry.has_notes) {
    const notesBox = text("div", "kv");
    const notesMasked = "•••••";
    let notesTimer = null;
    const row = kvRow("Notes", notesMasked, {
      actions: [actionButton("Afficher", "Afficher les notes", async () => {
        clearTimeout(notesTimer);
        row.val.textContent = await invoke("entry_reveal", { id: entry.id, field: "notes" });
        row.val.style.whiteSpace = "pre-wrap";
        notesTimer = setTimeout(() => { row.val.textContent = notesMasked; }, REVEAL_TIMEOUT_MS);
      })],
    });
    notesBox.append(row.row);
    host.append(notesBox);
  }

  if (entry.has_totp) renderTotp(host, entry);
}

/** Choix de ce que la saisie automatique doit taper. */
function autotypeMenu(entry) {
  const custom = entry.autotype_sequence;
  const choices = [
    ["Tout", custom ?? null, "Séquence de l'entrée : identifiant, Tab, mot de passe, Entrée"],
    ["Identifiant seul", "{USERNAME}", null],
    ["Mot de passe seul", "{PASSWORD}", null],
    ["Identifiant + Tab", "{USERNAME}{TAB}", null],
  ];
  if (entry.has_totp) choices.push(["Code TOTP seul", "{TOTP}", null]);

  openModal(`Saisie automatique — ${entry.title}`, (body, foot) => {
    body.append(text("p", "hint",
      "Cerberus se réduira, puis tapera dans la fenêtre qui reprend le focus. " +
      "Placez le curseur dans le bon champ avant de lancer."));

    const list = text("div", "cascade-picker");
    let chosen = choices[0][1];
    const redraw = () => {
      list.replaceChildren();
      choices.forEach(([label, sequence, note]) => {
        const item = text("div", `cascade-item${sequence === chosen ? " on" : ""}`);
        const box = text("div", "grow");
        box.append(text("div", null, label));
        if (note) box.append(text("div", "hint", note));
        item.append(box);
        item.addEventListener("click", () => { chosen = sequence; redraw(); });
        list.append(item);
      });
    };
    redraw();
    body.append(list);

    body.append(text("p", "hint warn",
      "Le mot de passe est envoyé à la fenêtre active, quelle qu'elle soit. " +
      "Vérifiez qu'il s'agit bien de l'application attendue."));

    const go = text("button", "btn primary", "Taper maintenant");
    go.addEventListener("click", async () => {
      go.disabled = true;
      try {
        await invoke("autotype", { id: entry.id, sequence: chosen });
        closeModal();
      } catch (e) {
        toast(String(e), "err");
        go.disabled = false;
      }
    });
    foot.append(cancelButton(), go);
  });
}

/** Affiche un QR pour l'un des champs de l'entrée, au choix. */
async function entryQrMenu(entry) {
  const choices = [];
  if (entry.has_password) choices.push(["Mot de passe", "password", true]);
  if (entry.username) choices.push(["Identifiant", "username", false]);
  if (entry.url) choices.push(["URL", "url", false]);
  if (entry.has_totp) choices.push(["Secret TOTP", "totp-uri", true]);

  if (choices.length === 0) {
    return toast("Cette entrée n'a rien à encoder", "err");
  }

  openModal(`QR — ${entry.title}`, (body) => {
    const buttons = text("div", "row");
    const host = text("div", "qr-host");
    const caution = text("p", "hint warn", "");

    const show = async ([label, field, secret]) => {
      try {
        // Le SVG est rendu par Rust : aucun secret ne traverse une
        // bibliothèque QR JavaScript.
        const svg = field === "totp-uri"
          ? await invoke("entry_totp_qr", { id: entry.id })
          : await invoke("qr_svg", {
              text: field === "url"
                ? entry.url
                : await invoke("entry_reveal", { id: entry.id, field }),
            });
        host.innerHTML = svg;
        caution.textContent = secret
          ? `Ce QR code contient « ${label.toLowerCase()} » en clair. Ne le montrez à personne, ` +
            "et ne le laissez pas à l'écran devant une caméra."
          : "";
      } catch (e) {
        toast(String(e), "err");
      }
    };

    choices.forEach((choice, i) => {
      const b = text("button", `btn ${i === 0 ? "primary" : "ghost"}`, choice[0]);
      b.addEventListener("click", () => {
        buttons.querySelectorAll("button").forEach((x) => {
          x.className = "btn ghost";
        });
        b.className = "btn primary";
        show(choice);
      });
      buttons.append(b);
    });

    body.append(buttons, host, caution);
    show(choices[0]);
  });
}

/** Bloc de champs commun à la vue normale et à la vue corbeille. */
function renderFields(entry) {
  const kv = text("div", "kv");
  kv.append(kvRow("Identifiant", entry.username || "—").row);
  kv.append(kvRow("URL", entry.url || "—").row);
  if (entry.tags.length) kv.append(kvRow("Étiquettes", entry.tags.join(", ")).row);
  if (entry.deleted_at) {
    kv.append(kvRow("Supprimée le", formatDate(entry.deleted_at)).row);
  }
  return kv;
}

/** Champs personnalisés : les secrets se comportent comme un mot de passe. */
function renderCustomFields(host, entry) {
  if (entry.custom_fields.length === 0) return;

  const box = text("div", "kv");
  for (const cf of entry.custom_fields) {
    if (!cf.secret) {
      box.append(kvRow(cf.name, cf.value ?? "", {
        actions: [actionButton("⧉", "Copier", async () => {
          await navigator.clipboard.writeText(cf.value ?? "");
          toast("Copié", "ok");
        })],
      }).row);
      continue;
    }

    const masked = "••••••••";
    const row = kvRow(cf.name, masked, { mono: true });
    let shown = false;
    let hideTimer = null;
    const eye = actionButton("👁", "Afficher", async () => {
      shown = !shown;
      clearTimeout(hideTimer);
      if (shown) {
        const secret = await invoke("entry_reveal_custom", { id: entry.id, name: cf.name });
        if (!shown) return; // re-masked while the IPC was in flight
        row.val.textContent = secret;
        hideTimer = setTimeout(() => { row.val.textContent = masked; shown = false; }, REVEAL_TIMEOUT_MS);
      } else {
        row.val.textContent = masked;
      }
    });
    const copy = actionButton("⧉", "Copier (effacement automatique)", async () => {
      try {
        const seconds = await invoke("entry_copy_custom", { id: entry.id, name: cf.name });
        toast(`Copié · effacement dans ${seconds} s`, "ok");
      } catch (e) {
        toast(String(e), "err");
      }
    });
    const actions = text("div", "kv-actions");
    actions.append(eye, copy);
    row.row.append(actions);
    box.append(row.row);
  }
  host.append(box);
}

function copyButton(id, field) {
  return actionButton("⧉", "Copier (effacement automatique)", async () => {
    try {
      const seconds = await invoke("entry_copy", { id, field });
      toast(`Copié · effacement dans ${seconds} s`, "ok");
    } catch (e) {
      toast(String(e), "err");
    }
  });
}

function renderTotp(host, entry) {
  const box = text("div", "kv");
  const row = text("div", "kv-row");
  row.append(text("div", "kv-key", "Code TOTP"));
  const code = text("div", "grow totp-code", "······");
  row.append(code);
  const ring = text("div", "totp-ring");
  row.append(ring);

  const actions = text("div", "kv-actions");
  actions.append(copyButton(entry.id, "totp"));
  actions.append(actionButton("QR", "Afficher le QR code", async () => {
    try {
      const svg = await invoke("entry_totp_qr", { id: entry.id });
      openModal("QR code TOTP", (body) => {
        const wrap = text("div", "qr-host");
        // Le SVG est produit par Rust, jamais par une bibliothèque JavaScript.
        wrap.innerHTML = svg;
        body.append(wrap);
        body.append(text("p", "hint warn",
          "Ce QR code contient le secret TOTP en clair. Ne le montrez à personne."));
      });
    } catch (e) {
      toast(String(e), "err");
    }
  }));
  row.append(actions);
  box.append(row);
  host.append(box);

  const refresh = async () => {
    try {
      const t = await invoke("entry_totp", { id: entry.id });
      code.textContent = t.code.replace(/(.{3})(?=.)/g, "$1 ");
      const ratio = t.seconds_remaining / t.period;
      ring.style.borderTopColor = ratio < 0.25 ? "var(--danger)" : "var(--accent)";
      ring.title = `${t.seconds_remaining} s`;
    } catch {
      clearInterval(ui.totpTimer);
    }
  };
  refresh();
  ui.totpTimer = setInterval(refresh, 1000);
}

async function showHistory(entry) {
  const history = await invoke("entry_history", { id: entry.id });
  openModal("Historique des mots de passe", (body) => {
    body.append(text("p", "hint warn",
      "Ces anciens mots de passe restent stockés dans le coffre. Supprimez l'entrée pour les effacer."));
    const list = text("div", "kv");
    history.forEach(([password, when]) => {
      // Masqué par défaut + dévoilement par ligne avec ré-masquage auto, comme
      // les autres secrets. Avant, tout l'historique s'affichait en clair d'un
      // coup (repéré en audit croisé).
      const masked = "•".repeat(Math.min(password.length, 24));
      const row = kvRow(formatDate(when), masked, { mono: true });
      let shown = false;
      let hideTimer = null;
      const eye = actionButton("👁", "Afficher", () => {
        shown = !shown;
        clearTimeout(hideTimer);
        if (shown) {
          row.val.textContent = password;
          hideTimer = setTimeout(() => { row.val.textContent = masked; shown = false; }, REVEAL_TIMEOUT_MS);
        } else {
          row.val.textContent = masked;
        }
      });
      const actions = text("div", "kv-actions");
      actions.append(eye);
      row.row.append(actions);
      list.append(row.row);
    });
    body.append(list);
  });
}

/* ── formulaire d'entrée ─────────────────────────────────────────────────── */

function field(label, control, hint) {
  const wrap = text("div", "field");
  wrap.append(text("label", null, label));
  wrap.append(control);
  if (hint) wrap.append(text("p", "hint", hint));
  return wrap;
}

function input(type, value = "") {
  const el = document.createElement("input");
  el.type = type;
  el.value = value;
  return el;
}

async function entryForm(existing) {
  const isEdit = Boolean(existing);
  let currentPassword = "";
  let currentNotes = "";
  let currentTotp = "";
  if (isEdit) {
    currentPassword = existing.has_password
      ? await invoke("entry_reveal", { id: existing.id, field: "password" })
      : "";
    currentNotes = existing.has_notes
      ? await invoke("entry_reveal", { id: existing.id, field: "notes" })
      : "";
  }

  openModal(isEdit ? "Modifier l'entrée" : "Nouvelle entrée", (body, foot) => {
    const title = input("text", existing?.title ?? "");
    const username = input("text", existing?.username ?? "");
    const password = input("text", currentPassword);
    password.className = "mono";
    const url = input("text", existing?.url ?? "");
    const tags = input("text", (existing?.tags ?? []).join(", "));
    const totp = input("text", currentTotp);
    const window_ = input("text", existing?.autotype_window ?? "");
    const sequence = input("text", existing?.autotype_sequence ?? "");
    sequence.placeholder = "{USERNAME}{TAB}{PASSWORD}{ENTER}";
    const expires = input("date",
      existing?.expires_at
        ? new Date(existing.expires_at * 1000).toISOString().slice(0, 10)
        : "");
    const notes = document.createElement("textarea");
    notes.value = currentNotes;

    const folderSelect = document.createElement("select");
    ui.folders.forEach((f) => {
      const opt = document.createElement("option");
      opt.value = f.id;
      opt.textContent = f.parent === null ? window.i18n.t("sidebar.allEntries", "Toutes les entrées") : f.name;
      folderSelect.append(opt);
    });
    folderSelect.value = existing?.folder ?? ui.folder ?? ui.folders.find((f) => !f.parent).id;

    const generate = text("button", "btn ghost", "Générer");
    generate.addEventListener("click", async () => {
      const result = await invoke("generate_password", { policy: defaultPolicy() });
      password.value = result.password;
      toast(`Généré · ≈ ${Math.round(result.bits)} bits`, "ok");
    });
    const passwordRow = text("div", "row");
    passwordRow.append(password, generate);

    // Champs personnalisés. `value: null` signifie « garder la valeur stockée » :
    // c'est ce qui permet de modifier une entrée sans que ses champs secrets
    // aient jamais transité vers l'interface.
    const customState = (existing?.custom_fields ?? []).map((f) => ({
      name: f.name, value: f.value, secret: f.secret, touched: false,
    }));
    const customHost = text("div", "custom-fields");

    const redrawCustom = () => {
      customHost.replaceChildren();
      customState.forEach((f, i) => {
        const row = text("div", "custom-row");

        const name = input("text", f.name);
        name.placeholder = "Nom du champ";
        name.addEventListener("input", () => { f.name = name.value; });

        const value = input(f.secret ? "password" : "text", f.value ?? "");
        value.placeholder = f.secret && f.value === null ? "(inchangé)" : "Valeur";
        value.addEventListener("input", () => { f.value = value.value; f.touched = true; });

        const secret = text("label", "row tiny");
        const box = input("checkbox");
        box.checked = f.secret;
        box.addEventListener("change", () => {
          f.secret = box.checked;
          // Passer un champ en secret sans valeur connue le viderait au save.
          if (f.secret && f.value === null) f.value = "";
          redrawCustom();
        });
        secret.append(box, text("span", null, "secret"));

        const remove = text("button", "btn ghost small", "✕");
        remove.title = "Retirer ce champ";
        remove.addEventListener("click", () => { customState.splice(i, 1); redrawCustom(); });

        row.append(name, value, secret, remove);
        customHost.append(row);
      });

      const add = text("button", "btn ghost small", "+ Ajouter un champ");
      add.addEventListener("click", () => {
        customState.push({ name: "", value: "", secret: false, touched: true });
        redrawCustom();
      });
      customHost.append(add);
    };
    redrawCustom();

    body.append(
      field("Titre", title),
      field("Dossier", folderSelect),
      field("Identifiant", username),
      field("Mot de passe", passwordRow),
      field("URL", url),
      field("Étiquettes", tags, "Séparées par des virgules"),
      field("Secret TOTP", totp, "Base32 ou URI otpauth://. Laisser vide s'il n'y en a pas."),
      field("Expiration", expires, "Laisser vide pour ne jamais expirer."),
      field("Fenêtre pour la saisie auto", window_,
            "Motif de titre, par exemple *GitHub*. Sert au raccourci global Ctrl+Alt+A."),
      field("Séquence de saisie auto", sequence,
            "Vide = {USERNAME}{TAB}{PASSWORD}{ENTER}. " +
            "Jetons : {USERNAME} {PASSWORD} {TOTP} {TAB} {ENTER} {DELAY 200}"),
      field("Champs personnalisés", customHost,
            "Un champ marqué secret est masqué, exclu de la recherche, et copié " +
            "avec effacement automatique."),
      field("Notes", notes),
    );

    const save = text("button", "btn primary", isEdit ? "Enregistrer" : "Créer");
    save.addEventListener("click", async () => {
      if (!title.value.trim()) return toast("Le titre est obligatoire", "err");
      const payload = {
        folder: folderSelect.value,
        title: title.value.trim(),
        username: username.value,
        password: password.value,
        url: url.value,
        notes: notes.value,
        totp: totp.value || null,
        tags: tags.value.split(",").map((t) => t.trim()).filter(Boolean),
        // Minuit UTC du jour choisi : l'entrée expire au début de cette journée.
        expires_at: expires.value ? Math.floor(Date.parse(expires.value) / 1000) : null,
        autotype_window: window_.value || null,
        autotype_sequence: sequence.value || null,
        custom_fields: customState
          .filter((f) => f.name.trim())
          .map((f) => ({
            name: f.name.trim(),
            // Un secret non modifié part à null : le backend conserve la valeur
            // existante plutôt que de l'écraser par une chaîne vide.
            value: f.secret && !f.touched ? null : (f.value ?? ""),
            secret: f.secret,
          })),
      };
      try {
        if (isEdit) await invoke("entry_update", { id: existing.id, input: payload });
        else ui.selected = await invoke("entry_create", { input: payload });
        markDirty();
        closeModal();
        await loadEntries();
        await loadFolders();
        renderDetail(ui.entries.find((e) => e.id === ui.selected));
      } catch (e) {
        toast(String(e), "err");
      }
    });
    foot.append(cancelButton(), save);
    setTimeout(() => title.focus(), 50);
  });
}

$("#btn-new-entry").addEventListener("click", () => entryForm(null));

/* ── générateur ──────────────────────────────────────────────────────────── */

function defaultPolicy() {
  return {
    length: 20,
    lowercase: true,
    uppercase: true,
    digits: true,
    symbols: true,
    avoid_ambiguous: false,
    excluded: "",
    require_each_class: true,
  };
}

$("#btn-generate").addEventListener("click", () => {
  openModal("Générateur", (body) => {
    const output = input("text", "");
    output.className = "mono";
    output.readOnly = true;
    const bits = text("p", "hint", "");

    const length = input("number", "20");
    length.min = 4; length.max = 128;

    const checks = {};
    const options = text("div", "row");
    [["lowercase", "a-z"], ["uppercase", "A-Z"], ["digits", "0-9"], ["symbols", "!@#"],
     ["avoid_ambiguous", "Sans ambigus"]].forEach(([key, label]) => {
      const wrap = text("label", "row");
      const box = input("checkbox");
      box.checked = key !== "avoid_ambiguous";
      checks[key] = box;
      wrap.append(box, text("span", null, label));
      options.append(wrap);
    });

    const words = input("number", "6");
    words.min = 3; words.max = 20;

    const roll = async (mode) => {
      try {
        const result = mode === "phrase"
          ? await invoke("generate_passphrase", {
              words: Number(words.value), separator: "-", capitalize: true })
          : await invoke("generate_password", {
              policy: {
                ...defaultPolicy(),
                length: Number(length.value),
                lowercase: checks.lowercase.checked,
                uppercase: checks.uppercase.checked,
                digits: checks.digits.checked,
                symbols: checks.symbols.checked,
                avoid_ambiguous: checks.avoid_ambiguous.checked,
              },
            });
        output.value = result.password;
        bits.textContent = `≈ ${Math.round(result.bits)} bits d'entropie`;
      } catch (e) {
        bits.textContent = String(e);
      }
    };

    const genPassword = text("button", "btn primary", "Mot de passe");
    genPassword.addEventListener("click", () => roll("password"));
    const genPhrase = text("button", "btn ghost", "Phrase de passe");
    genPhrase.addEventListener("click", () => roll("phrase"));
    const copy = text("button", "btn ghost", "Copier");
    copy.addEventListener("click", async () => {
      await navigator.clipboard.writeText(output.value);
      toast("Copié", "ok");
    });
    const qrHost = text("div", "qr-host");
    qrHost.hidden = true;
    const qr = text("button", "btn ghost", "QR");
    qr.addEventListener("click", async () => {
      if (!output.value) return;
      // Remplace le QR précédent au lieu d'en empiler un nouveau à chaque clic.
      qrHost.innerHTML = await invoke("qr_svg", { text: output.value });
      qrHost.hidden = false;
    });

    body.append(
      field("Résultat", output),
      bits,
      field("Longueur", length),
      field("Classes de caractères", options),
      field("Mots (phrase de passe)", words),
    );
    const buttons = text("div", "row");
    buttons.append(genPassword, genPhrase, copy, qr);
    body.append(buttons, qrHost);
    roll("password");
  });
});

/* ── audit ───────────────────────────────────────────────────────────────── */

$("#btn-audit").addEventListener("click", async () => {
  const report = await invoke("vault_audit");
  openModal("Audit du coffre", (body) => {
    const group = (title, items, describe) => {
      const g = text("div", "audit-group");
      g.append(text("h3", null, `${title} — ${items.length}`));
      const ul = document.createElement("ul");
      if (items.length === 0) {
        ul.append(text("li", "muted", "Rien à signaler"));
      } else {
        items.forEach((e) => ul.append(text("li", null, describe(e))));
      }
      g.append(ul);
      body.append(g);
    };
    body.append(text("p", "hint", `${report.total} entrée(s) analysée(s).`));
    group("Mots de passe réutilisés", report.reused, (e) => `${e.title} · ${e.username || "—"}`);
    group("Mots de passe expirés", report.expired, (e) => e.title);
    group("Mots de passe courts (< 12 caractères)", report.weak,
          (e) => `${e.title} · ${e.password_length} caractères`);
    body.append(text("p", "hint",
      `${report.without_totp} entrée(s) sans second facteur TOTP.`));
  });
});

/* ── import / export ─────────────────────────────────────────────────────── */

$("#btn-porting").addEventListener("click", () => {
  openModal("Import / Export", (body) => {
    // — Import CSV —
    const importBlock = text("div", "porting-block");
    importBlock.append(text("h3", null, "Importer un CSV"));
    importBlock.append(text("p", "hint",
      "Accepte les exports de KeePass, Bitwarden, 1Password, Chrome, Firefox et Edge. " +
      "Les colonnes sont reconnues sous leurs différents noms, et l'arborescence de " +
      "dossiers est recréée."));

    const importBtn = text("button", "btn primary", "Choisir un fichier CSV…");
    importBtn.addEventListener("click", async () => {
      const path = await dialog.open({
        title: "Importer un CSV",
        filters: [{ name: "CSV", extensions: ["csv", "txt"] }],
      });
      if (!path) return;
      try {
        const report = await invoke("vault_import_csv", { path, folder: ui.folder });
        markDirty();
        await loadFolders();
        await loadEntries();
        closeModal();

        const bits = [`${report.imported} entrée(s) importée(s)`];
        if (report.folders_created) bits.push(`${report.folders_created} dossier(s) créé(s)`);
        if (report.skipped) bits.push(`${report.skipped} ligne(s) ignorée(s)`);
        toast(bits.join(" · "), "ok");
        if (report.problems.length) {
          openModal("Avertissements d'import", (b) => {
            const ul = document.createElement("ul");
            report.problems.forEach((p) => ul.append(text("li", null, p)));
            b.append(ul);
          });
        }
      } catch (e) {
        toast(String(e), "err");
      }
    });
    importBlock.append(importBtn);
    body.append(importBlock);

    // — Sauvegarde chiffrée —
    const backupBlock = text("div", "porting-block");
    backupBlock.append(text("h3", null, "Sauvegarde chiffrée"));
    backupBlock.append(text("p", "hint",
      "Copie complète du coffre, chiffrée avec les mêmes facteurs que l'original."));
    const backupBtn = text("button", "btn primary", "Enregistrer une sauvegarde…");
    backupBtn.addEventListener("click", async () => {
      const stamp = new Date().toISOString().slice(0, 10);
      const path = await dialog.save({
        title: "Enregistrer la sauvegarde",
        defaultPath: `sauvegarde-${stamp}.cbv`,
        filters: [{ name: "Coffre Cerberus", extensions: ["cbv"] }],
      });
      if (!path) return;
      try {
        await invoke("vault_backup", { path });
        toast("Sauvegarde enregistrée", "ok");
      } catch (e) {
        toast(String(e), "err");
      }
    });
    backupBlock.append(backupBtn);
    body.append(backupBlock);

    // — Export CSV —
    const exportBlock = text("div", "porting-block danger-block");
    exportBlock.append(text("h3", null, "Exporter en CSV"));
    exportBlock.append(text("p", "hint warn",
      "Le fichier produit contient tous vos mots de passe EN CLAIR, lisibles par " +
      "n'importe qui et par n'importe quel programme. Ne l'utilisez que pour migrer " +
      "vers un autre gestionnaire, et supprimez-le aussitôt après."));

    const confirmWrap = text("label", "row");
    const confirmBox = input("checkbox");
    confirmWrap.append(confirmBox, text("span", "tiny", "J'ai compris et je veux exporter en clair"));
    exportBlock.append(confirmWrap);

    const exportBtn = text("button", "btn danger", "Exporter en clair…");
    exportBtn.disabled = true;
    confirmBox.addEventListener("change", () => { exportBtn.disabled = !confirmBox.checked; });
    exportBtn.addEventListener("click", async () => {
      const path = await dialog.save({
        title: "Exporter en CSV (non chiffré)",
        defaultPath: "cerberus-export-EN-CLAIR.csv",
        filters: [{ name: "CSV", extensions: ["csv"] }],
      });
      if (!path) return;
      // Re-authentification : l'utilisateur doit re-saisir ses facteurs, qui sont
      // re-vérifiés côté Rust contre le fichier. Une session déverrouillée (ou un
      // code compromis qui la chevauche) ne suffit pas à vider tout en clair.
      openModal("Confirmer l'export — re-saisis tes facteurs", (rbody, rfoot) => {
        rbody.append(text("p", "hint warn",
          "Pour autoriser l'export EN CLAIR de tous tes mots de passe, ressaisis " +
          "les facteurs qui ouvrent ce coffre. C'est la même vérification qu'au déverrouillage."));
        const editor = makeFactorEditor();
        rbody.append(editor.element);
        const confirm = text("button", "btn danger", "Vérifier et exporter");
        confirm.addEventListener("click", async () => {
          confirm.disabled = true;
          confirm.textContent = "Vérification…";
          try {
            const count = await invoke("vault_export_csv", { path, input: editor.collect() });
            closeModal();
            toast(`${count} entrée(s) exportée(s) en clair — pensez à supprimer le fichier`, "ok");
          } catch (e) {
            toast(String(e), "err");
            confirm.disabled = false;
            confirm.textContent = "Vérifier et exporter";
          }
        });
        rfoot.append(cancelButton(), confirm);
      });
    });
    exportBlock.append(exportBtn);
    body.append(exportBlock);
  });
});

/* ── paramètres ──────────────────────────────────────────────────────────── */

$("#btn-settings").addEventListener("click", async () => {
  const info = await invoke("vault_info");
  openModal("Paramètres", (body, foot) => {
    const clipboardSeconds = input("number", "12");
    clipboardSeconds.min = 1; clipboardSeconds.max = 600;
    const autolockMinutes = input("number", "5");
    autolockMinutes.min = 0; autolockMinutes.max = 240;

    // Sélecteur de langue : liste toutes les langues enregistrées (lang/*.js).
    const langSelect = document.createElement("select");
    for (const { code, name } of window.i18n.availableLanguages()) {
      const opt = document.createElement("option");
      opt.value = code;
      opt.textContent = name;
      langSelect.append(opt);
    }
    langSelect.value = window.i18n.currentLanguage();
    langSelect.addEventListener("change", () => changeLanguage(langSelect.value));

    body.append(
      field("Langue / Language", langSelect),
      field("Effacement du presse-papier (secondes)", clipboardSeconds),
      field("Verrouillage automatique (minutes, 0 = jamais)", autolockMinutes),
    );

    const cascadeBox = text("div", "field");
    cascadeBox.append(text("label", null, "Cascade actuelle"));
    cascadeBox.append(text("p", "hint", info.cascade.join("  →  ")));
    body.append(cascadeBox);

    const rekeyBtn = text("button", "btn ghost block", "Modifier la sécurité (facteurs, cascade)…");
    rekeyBtn.style.marginTop = "6px";
    rekeyBtn.addEventListener("click", () => openRekey(info));
    body.append(rekeyBtn);

    const gateBtn = text("button", "btn ghost block", "Phrase-barrière de l'application…");
    gateBtn.style.marginTop = "6px";
    gateBtn.addEventListener("click", openGateSettings);
    body.append(gateBtn);

    // État de sécurité : signale si le verrouillage mémoire a échoué.
    invoke("security_status").then((st) => {
      if (st && st.memory_lock_failures > 0) {
        const warn = text("p", "hint warn",
          `Attention : ${st.memory_lock_failures} clé(s) n'ont pas pu être verrouillées ` +
          `en mémoire (quota système atteint). Des fragments de clé pourraient être ` +
          `écrits dans le fichier d'échange. Fermez d'autres applications gourmandes ` +
          `puis relancez Cerberus si cela persiste.`);
        warn.style.marginTop = "8px";
        body.append(warn);
      }
    }).catch(() => {});

    const apply = text("button", "btn primary", "Appliquer");
    apply.addEventListener("click", async () => {
      await invoke("set_clipboard_seconds", { seconds: Number(clipboardSeconds.value) });
      await invoke("set_autolock_minutes", {
        minutes: Number(autolockMinutes.value) || null,
      });
      toast("Paramètres appliqués", "ok");
      closeModal();
    });
    foot.append(cancelButton(), apply);
  });
});

/* ── réglage de la phrase-barrière ───────────────────────────────────────── */

async function openGateSettings() {
  const status = await invoke("gate_status");
  openModal("Phrase-barrière de l'application", (body, foot) => {
    body.append(text("p", "hint",
      "La phrase-barrière protège l'accès à l'application : coffres récents et " +
      "préférences. Elle ne verrouille PAS les coffres eux-mêmes (ils gardent " +
      "leurs propres facteurs). La perdre ne fait perdre aucun coffre."));

    if (status.gate_set) {
      body.append(text("p", "hint", "Une phrase-barrière est actuellement active."));
      // La phrase actuelle est exigée pour changer ou désactiver : le backend
      // la vérifie, un appel IPC ne peut plus la contourner.
      const currentInput = text("input"); currentInput.type = "password";
      body.append(field("Phrase actuelle (obligatoire)", currentInput));

      const remove = text("button", "btn danger", "Désactiver la phrase-barrière");
      remove.addEventListener("click", async () => {
        if (!currentInput.value) return toast("Saisis la phrase actuelle", "err");
        try {
          await invoke("gate_configure", { current: currentInput.value, newPhrase: null });
          toast("Phrase-barrière désactivée", "ok");
          closeModal();
        } catch (e) { toast(String(e), "err"); }
      });
      const change = text("input"); change.type = "password";
      const changeBtn = text("button", "btn primary", "Changer la phrase");
      changeBtn.addEventListener("click", async () => {
        if (!currentInput.value) return toast("Saisis la phrase actuelle", "err");
        if (change.value.length < 6) return toast("6 caractères minimum", "err");
        try {
          await invoke("gate_configure", { current: currentInput.value, newPhrase: change.value });
          toast("Phrase-barrière changée", "ok");
          closeModal();
        } catch (e) { toast(String(e), "err"); }
      });
      body.append(field("Nouvelle phrase", change), changeBtn);
      foot.append(cancelButton(), remove);
    } else {
      const set = text("input"); set.type = "password";
      body.append(field("Définir une phrase-barrière (6 caractères min.)", set));
      const enable = text("button", "btn primary", "Activer");
      enable.addEventListener("click", async () => {
        if (set.value.length < 6) return toast("6 caractères minimum", "err");
        try {
          await invoke("gate_configure", { current: null, newPhrase: set.value });
          toast("Phrase-barrière activée — elle sera demandée au prochain lancement", "ok");
          closeModal();
        } catch (e) { toast(String(e), "err"); }
      });
      foot.append(cancelButton(), enable);
    }
  });
}

/* ── éditeur de facteurs réutilisable ────────────────────────────────────── */

/* Construit un bloc de saisie de facteurs autonome (mot de passe, PIN,
 * fichiers-clés, schéma) et renvoie { element, collect() }. Utilisé par
 * l'éditeur de sécurité (rekey). */
function makeFactorEditor() {
  const state = { keyfiles: [], pattern: { size: 5, points: [] } };
  const root = text("div", "factor-editor");

  const pw = input("password", "");
  const pin = input("password", "");
  pin.inputMode = "numeric";

  // Fichiers-clés
  const keyfileList = text("ul", "chip-list");
  const renderKf = () => {
    keyfileList.replaceChildren();
    state.keyfiles.forEach((path, i) => {
      const li = text("li", "chip");
      li.append(text("span", null, path.split(/[\\/]/).pop()));
      const rm = text("button", null, "✕");
      rm.addEventListener("click", () => { state.keyfiles.splice(i, 1); renderKf(); });
      li.append(rm);
      keyfileList.append(li);
    });
  };
  const addKf = text("button", "btn ghost small", "Ajouter un fichier-clé…");
  addKf.addEventListener("click", async () => {
    const picked = await dialog.open({ multiple: true, title: "Choisir des fichiers-clés" });
    if (!picked) return;
    for (const p of [].concat(picked)) if (!state.keyfiles.includes(p)) state.keyfiles.push(p);
    renderKf();
  });

  // Schéma (canvas dédié)
  const sizeSel = document.createElement("select");
  [3, 4, 5, 6, 7, 8].forEach((s) => {
    const o = document.createElement("option");
    o.value = s; o.textContent = `${s} × ${s}`;
    if (s === 5) o.selected = true;
    sizeSel.append(o);
  });
  const cv = document.createElement("canvas");
  cv.width = 300; cv.height = 300; cv.className = "pattern-mini";
  const patInfo = text("p", "hint", "Aucun point");
  const clearPat = text("button", "btn ghost small", "Effacer");
  makePatternEditor({
    canvas: cv, sizeSelect: sizeSel, infoEl: patInfo, clearBtn: clearPat, state: state.pattern,
  });

  root.append(
    field("Mot de passe", pw),
    field("PIN", pin, "Chiffres uniquement. Jamais seul."),
    (() => { const f = field("Fichiers-clés", keyfileList); f.append(addKf); return f; })(),
    (() => {
      const f = text("div", "field");
      const row = text("div", "row between");
      row.append(text("label", null, "Schéma"), sizeSel);
      f.append(row);
      const host = text("div", "pattern-host"); host.append(cv); f.append(host);
      const bottom = text("div", "row between"); bottom.append(patInfo, clearPat); f.append(bottom);
      return f;
    })(),
  );

  const collect = () => {
    const factors = { keyfiles: state.keyfiles };
    if (pw.value) factors.password = pw.value;
    if (pin.value) factors.pin = pin.value;
    if (state.pattern.points.length > 0) {
      factors.pattern = { size: state.pattern.size, points: state.pattern.points };
    }
    return factors;
  };

  return { element: root, collect };
}

/* ── éditeur de sécurité d'un coffre (rekey) ─────────────────────────────── */

function openRekey(info) {
  openModal("Modifier la sécurité du coffre", (body, foot) => {
    body.append(text("p", "hint warn",
      "Définis les NOUVEAUX facteurs ci-dessous. Ils remplacent entièrement les anciens : " +
      "après validation, le coffre s'ouvrira uniquement avec ces facteurs-là. " +
      "Les sauvegardes déjà faites gardent les anciens facteurs."));

    const editor = makeFactorEditor();
    body.append(editor.element);

    // Cascade — reprend la cascade actuelle par ses identifiants internes.
    const nameToId = {
      "AES-256-GCM": "Aes256Gcm", "XChaCha20-Poly1305": "XChaCha20Poly1305",
      "Serpent-256 (CTR+HMAC)": "Serpent256", "Twofish-256 (CTR+HMAC)": "Twofish256",
      "Camellia-256 (CTR+HMAC)": "Camellia256",
    };
    const cascade = info.cascade.map((n) => nameToId[n]).filter(Boolean);
    const picker = text("div", "cascade-picker");
    const redraw = () => {
      picker.replaceChildren();
      [["Aes256Gcm", "AES-256-GCM"], ["XChaCha20Poly1305", "XChaCha20-Poly1305"],
       ["Serpent256", "Serpent-256 (CTR+HMAC)"], ["Twofish256", "Twofish-256 (CTR+HMAC)"],
       ["Camellia256", "Camellia-256 (CTR+HMAC)"]].forEach(([id, label]) => {
        const order = cascade.indexOf(id);
        const item = text("div", `cascade-item${order >= 0 ? " on" : ""}`);
        if (order >= 0) item.append(text("span", "order", String(order + 1)));
        item.append(text("span", "grow", label));
        item.addEventListener("click", () => {
          if (order >= 0) cascade.splice(order, 1);
          else if (cascade.length < 4) cascade.push(id);
          else return toast("Quatre couches au maximum", "err");
          redraw();
        });
        picker.append(item);
      });
    };
    redraw();

    const kdf = document.createElement("select");
    [["interactive", "Interactif — 256 Mio, ~0,5 s"],
     ["hardened", "Renforcé — 1 Gio, ~2 s"],
     ["paranoid", "Paranoïaque — 4 Gio, ~15 s"]].forEach(([v, l]) => {
      const o = document.createElement("option"); o.value = v; o.textContent = l; kdf.append(o);
    });
    kdf.value = "hardened";

    body.append(
      field("Nouvelle cascade", picker, "Cliquez pour ajouter/retirer."),
      field("Coût de dérivation", kdf),
    );

    const apply = text("button", "btn primary", "Ré-encoder le coffre");
    apply.addEventListener("click", async () => {
      const factors = editor.collect();
      if (!factors.password && !factors.pin && !factors.pattern && factors.keyfiles.length === 0) {
        return toast("Choisis au moins un facteur", "err");
      }
      if (cascade.length === 0) return toast("Choisis au moins un algorithme", "err");
      const selectedKdf = isStandalonePattern(factors) ? "paranoid" : kdf.value;
      if (selectedKdf === "paranoid" && kdf.value !== "paranoid") {
        kdf.value = "paranoid";
        toast("Profil paranoïaque imposé pour un schéma utilisé seul");
      }
      const ok = await dialog.confirm(
        "Confirmer le changement de sécurité ? Le coffre sera ré-encodé avec les nouveaux facteurs.",
        { title: "Modifier la sécurité", kind: "warning" }
      );
      if (!ok) return;
      apply.disabled = true;
      apply.textContent = "Dérivation…";
      try {
        await invoke("vault_rekey", {
          input: factors,
          cascade,
          kdfProfile: selectedKdf,
        });
        closeModal();
        toast("Sécurité du coffre mise à jour", "ok");
      } catch (e) {
        toast(String(e), "err");
      } finally {
        apply.disabled = false;
        apply.textContent = "Ré-encoder le coffre";
      }
    });
    foot.append(cancelButton(), apply);
  });
}

/* ── création de coffre ──────────────────────────────────────────────────── */

$("#btn-new-vault").addEventListener("click", () => {
  // Les facteurs se saisissent sur l'écran de fond, que la modale masque.
  // Sans ce garde-fou, on ne découvre le problème qu'au clic final.
  if (factorSummary().length === 0) {
    showError(
      "Choisissez d'abord vos facteurs ci-dessus (mot de passe, PIN, fichier-clé ou schéma), " +
      "puis relancez la création du coffre."
    );
    $("#in-password").focus();
    return;
  }

  openModal("Nouveau coffre", (body, foot) => {
    const name = input("text", "Personnel");
    const chosen = ["Aes256Gcm", "XChaCha20Poly1305"];

    const picker = text("div", "cascade-picker");
    const redraw = () => {
      picker.replaceChildren();
      [
        ["Aes256Gcm", "AES-256-GCM"],
        ["XChaCha20Poly1305", "XChaCha20-Poly1305"],
        ["Serpent256", "Serpent-256 (CTR+HMAC)"],
        ["Twofish256", "Twofish-256 (CTR+HMAC)"],
        ["Camellia256", "Camellia-256 (CTR+HMAC)"],
      ].forEach(([id, label]) => {
        const order = chosen.indexOf(id);
        const item = text("div", `cascade-item${order >= 0 ? " on" : ""}`);
        if (order >= 0) item.append(text("span", "order", String(order + 1)));
        item.append(text("span", "grow", label));
        item.addEventListener("click", () => {
          if (order >= 0) chosen.splice(order, 1);
          else if (chosen.length < 4) chosen.push(id);
          else return toast("Quatre couches au maximum", "err");
          redraw();
        });
        picker.append(item);
      });
    };
    redraw();

    const kdf = document.createElement("select");
    [["interactive", "Interactif — 256 Mio, ~0,5 s"],
     ["hardened", "Renforcé — 1 Gio, ~2 s (recommandé)"],
     ["paranoid", "Paranoïaque — 4 Gio, ~15 s"]].forEach(([v, l]) => {
      const o = document.createElement("option");
      o.value = v; o.textContent = l;
      kdf.append(o);
    });
    kdf.value = "hardened";

    const patternOnly = isStandalonePattern(collectFactors());
    if (patternOnly) {
      kdf.value = "paranoid";
      kdf.disabled = true;
    }

    const recap = text("div", "kv");
    recap.append(kvRow("Facteurs retenus", factorSummary().join(" + ") || "aucun").row);

    // — Option Shamir : découper un facteur en N parts, K requises —
    const shamirWrap = text("div", "field");
    const shamirToggle = text("label", "row");
    const shamirBox = input("checkbox");
    shamirToggle.append(shamirBox, text("span", null,
      "Protéger par parts de secours (Shamir) — clés USB réparties"));
    shamirWrap.append(shamirToggle);

    const shamirParams = text("div", "row");
    shamirParams.style.marginTop = "10px";
    shamirParams.hidden = true;
    const kIn = input("number", "2"); kIn.min = 2; kIn.max = 255; kIn.style.width = "70px";
    const nIn = input("number", "3"); nIn.min = 2; nIn.max = 255; nIn.style.width = "70px";
    shamirParams.append(
      text("span", "tiny", "Il faut"), kIn, text("span", "tiny", "part(s) sur"), nIn,
      text("span", "tiny", "pour ouvrir"),
    );
    shamirWrap.append(shamirParams);
    const shamirHint = text("p", "hint", "");
    shamirWrap.append(shamirHint);
    shamirBox.addEventListener("change", () => {
      shamirParams.hidden = !shamirBox.checked;
      shamirHint.textContent = shamirBox.checked
        ? "Un facteur secret sera généré et découpé en N parts (fichiers à ranger sur des clés USB séparées). Le mot de passe reste exigé par-dessus."
        : "";
    });

    body.append(
      field("Nom du coffre", name),
      recap,
      shamirWrap,
      field("Cascade de chiffrement", picker,
            "Cliquez pour ajouter ou retirer. L'ordre d'application est numéroté."),
      field("Coût de dérivation Argon2id", kdf,
            patternOnly ? "Profil paranoïaque imposé : le schéma est utilisé seul." : ""),
      text("p", "hint warn",
        "Ces facteurs seront exigés à chaque ouverture, tous ensemble. " +
        "Perdre l'un d'eux rend le coffre irrécupérable : il n'existe aucune récupération."),
    );

    const create = text("button", "btn primary", "Créer le coffre");
    create.addEventListener("click", async () => {
      if (chosen.length === 0) return toast("Choisissez au moins un algorithme", "err");
      const useShamir = shamirBox.checked;
      const factors = collectFactors();
      const selectedKdf = isStandalonePattern(factors) ? "paranoid" : kdf.value;
      const k = Number(kIn.value), n = Number(nIn.value);
      if (useShamir && (k < 2 || n < k)) {
        return toast("Seuil invalide : K ≥ 2 et N ≥ K", "err");
      }
      const path = await dialog.save({
        title: "Enregistrer le nouveau coffre",
        defaultPath: "coffre.cbv",
        filters: [{ name: "Coffre Cerberus", extensions: ["cbv"] }],
      });
      if (!path) return;

      create.disabled = true;
      create.textContent = "Dérivation…";
      try {
        if (useShamir) {
          const shares = await invoke("vault_create_shamir", {
            path,
            name: name.value.trim() || "Coffre",
            input: factors,
            k, n,
            cascade: chosen,
            kdfProfile: selectedKdf,
          });
          const info = await invoke("vault_info");
          closeModal();
          await showSharesExport(shares, () => enterVault(info));
        } else {
          const info = await invoke("vault_create", {
            path,
            name: name.value.trim() || "Coffre",
            input: factors,
            cascade: chosen,
            kdfProfile: selectedKdf,
          });
          closeModal();
          await enterVault(info);
          toast("Coffre créé", "ok");
        }
      } catch (e) {
        toast(String(e), "err");
      } finally {
        create.disabled = false;
        create.textContent = "Créer le coffre";
      }
    });
    foot.append(cancelButton(), create);
  });
});

/* ── export des parts Shamir ─────────────────────────────────────────────── */

async function showSharesExport(shares, onDone) {
  openModal(`Vos ${shares.length} parts de secours`, (body, foot) => {
    body.append(text("p", "hint warn",
      "Sauvegarde CHAQUE part dans un endroit SÉPARÉ (clés USB, papier chez un proche). " +
      `Il en faut ${shares[0].k} pour rouvrir le coffre. Une part perdue seule n'est pas grave ; ` +
      "une part isolée ne révèle rien."));

    const saved = new Set();
    const updateDone = () => {
      done.disabled = saved.size < shares.length;
      done.textContent = saved.size < shares.length
        ? `Enregistre les ${shares.length} parts (${saved.size}/${shares.length})`
        : "Terminé — ouvrir le coffre";
    };

    shares.forEach((share) => {
      const card = text("div", "kv");
      const head = text("div", "kv-row");
      head.append(text("div", "kv-key", `Part ${share.index}/${share.n}`));
      const status = text("div", "grow tiny muted", "non enregistrée");
      head.append(status);
      card.append(head);

      // Boutons : sauver fichier, afficher QR, copier hex.
      const actions = text("div", "kv-row");
      const actWrap = text("div", "row");

      const saveBtn = text("button", "btn primary small", "Enregistrer le fichier…");
      saveBtn.addEventListener("click", async () => {
        const path = await dialog.save({
          title: `Enregistrer la part ${share.index}`,
          defaultPath: share.filename,
          filters: [{ name: "Part Cerberus", extensions: ["cbvshare"] }],
        });
        if (!path) return;
        await invoke("share_save", { path, fileB64: share.file_b64 });
        saved.add(share.index);
        status.textContent = "✓ enregistrée";
        status.style.color = "var(--ok)";
        updateDone();
        toast(`Part ${share.index} enregistrée`, "ok");
      });

      const qrBtn = text("button", "btn ghost small", "QR papier");
      const hexBtn = text("button", "btn ghost small", "Copier le hex");
      hexBtn.addEventListener("click", async () => {
        await navigator.clipboard.writeText(share.hex);
        toast("Hex copié — colle-le sur ta feuille de secours", "ok");
        saved.add(share.index);
        status.textContent = "✓ sauvegardée (hex)";
        status.style.color = "var(--ok)";
        updateDone();
      });

      const qrHost = text("div", "qr-host");
      qrHost.hidden = true;
      qrBtn.addEventListener("click", async () => {
        if (qrHost.hidden) {
          qrHost.innerHTML = await invoke("share_qr", { hex: share.hex });
          qrHost.hidden = false;
          saved.add(share.index);
          status.textContent = "✓ QR affiché";
          status.style.color = "var(--ok)";
          updateDone();
        } else {
          qrHost.hidden = true;
        }
      });

      actWrap.append(saveBtn, qrBtn, hexBtn);
      actions.append(actWrap);
      card.append(actions);
      card.append(qrHost);
      body.append(card);
    });

    const done = text("button", "btn primary", "");
    done.addEventListener("click", () => { closeModal(); onDone(); });
    updateDone();
    foot.append(done);
  });
}

/* ── enregistrement ──────────────────────────────────────────────────────── */

let saveTimer = null;

function markDirty() {
  $("#save-state").hidden = false;
  clearTimeout(saveTimer);
  // La clé maîtresse est en cache côté Rust, donc une écriture ne coûte plus
  // qu'un chiffrement : quelques millisecondes, quel que soit le profil Argon2.
  // Le délai sert juste à regrouper une rafale de modifications.
  saveTimer = setTimeout(save, 800);
}

async function save() {
  try {
    await invoke("vault_save");
    $("#save-state").hidden = true;
  } catch (e) {
    toast(`Échec de l'enregistrement : ${e}`, "err");
  }
}

/* ── aide intégrée ───────────────────────────────────────────────────────── */

/* Contenu structuré plutôt que du HTML brut : chaque bloc est une donnée, ce qui
 * permettra de le traduire à l'étape localisation sans toucher au rendu. */
const HELP = [
  {
    id: "base",
    title: "L'essentiel",
    blocks: [
      { p: "Un coffre est un fichier .cbv qui contient tous tes mots de passe, chiffrés. Le fichier peut être copié, volé, mis sur une clé USB : sans tes facteurs, il reste illisible." },
      { callout: "La sécurité vient de tes facteurs (ce que tu sais, ce que tu possèdes), jamais du secret du code. Le code peut être public, ton coffre reste sûr." },
    ],
  },
  {
    id: "facteurs",
    title: "Les facteurs",
    blocks: [
      { p: "Tu combines un ou plusieurs facteurs. Tous ceux que tu choisis sont exigés ensemble pour ouvrir." },
      { table: [
        ["Mot de passe", "Ce que tu sais. Le plus important — c'est lui qui pèse le plus."],
        ["PIN", "Ce que tu sais. Jamais seul (trop court)."],
        ["Fichier-clé", "Ce que tu as. Un fichier secret, souvent sur une clé USB."],
        ["Schéma", "Ce que tu sais. Grille 3×3 à 8×8 ; l'ordre et le sens comptent."],
      ]},
      { h4: "Pourquoi le mot de passe reste roi" },
      { p: "Les autres facteurs sont des données (un fichier, une grille) : copiables si quelqu'un y a accès. Le mot de passe est dans ta tête — incopiable. C'est le seul qu'un voleur n'obtient jamais. D'où son caractère obligatoire." },
    ],
  },
  {
    id: "cle",
    title: "Fabrication de la clé",
    blocks: [
      { p: "Tes facteurs sont mélangés puis passés dans Argon2id, une fonction volontairement lente et gourmande en mémoire (jusqu'à 4 Gio par essai). Chaque tentative de devinette coûte ~2 à 15 secondes, ce qui rend le forçage brut irréaliste." },
      { p: "Trois profils : Interactif (~0,5 s), Renforcé (~2 s, défaut), Paranoïaque (~15 s)." },
    ],
  },
  {
    id: "cascade",
    title: "La cascade de chiffrement",
    blocks: [
      { p: "Tes données passent par 1 à 4 couches empilées au choix : AES-256-GCM, XChaCha20-Poly1305, Serpent, Twofish, Camellia. Chaque couche a sa propre clé indépendante : casser une couche ne donne rien sur les autres." },
      { callout: "AES-256 seul est déjà hors de portée. La cascade est une assurance contre l'imprévu, pas une nécessité." },
    ],
  },
  {
    id: "fichier",
    title: "Ce que le fichier révèle",
    blocks: [
      { p: "Seul reste en clair ce dont Argon2 a besoin avant d'avoir une clé : version, coût, sel. Rien de sensible." },
      { p: "Un voleur du fichier ne voit pas : combien de mots de passe, lesquels, quels facteurs, quels algorithmes. Deux coffres de contenus différents ont la même taille sur disque. Toute modification d'un octet est détectée." },
    ],
  },
  {
    id: "quotidien",
    title: "Protections au quotidien",
    blocks: [
      { table: [
        ["Presse-papier", "Un mot de passe copié disparaît après ~12 s (ou au 1er collage)."],
        ["Verrouillage auto", "Le coffre se referme après inactivité ou à la mise en veille."],
        ["Anti-forçage", "Après un échec, l'essai suivant est retardé (1, 2, 4, 8 s…), même après un redémarrage."],
        ["Corbeille", "Supprimer met à la corbeille ; rien n'est détruit sans confirmation."],
        ["Sauvegarde auto", "Une copie horodatée est gardée avant chaque écriture."],
      ]},
    ],
  },
  {
    id: "sauvegarde",
    title: "Sauvegarde et récupération",
    blocks: [
      { calloutWarn: "Le risque le plus probable n'est pas le vol — c'est la perte. Mot de passe oublié, clé USB morte, disque formaté." },
      { ul: [
        "Garde une sauvegarde du fichier .cbv (Import/Export → Sauvegarde chiffrée). Elle s'ouvre avec les mêmes facteurs, partout.",
        "Ne stocke jamais un fichier-clé sur le même disque que ton usage courant. Mets-le sur une clé USB débranchée.",
        "Fais des copies de tes fichiers-clés — ce sont juste 256 octets. Une USB perdue ne doit jamais être ta seule copie.",
      ]},
      { calloutWarn: "Aucune récupération cachée n'existe. Personne, pas même l'auteur, ne peut ouvrir ton coffre sans tes facteurs. Si tu perds tout, c'est perdu. D'où l'importance des copies." },
    ],
  },
  {
    id: "limites",
    title: "Ce qui n'est PAS protégé",
    blocks: [
      { table: [
        ["Vol du fichier seul", "Protégé — inutilisable sans tes facteurs."],
        ["Vol d'une clé USB", "Protégé — inutile sans le mot de passe."],
        ["Perte / panne", "Récupérable si tu as des copies."],
        ["Altération du fichier", "Détectée."],
        ["Machine déjà infectée", "NON — et aucun logiciel local n'y résiste."],
      ]},
      { p: "Si ta machine est compromise au moment où tu ouvres le coffre, l'attaquant lit tes mots de passe directement en mémoire, ou enregistre ta frappe. Ni Cerberus, ni KeePass, ni Bitwarden n'y échappent. La parade est en amont : garder ta machine saine, ou utiliser une machine dédiée hors ligne pour les secrets les plus sensibles." },
      { callout: "En une phrase : Cerberus rend ton coffre inviolable au repos (volé, copié, perdu, il ne livre rien) et honnête sur ses limites. Ta meilleure protection : un mot de passe fort, des sauvegardes, et une machine propre." },
    ],
  },
  {
    id: "licence",
    title: "License and rights",
    blocks: [
      { h4: "Author and copyright holder" },
      { callout: "Cerberus — Copyright © 2026 GLINGONK. GLINGONK exclusively retains the right to authorize the sale, commercial distribution and any other commercial exploitation of Cerberus." },
      { h4: "What the license allows" },
      { p: "Cerberus is distributed under the PolyForm Noncommercial License 1.0.0. For noncommercial purposes, you may inspect, use, study, modify and share the software, including as a fork." },
      { h4: "Redistribution conditions" },
      { ul: [
        "Any redistributed copy or modified version must remain limited to noncommercial purposes.",
        "The PolyForm Noncommercial license and the Copyright 2026 GLINGONK notice must accompany every redistribution.",
        "Selling, paid distribution or commercial exploitation of Cerberus or a fork is prohibited without prior written authorization from GLINGONK.",
      ]},
      { calloutWarn: "This license makes the source code available, but it is not an OSI-approved open-source license because commercial rights are intentionally reserved." },
    ],
  },
];

function renderHelp() {
  const toc = $("#help-toc");
  const body = $("#help-body");
  toc.replaceChildren();

  const content = text("div", "help-content");
  for (const section of HELP) {
    const sec = text("section", "help-section");
    sec.id = `help-${section.id}`;
    sec.append(text("h3", null, section.title));

    for (const block of section.blocks) {
      if (block.p) sec.append(text("p", null, block.p));
      else if (block.h4) sec.append(text("h4", null, block.h4));
      else if (block.callout) {
        const c = text("div", "help-callout");
        c.append(text("p", null, block.callout));
        sec.append(c);
      } else if (block.calloutWarn) {
        const c = text("div", "help-callout warn");
        c.append(text("p", null, block.calloutWarn));
        sec.append(c);
      } else if (block.ul) {
        const ul = document.createElement("ul");
        block.ul.forEach((li) => ul.append(text("li", null, li)));
        sec.append(ul);
      } else if (block.table) {
        const tbl = text("table", "help-table");
        block.table.forEach(([k, v]) => {
          const tr = document.createElement("tr");
          tr.append(text("td", null, k), text("td", null, v));
          tbl.append(tr);
        });
        sec.append(tbl);
      }
    }
    content.append(sec);

    const tab = text("button", null, section.title);
    tab.addEventListener("click", () => {
      $(`#help-${section.id}`).scrollIntoView({ behavior: "smooth", block: "start" });
    });
    toc.append(tab);
  }
  body.replaceChildren(content);
}

function openHelp() {
  renderHelp();
  $("#screen-help").hidden = false;
}
function closeHelp() {
  $("#screen-help").hidden = true;
}

$("#btn-help-lock").addEventListener("click", openHelp);
$("#btn-help").addEventListener("click", openHelp);
$("#btn-help-close").addEventListener("click", closeHelp);

/* ── modales ─────────────────────────────────────────────────────────────── */

function openModal(title, build) {
  $("#modal-title").textContent = title;
  const body = $("#modal-body");
  const foot = $("#modal-foot");
  body.replaceChildren();
  foot.replaceChildren();
  build(body, foot);
  $("#modal-host").hidden = false;
}

function closeModal() {
  $("#modal-host").hidden = true;
  $("#modal-body").replaceChildren();
  $("#modal-foot").replaceChildren();
}

function cancelButton() {
  const b = text("button", "btn ghost", "Annuler");
  b.addEventListener("click", closeModal);
  return b;
}

$$("[data-close]").forEach((el) => el.addEventListener("click", closeModal));

/* ── démarrage ───────────────────────────────────────────────────────────── */

// Le raccourci global Ctrl+Alt+A se déclenche alors que la fenêtre est derrière
// l'application cible : son résultat revient par un évènement, pas par un retour
// d'appel.
/* Verrouillage forcé côté natif (inactivité, session Windows verrouillée, mise
 * en veille) : n'attend pas le prochain sondage pour rafraîchir l'écran. */
listen("vault-locked", () => {
  if ($("#screen-main").classList.contains("active")) {
    toast("Coffre verrouillé", "ok");
    lockVault();
  }
});

listen("autotype-result", (event) => {
  const payload = event.payload ?? {};
  if (payload.ok) toast(`Saisie automatique : ${payload.entry}`, "ok");
  else toast(payload.error ?? "Saisie automatique impossible", "err");
});

/* ── phrase-barrière d'application ────────────────────────────────────────── */

/** Remplit un <select> avec les langues disponibles et le synchronise. */
function fillLangPicker(sel) {
  if (!sel) return;
  sel.innerHTML = "";
  for (const { code, name } of window.i18n.availableLanguages()) {
    const opt = document.createElement("option");
    opt.value = code;
    opt.textContent = name;
    sel.append(opt);
  }
  sel.value = window.i18n.currentLanguage();
  sel.addEventListener("change", () => changeLanguage(sel.value));
}

/** Change la langue partout : UI + sélecteurs + persistance. */
async function changeLanguage(code) {
  window.i18n.setLanguage(code);
  document.querySelectorAll("#lang-picker, #lang-picker-gate").forEach((s) => {
    if (s) s.value = code;
  });
  try { await invoke("set_language", { code }); } catch { /* config pas encore chargée */ }
}

/** Applique une langue au démarrage (avant même la config, pour l'écran gate). */
function bootLanguage() {
  window.i18n?.setLanguage(window.i18n.pickInitial(null));
  fillLangPicker($("#lang-picker"));
  fillLangPicker($("#lang-picker-gate"));
}

/** Applique la langue enregistrée dans la config une fois celle-ci chargée. */
function applyConfigLanguage(language) {
  if (!language || !window.i18n) return;
  window.i18n.setLanguage(language);
  document.querySelectorAll("#lang-picker, #lang-picker-gate").forEach((s) => {
    if (s) s.value = language;
  });
}

async function startupGate() {
  bootLanguage();
  let status;
  try {
    status = await invoke("gate_status");
  } catch {
    return proceedAfterGate(); // pas de config : on continue normalement
  }

  if (!status.gate_set) {
    // Charge la config en clair (coffres récents) et continue.
    try {
      const cfg = await invoke("gate_open", { phrase: null });
      applyConfigLanguage(cfg?.language);
    } catch { /* ignore */ }
    return proceedAfterGate();
  }

  // Une phrase-barrière est active : on la demande avant tout.
  const gate = $("#screen-gate");
  gate.hidden = false;
  gate.classList.add("active");
  $("#screen-lock").classList.remove("active");
  setTimeout(() => $("#gate-phrase").focus(), 50);
}

async function tryGate() {
  const phrase = $("#gate-phrase").value;
  const err = $("#gate-error");
  err.hidden = true;
  try {
    const cfg = await invoke("gate_open", { phrase });
    applyConfigLanguage(cfg?.language);
    $("#gate-phrase").value = "";
    $("#screen-gate").hidden = true;
    $("#screen-gate").classList.remove("active");
    $("#screen-lock").classList.add("active");
    proceedAfterGate();
  } catch (e) {
    err.textContent = humanise(e);
    err.hidden = false;
  }
}

$("#btn-gate-unlock").addEventListener("click", tryGate);
$("#gate-phrase").addEventListener("keydown", (e) => { if (e.key === "Enter") tryGate(); });

/** Après la barrière (ou son absence) : proposer le dernier coffre ouvert. */
async function proceedAfterGate() {
  try {
    const recent = await invoke("recent_vaults");
    if (recent && recent.length > 0) {
      await selectVault(recent[0], { silent: true });
    }
  } catch { /* ignore */ }
  $("#in-password").focus();
}

drawPattern();
updatePatternInfo();
renderShares();
refreshStrength();
startupGate();
