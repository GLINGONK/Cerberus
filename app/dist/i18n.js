/* Cerberus — localisation engine (i18n).
 *
 * Dependency-free. Dictionaries are `lang/<code>.js` files that call
 * `registerLang(code, name, dict)`. Adding a language = drop such a file and
 * include it in index.html — no other change.
 *
 * `t(key, fallback)` returns the translation in the active language; if the key
 * is missing (incomplete language) it falls back to English, then to `fallback`.
 * So a partial translation never shows a raw key or a blank.
 */

(function () {
  const langs = {}; // code -> { name, dict }
  let current = "en";

  window.registerLang = function (code, name, dict) {
    langs[code] = { name, dict };
  };

  /** Simple interpolation: t("x", "…", {n: 3}) replaces {n}. */
  function interpolate(str, params) {
    if (!params) return str;
    return str.replace(/\{(\w+)\}/g, (m, k) => (k in params ? params[k] : m));
  }

  function t(key, fallback, params) {
    const inCurrent = langs[current]?.dict?.[key];
    const inEnglish = langs["en"]?.dict?.[key];
    const value = inCurrent ?? inEnglish ?? fallback ?? key;
    return interpolate(value, params);
  }

  function availableLanguages() {
    return Object.entries(langs).map(([code, v]) => ({ code, name: v.name }));
  }

  function setLanguage(code) {
    if (langs[code]) current = code;
    applyStatic();
    document.documentElement.lang = current;
    // Writing direction for right-to-left languages.
    const rtl = ["ar", "he", "fa", "ur"];
    document.documentElement.dir = rtl.includes(current) ? "rtl" : "ltr";
  }

  function currentLanguage() {
    return current;
  }

  /** Pick the best language: saved preference, otherwise the system one. */
  function pickInitial(preferred) {
    if (preferred && langs[preferred]) return preferred;
    const sys = (navigator.language || "en").slice(0, 2).toLowerCase();
    return langs[sys] ? sys : "en";
  }

  /** Translate every element carrying data-i18n* attributes. */
  function applyStatic() {
    document.querySelectorAll("[data-i18n]").forEach((el) => {
      el.textContent = t(el.getAttribute("data-i18n"), el.textContent);
    });
    document.querySelectorAll("[data-i18n-ph]").forEach((el) => {
      el.setAttribute("placeholder", t(el.getAttribute("data-i18n-ph"), el.getAttribute("placeholder")));
    });
    document.querySelectorAll("[data-i18n-title]").forEach((el) => {
      el.setAttribute("title", t(el.getAttribute("data-i18n-title"), el.getAttribute("title")));
    });
  }

  window.i18n = { t, setLanguage, currentLanguage, availableLanguages, pickInitial, applyStatic };
})();
