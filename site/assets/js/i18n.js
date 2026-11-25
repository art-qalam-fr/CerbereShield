// i18n Cerbere site — FR/EN/DE/ES
// Usage : data-i18n="cle" sur les éléments, dictionnaires dans assets/i18n/
(function () {
  const LANGS = ['fr', 'en', 'de', 'es'];
  const LABELS = { fr: 'FR', en: 'EN', de: 'DE', es: 'ES' };
  let dict = {};
  let lang = 'fr';

  function detect() {
    const saved = localStorage.getItem('cerbere_lang');
    if (saved && LANGS.includes(saved)) return saved;
    const nav = (navigator.language || 'fr').slice(0, 2).toLowerCase();
    return LANGS.includes(nav) ? nav : 'fr';
  }

  function apply(d) {
    dict = d;
    document.documentElement.lang = lang;
    document.querySelectorAll('[data-i18n]').forEach((el) => {
      const k = el.getAttribute('data-i18n');
      if (d[k] !== undefined) el.innerHTML = d[k];
    });
    const mt = document.querySelector('meta[name="description"]');
    const tk = document.documentElement.getAttribute('data-i18n-title') || 'meta.title';
    const dk = document.documentElement.getAttribute('data-i18n-desc') || 'meta.desc';
    if (mt && d[dk]) mt.setAttribute('content', d[dk]);
    if (d[tk]) document.title = d[tk];
    document.dispatchEvent(new Event('i18n:ready'));
  }

  function load(l) {
    fetch('assets/i18n/' + l + '.json')
      .then((r) => { if (!r.ok) throw 0; return r.json(); })
      .then(apply)
      .catch(() => { if (l !== 'fr') load('fr'); });
  }

  function setLang(l) {
    if (!LANGS.includes(l) || l === lang) { closeMenu(); return; }
    lang = l;
    localStorage.setItem('cerbere_lang', l);
    load(l);
    markActive();
  }

  // ---------- Sélecteur de langue ----------
  let menuEl = null;
  function closeMenu() { if (menuEl) menuEl.classList.remove('open'); }
  function markActive() {
    if (!menuEl) return;
    menuEl.querySelectorAll('.lang-btn').forEach((b) => {
      b.classList.toggle('active', b.dataset.lang === lang);
    });
    menuEl.querySelector('.lang-current').textContent = LABELS[lang];
  }

  function injectStyle() {
    const s = document.createElement('style');
    s.textContent =
      '.lang-picker{position:relative;font-size:.85rem}' +
      '.lang-picker.fixed{position:fixed;top:14px;right:16px;z-index:100}' +
      '.lang-toggle{display:flex;align-items:center;gap:.35rem;background:rgba(15,23,42,.6);' +
      'border:1px solid var(--line,#334155);color:var(--muted,#94a3b8);border-radius:999px;' +
      'padding:.3rem .7rem;cursor:pointer;font:inherit}' +
      '.lang-toggle:hover{color:var(--text-strong,#f1f5f9);border-color:#475569}' +
      '.lang-menu{position:absolute;right:0;top:calc(100% + 6px);background:#111c33;' +
      'border:1px solid #334155;border-radius:10px;padding:.3rem;display:none;min-width:64px;z-index:101}' +
      '.lang-picker.open .lang-menu{display:block}' +
      '.lang-btn{display:block;width:100%;background:none;border:none;color:#94a3b8;' +
      'padding:.4rem .8rem;text-align:center;cursor:pointer;border-radius:7px;font:inherit}' +
      '.lang-btn:hover{background:#1e293b;color:#f1f5f9}' +
      '.lang-btn.active{color:#60a5fa;font-weight:600}';
    document.head.appendChild(s);
  }

  function buildPicker() {
    const host = document.querySelector('.nav');
    menuEl = document.createElement('div');
    menuEl.className = 'lang-picker' + (host ? '' : ' fixed');
    let html = '<button class="lang-toggle" type="button" aria-label="Language">' +
      '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">' +
      '<circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15.3 15.3 0 0 1 0 20 15.3 15.3 0 0 1 0-20z"/></svg>' +
      '<span class="lang-current">' + LABELS[lang] + '</span></button><div class="lang-menu">';
    LANGS.forEach((l) => {
      html += '<button class="lang-btn' + (l === lang ? ' active' : '') + '" data-lang="' + l + '">' + LABELS[l] + '</button>';
    });
    menuEl.innerHTML = html + '</div>';
    (host || document.body).appendChild(menuEl);
    menuEl.querySelector('.lang-toggle').addEventListener('click', (e) => {
      e.stopPropagation();
      menuEl.classList.toggle('open');
    });
    menuEl.querySelectorAll('.lang-btn').forEach((b) => {
      b.addEventListener('click', (e) => { e.stopPropagation(); setLang(b.dataset.lang); });
    });
    document.addEventListener('click', closeMenu);
  }

  window.__siteI18n = {
    get dict() { return dict; },
    get lang() { return lang; },
    t: (k, f) => (dict[k] !== undefined ? dict[k] : (f !== undefined ? f : k)),
  };

  lang = detect();
  injectStyle();
  buildPicker();
  if (lang !== 'fr') load(lang);
  else window.__siteI18n.ready = Promise.resolve();
})();
