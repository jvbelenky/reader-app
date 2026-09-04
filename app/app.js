(function () {
  'use strict';
  const $ = s => document.querySelector(s);
  const root = document.documentElement;
  const store = {
    get(k) { try { return JSON.parse(localStorage.getItem(k)); } catch (e) { return null; } },
    set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch (e) {} },
  };
  try { history.scrollRestoration = 'manual'; } catch (e) {}
  let toastT;

  // ------------------------------------------------------------ settings
  const DEF = { size: 19, lh: 1.62, font: 'literata', mode: 'auto', resume: 'last' };
  const settings = Object.assign({}, DEF, store.get('reader.settings.v1') || {});
  function applySettings() {
    root.style.setProperty('--fs', settings.size + 'px');
    root.style.setProperty('--lh', settings.lh);
    if (settings.font === 'literata') root.removeAttribute('data-font'); else root.setAttribute('data-font', settings.font);
    if (settings.mode === 'auto') root.removeAttribute('data-mode'); else root.setAttribute('data-mode', settings.mode);
    $('#sizeVal').textContent = settings.size + ' px';
    document.querySelectorAll('[data-set]').forEach(b => {
      const [k, v] = b.dataset.set.split(':');
      b.setAttribute('aria-pressed', String(settings[k]) === v ? 'true' : 'false');
    });
    const m = document.querySelector('meta[name=theme-color]');
    if (m) m.content = getComputedStyle(root).getPropertyValue('--bg').trim();
  }
  applySettings();

  // ------------------------------------------------------------ crypto + lock
  // Content is AES-256-GCM encrypted at build time. The key derived from the
  // passphrase is kept in IndexedDB as a non-extractable CryptoKey.
  const enc = new TextEncoder(), dec = new TextDecoder();
  let key = null, meta = null;
  function idb() {
    return new Promise((res, rej) => {
      const r = indexedDB.open('reader-keys', 1);
      r.onupgradeneeded = () => r.result.createObjectStore('k');
      r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error);
    });
  }
  async function idbGet(k) { const db = await idb(); return new Promise((res, rej) => { const t = db.transaction('k').objectStore('k').get(k); t.onsuccess = () => res(t.result || null); t.onerror = () => rej(t.error); }); }
  async function idbSet(k, v) { const db = await idb(); return new Promise((res, rej) => { const t = db.transaction('k', 'readwrite'); t.objectStore('k').put(v, k); t.oncomplete = res; t.onerror = () => rej(t.error); }); }
  async function idbDel(k) { const db = await idb(); return new Promise((res, rej) => { const t = db.transaction('k', 'readwrite'); t.objectStore('k').delete(k); t.oncomplete = res; t.onerror = () => rej(t.error); }); }
  const b64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  async function deriveKey(pass) {
    const base = await crypto.subtle.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: b64(meta.salt), iterations: meta.iter, hash: 'SHA-256' }, base,
      { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  }
  async function decrypt(buf, aad) {
    const u = new Uint8Array(buf);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: u.slice(0, 12), additionalData: enc.encode(aad) }, key, u.slice(12));
    return dec.decode(pt);
  }
  async function keyWorks(k) {
    try { key = k; await decrypt(b64(meta.check), 'check'); return true; } catch (e) { key = null; return false; }
  }
  async function loadMeta() {
    try { const r = await fetch('meta.json', { cache: 'no-cache' }); if (r.ok) meta = await r.json(); } catch (e) {}
    if (!meta) meta = store.get('reader.meta') || null;
    if (meta) store.set('reader.meta', meta);   // salt + check value only; nothing secret
    return meta;
  }
  const lock = $('#lock');
  function showLock() {
    shelf.hidden = true; reader.hidden = true; lock.hidden = false;
    document.title = 'Reader';
    setTimeout(() => $('#pass').focus(), 50);
    return new Promise(res => { lockResolve = res; });
  }
  let lockResolve = null;
  $('#lockForm').addEventListener('submit', async e => {
    e.preventDefault();
    const btn = $('#unlock'), err = $('#lockErr');
    btn.disabled = true; err.hidden = true; btn.textContent = 'Unlocking…';
    try {
      const k = await deriveKey($('#pass').value);
      if (await keyWorks(k)) {
        await idbSet('main', k);
        $('#pass').value = '';
        lock.hidden = true;
        if (lockResolve) lockResolve();
      } else {
        err.textContent = 'That passphrase doesn\'t match. Try again.'; err.hidden = false;
      }
    } catch (ex) {
      err.textContent = 'Couldn\'t unlock: ' + (ex.message || ex); err.hidden = false;
    }
    btn.disabled = false; btn.textContent = 'Unlock';
  });
  $('#lockBtn').addEventListener('click', async () => {
    await idbDel('main'); key = null;
    closeSheets();
    location.href = location.pathname;
  });

  // ------------------------------------------------------------ library
  let library = { books: [] };
  const shelf = $('#shelf'), reader = $('#reader'), book = $('#book');

  async function loadLibrary() {
    try {
      const r = await fetch('library.bin', { cache: 'no-cache' });
      if (r.ok) library = JSON.parse(await decrypt(await r.arrayBuffer(), 'library'));
    } catch (e) { /* offline with nothing cached: empty shelf */ }
    return library;
  }
  function posOf(id) { return store.get('pos:' + id) || null; }
  function fmtAgo(t) {
    const d = (Date.now() - t) / 1000;
    if (d < 60) return 'just now';
    if (d < 3600) return Math.round(d / 60) + ' min ago';
    if (d < 86400) return Math.round(d / 3600) + ' h ago';
    if (d < 86400 * 14) return Math.round(d / 86400) + ' d ago';
    return new Date(t).toLocaleDateString();
  }
  function renderShelf() {
    const list = $('#shelfList'); list.innerHTML = '';
    const books = library.books.slice().map(b => ({ ...b, pos: posOf(b.id) }));
    books.sort((a, b) => ((b.pos && b.pos.t) || 0) - ((a.pos && a.pos.t) || 0) || a.title.localeCompare(b.title));
    $('#shelfEmpty').hidden = books.length > 0;
    const lastId = store.get('reader.last');
    books.forEach(b => {
      const li = document.createElement('li');
      if (b.id === lastId) li.className = 'cont';
      const pct = b.pos ? Math.round(b.pos.pct || 0) : 0;
      const mins = Math.max(1, Math.round(b.words / 230));
      const left = b.pos ? Math.max(0, Math.round(mins * (1 - pct / 100))) : mins;
      li.innerHTML =
        (b.id === lastId ? '<span class="tag">Continue reading</span>' : '') +
        '<span class="t"></span>' + (b.author ? '<span class="a"></span>' : '') +
        '<span class="meta"><span class="bar"><i></i></span><span class="p"></span><span class="w"></span></span>' +
        '<span class="go"><svg viewBox="0 0 24 24"><path d="M9 5l7 7-7 7"/></svg></span>';
      li.querySelector('.t').textContent = b.title;
      if (b.author) li.querySelector('.a').textContent = b.author;
      li.querySelector('.bar i').style.width = pct + '%';
      li.querySelector('.p').textContent = b.pos ? pct + '% · ' + fmtAgo(b.pos.t) : 'Not started';
      li.querySelector('.w').textContent = (left >= 60 ? Math.round(left / 60) + ' h' : left + ' min') + (b.pos ? ' left' : '');
      li.addEventListener('click', () => openBook(b.id, true));
      list.appendChild(li);
    });
    const n = books.length;
    $('#shelfFoot').textContent = n ? n + (n === 1 ? ' book' : ' books') + ' · updated ' + new Date((library.built || 0) * 1000).toLocaleDateString() : '';
  }
  function showShelf(push) {
    closeBook();
    renderShelf();
    reader.hidden = true; shelf.hidden = false;
    document.title = 'Reader';
    window.scrollTo(0, 0);
    if (push) history.pushState({ v: 'shelf' }, '', location.pathname);
  }

  // ------------------------------------------------------------ reader
  let cur = null;   // { id, meta, nodes, chapters, tops, measuredH, last, ro, ac }
  const bar = $('#bar'), prog = $('#progress i'), where = $('#where');
  const barH = () => bar.offsetHeight;

  async function openBook(id, push) {
    const meta = library.books.find(b => b.id === id);
    if (!meta) { showShelf(false); return; }
    closeBook();
    shelf.hidden = true; reader.hidden = false;
    $('#barTitle').textContent = meta.title; where.textContent = '';
    document.title = meta.title;
    book.innerHTML = '<p class="loading">Opening…</p>';
    if (push) history.pushState({ v: 'book', id }, '', '?b=' + encodeURIComponent(id));
    let html;
    try {
      const r = await fetch('books/' + id + '.bin');
      if (!r.ok) throw new Error(r.status);
      html = await decrypt(await r.arrayBuffer(), 'book:' + id);
    } catch (e) {
      book.innerHTML = '<p class="loading">This book isn\'t available offline yet. Open it once while online and it will be.</p>';
      return;
    }
    book.innerHTML = html;
    const nodes = Array.from(book.querySelectorAll('h2, p'));
    const c = cur = { id, meta, nodes, chapters: nodes.filter(n => n.tagName === 'H2'), tops: [], measuredH: 0, ac: new AbortController() };
    let last = posOf(id) || { i: 0, f: 0 };
    if (!nodes[last.i]) last = { i: 0, f: 0 };
    c.last = last;
    store.set('reader.last', id);

    const sig = { signal: c.ac.signal, passive: true };
    let ticking = false, lastY = window.scrollY, saveT = 0;
    window.addEventListener('scroll', () => {
      if (ticking) return; ticking = true;
      requestAnimationFrame(() => {
        ticking = false;
        if (cur !== c) return;
        const y = window.scrollY;
        if (y > lastY + 6 && y > barH()) bar.classList.add('hidden'); else if (y < lastY - 6) bar.classList.remove('hidden');
        lastY = y;
        if (book.offsetHeight !== c.measuredH) return;   // reflow in progress; ResizeObserver re-anchors
        c.last = currentAnchor(); paint();
        clearTimeout(saveT); saveT = setTimeout(savePos, 150);
      });
    }, sig);
    ['pagehide', 'visibilitychange', 'beforeunload'].forEach(ev => window.addEventListener(ev, () => {
      if (cur !== c) return;
      if (book.offsetHeight === c.measuredH) c.last = currentAnchor();
      savePos();
    }, { signal: c.ac.signal }));
    c.ro = new ResizeObserver(() => { if (cur !== c) return; measure(); scrollToAnchor(c.last); paint(); });
    c.ro.observe(book);

    bar.classList.remove('hidden');
    measure(); scrollToAnchor(last); paint();
    if (last.i > 0) toast('Resumed at ' + where.textContent);
    if (document.fonts && document.fonts.ready) document.fonts.ready.then(() => { if (cur === c) { measure(); scrollToAnchor(c.last); } });
  }

  function closeBook() {
    if (!cur) return;
    if (book.offsetHeight === cur.measuredH) cur.last = currentAnchor();
    savePos();
    cur.ac.abort(); if (cur.ro) cur.ro.disconnect();
    cur = null; book.innerHTML = '';
    closeSheets();
  }

  function measure() { cur.tops = cur.nodes.map(n => n.offsetTop); cur.measuredH = book.offsetHeight; }
  function anchorAt(y) {
    const { tops, nodes } = cur;
    let lo = 0, hi = tops.length - 1;
    while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (tops[mid] <= y) lo = mid; else hi = mid - 1; }
    const h = nodes[lo].offsetHeight || 1;
    return { i: lo, f: Math.max(0, (y - tops[lo]) / h) };
  }
  function currentAnchor() { return anchorAt(window.scrollY + barH() + 1); }
  function yOf(a) { return cur.tops[a.i] + a.f * cur.nodes[a.i].offsetHeight; }
  function scrollToAnchor(a) { window.scrollTo(0, Math.max(0, Math.round(yOf(a) - barH() - 1))); }
  function pct() { const max = document.documentElement.scrollHeight - window.innerHeight; return max > 0 ? Math.min(100, Math.max(0, window.scrollY / max * 100)) : 0; }
  function savePos() { if (!cur) return; store.set('pos:' + cur.id, { i: cur.last.i, f: cur.last.f, pct: pct(), t: Date.now() }); }
  function chapterOf(i) { let c = null; for (const h of cur.chapters) { if (cur.nodes.indexOf(h) <= i) c = h; else break; } return c; }
  function paint() {
    const p = pct(); prog.style.width = p.toFixed(2) + '%';
    const ch = chapterOf(cur.last.i);
    where.textContent = (ch ? ch.parentElement.dataset.title + ' · ' : '') + Math.round(p) + '%';
  }

  // ------------------------------------------------------------ sheets
  const scrim = $('#scrim');
  function openSheet(id) { closeSheets(); $(id).classList.add('on'); scrim.classList.add('on'); bar.classList.remove('hidden'); }
  function closeSheets() { document.querySelectorAll('.sheet.on').forEach(s => s.classList.remove('on')); scrim.classList.remove('on'); }
  scrim.addEventListener('click', closeSheets);
  document.addEventListener('keydown', e => { if (e.key === 'Escape') closeSheets(); });
  $('#btnToc').addEventListener('click', () => { buildToc(); openSheet('#toc'); });
  $('#btnSet').addEventListener('click', () => openSheet('#set'));
  $('#shelfSet').addEventListener('click', () => openSheet('#set'));
  $('#btnBack').addEventListener('click', () => showShelf(true));
  book.addEventListener('click', () => { if (getSelection().toString()) return; bar.classList.toggle('hidden'); });

  function buildToc() {
    const ol = $('#toc ol'); ol.innerHTML = '';
    if (!cur) return;
    const total = document.documentElement.scrollHeight;
    const now = chapterOf(cur.last.i);
    cur.chapters.forEach(h => {
      const li = document.createElement('li');
      if (h === now) li.className = 'cur';
      li.innerHTML = '<span class="n"></span><span class="pct"></span>';
      li.querySelector('.n').textContent = h.parentElement.dataset.title;
      li.querySelector('.pct').textContent = Math.round(h.offsetTop / total * 100) + '%';
      li.addEventListener('click', () => { closeSheets(); scrollToAnchor({ i: cur.nodes.indexOf(h), f: 0 }); });
      ol.appendChild(li);
    });
    if (!cur.chapters.length) ol.innerHTML = '<li><span class="n" style="color:var(--muted)">No chapter headings found</span></li>';
  }

  function changeWith(fn) {
    const a = cur && cur.last;
    fn(); applySettings(); store.set('reader.settings.v1', settings);
    if (cur) { measure(); scrollToAnchor(a); paint(); }
  }
  $('#sizeDn').addEventListener('click', () => changeWith(() => { settings.size = Math.max(14, settings.size - 1); }));
  $('#sizeUp').addEventListener('click', () => changeWith(() => { settings.size = Math.min(34, settings.size + 1); }));
  document.querySelectorAll('[data-set]').forEach(b => b.addEventListener('click', () => changeWith(() => {
    const [k, v] = b.dataset.set.split(':'); settings[k] = (k === 'lh') ? parseFloat(v) : v;
  })));

  function toast(msg) { const t = $('#toast'); t.textContent = msg; t.classList.add('on'); clearTimeout(toastT); toastT = setTimeout(() => t.classList.remove('on'), 2600); }

  // ------------------------------------------------------------ routing
  window.addEventListener('popstate', e => {
    const id = new URLSearchParams(location.search).get('b');
    if (id) openBook(id, false); else showShelf(false);
  });
  if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => navigator.serviceWorker.register('./sw.js').catch(() => {}));
  }

  (async () => {
    if (!(window.crypto && crypto.subtle)) {
      lock.hidden = false; $('#lockForm').innerHTML = '<h1>Reader</h1><p class="lock-hint">This browser can\'t decrypt the library. Open the site over HTTPS in a current browser.</p>';
      return;
    }
    if (!(await loadMeta())) {
      lock.hidden = false; $('#lockForm').innerHTML = '<h1>Reader</h1><p class="lock-hint">Couldn\'t reach the library, and nothing is cached yet. Connect to the internet and reload.</p>';
      return;
    }
    const saved = await idbGet('main').catch(() => null);
    if (!(saved && await keyWorks(saved))) await showLock();
    await loadLibrary();
    const want = new URLSearchParams(location.search).get('b');
    const lastId = store.get('reader.last');
    if (want && library.books.some(b => b.id === want)) {
      history.replaceState({ v: 'book', id: want }, '', '?b=' + encodeURIComponent(want));
      openBook(want, false);
    } else if (settings.resume === 'last' && lastId && library.books.some(b => b.id === lastId)) {
      history.replaceState({ v: 'shelf' }, '', location.pathname);
      openBook(lastId, true);
    } else {
      history.replaceState({ v: 'shelf' }, '', location.pathname);
      showShelf(false);
    }
  })();
})();
