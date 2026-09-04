// Reader service worker.
// The app shell is versioned per build; books and fonts live in a persistent cache
// so a rebuild never evicts a book you've already opened.
const VERSION = 'shell-__VERSION__';
const BOOKS = 'reader-books-v1';
const SHELL = ['./', './index.html', './app.css', './app.js', './manifest.webmanifest', './meta.json', './library.bin', './icon-192.png', './icon-512.png'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(VERSION).then(c => c.addAll(SHELL)).then(() => self.skipWaiting()));
});
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys()
    .then(keys => Promise.all(keys.filter(k => k.startsWith('shell-') && k !== VERSION).map(k => caches.delete(k))))
    .then(() => self.clients.claim()));
});

function staleWhileRevalidate(req, cacheName, key) {
  return caches.open(cacheName).then(c => c.match(key || req).then(hit => {
    const net = fetch(req).then(r => { if (r.ok || r.type === 'opaque') c.put(key || req, r.clone()); return r; }).catch(() => hit);
    return hit || net;
  }));
}
function networkFirst(req, cacheName) {
  return caches.open(cacheName).then(c => fetch(req).then(r => { if (r.ok) c.put(req, r.clone()); return r; })
    .catch(() => c.match(req).then(hit => hit || Response.error())));
}

self.addEventListener('fetch', e => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (req.mode === 'navigate') { e.respondWith(staleWhileRevalidate(req, VERSION, './index.html')); return; }
  if (url.origin === location.origin) {
    if (url.pathname.endsWith('/library.bin') || url.pathname.endsWith('/meta.json')) { e.respondWith(networkFirst(req, VERSION)); return; }
    if (url.pathname.includes('/books/')) { e.respondWith(staleWhileRevalidate(req, BOOKS)); return; }
    e.respondWith(staleWhileRevalidate(req, VERSION)); return;
  }
  if (url.hostname.endsWith('gstatic.com') || url.hostname.endsWith('googleapis.com')) {
    e.respondWith(staleWhileRevalidate(req, BOOKS));
  }
});
