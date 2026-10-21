// Project Monitor Control - offline shell (GitHub API calls are never cached) - Created by Planner Ahmed Ghazy
const CACHE = 'pm-ctrl-v4';
const SHELL = ['./', 'index.html', 'core.js', 'manifest.webmanifest', 'icon-192.png', 'icon-512.png'];
self.addEventListener('install', (e) => { e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting())); });
self.addEventListener('activate', (e) => {
  e.waitUntil(caches.keys().then((ks) => Promise.all(ks.filter((k) => k !== CACHE).map((k) => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', (e) => {
  const u = new URL(e.request.url);
  if (e.request.method !== 'GET' || u.origin !== self.location.origin) return;
  // network first (new versions arrive at once), the cached copy when offline
  e.respondWith(fetch(e.request).then((r) => {
    const cp = r.clone(); caches.open(CACHE).then((c) => c.put(e.request, cp)); return r;
  }).catch(() => caches.match(e.request).then((m) => m || caches.match('index.html'))));
});
