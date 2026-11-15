// Switch 2 payload host - service worker precache.
//
// v3: network-first for pages/scripts. Earlier builds cached index.html and main.js and then
// served them forever, so a console kept running the first version it ever saw.

const CACHE_NAME = "sw2-host-v13";
const ASSETS = [
  "./",
  "./index.html",
  "./main.js",
  "./cache.html",
  "./worker.js",
  "./switch2.bin",
  "./switch2.appcache",
  "./patches/switch2_bin.cpp",
  "./patches/switch2_bin.py",
  "./patches/build.ps1",
];

async function notify(clients, payload) {
  for (const c of clients) c.postMessage(payload);
}

async function precache({ force = false } = {}) {
  const cache = await caches.open(CACHE_NAME);
  const clients = await self.clients.matchAll({ includeUncontrolled: true });
  let done = 0;

  for (const url of ASSETS) {
    let cached = force ? null : await cache.match(url, { ignoreSearch: true });
    if (!cached) {
      try {
        const res = await fetch(url, { cache: "reload" });
        if (res.ok) {
          await cache.put(url, res.clone());
          cached = res;
        }
      } catch {
        // Missing optional asset: report and move on.
      }
    }
    done += 1;
    await notify(clients, { type: "sw2-progress", done, total: ASSETS.length, url });
  }
  return done;
}

self.addEventListener("install", (event) => {
  event.waitUntil(
    (async () => {
      await precache();
      await self.skipWaiting();
    })()
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    (async () => {
      const keys = await caches.keys();
      await Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)));
      await self.clients.claim();
    })()
  );
});

self.addEventListener("message", (event) => {
  const data = event.data || {};
  if (data.type !== "sw2-prefetch") return;
  event.waitUntil(
    (async () => {
      await precache({ force: !!data.force });
      const clients = await self.clients.matchAll({ includeUncontrolled: true });
      await notify(clients, { type: "sw2-done", total: ASSETS.length });
    })()
  );
});

// Everything is network-first now. Offline still works: a failed fetch falls back to cache.
// The old cache-first rule is what kept serving a 192-byte switch2.bin after a rebuild.
function isFreshRequired() {
  return true;
}

self.addEventListener("fetch", (event) => {
  if (event.request.method !== "GET") return;
  const url = new URL(event.request.url);
  if (url.origin !== self.location.origin) return;
  if (url.pathname.startsWith("/netcat/") || url.pathname === "/version") return;

  event.respondWith(
    (async () => {
      const cache = await caches.open(CACHE_NAME);

      if (isFreshRequired(event.request)) {
        try {
          const fresh = await fetch(event.request, { cache: "no-store" });
          if (fresh.ok) cache.put(event.request, fresh.clone());
          return fresh;
        } catch {
          return (await cache.match(event.request, { ignoreSearch: true })) || Response.error();
        }
      }

      const cached = await cache.match(event.request, { ignoreSearch: true });
      if (cached) return cached;
      try {
        const fresh = await fetch(event.request);
        if (fresh.ok) cache.put(event.request, fresh.clone());
        return fresh;
      } catch {
        return Response.error();
      }
    })()
  );
});
