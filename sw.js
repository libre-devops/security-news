const CACHE_NAME = "mssecnews-v4";

const STATIC_ASSETS = [
  "/",
  "/index.html",
  "/css/styles.css",
  "/js/app.js",
  "/manifest.json",
  "/favicon.ico",
  "/security-libre-devops-black.png",
  "/security-libre-devops-white.png",
  "/icons/icon-192.png",
  "/icons/icon-512.png",
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) =>
      Promise.allSettled(
        STATIC_ASSETS.map((asset) => cache.add(asset))
      )
    )
  );

  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys
          .filter((key) => key !== CACHE_NAME)
          .map((key) => caches.delete(key))
      )
    )
  );

  self.clients.claim();
});

self.addEventListener("fetch", (event) => {
  if (event.request.method !== "GET") {
    return;
  }

  const url = new URL(event.request.url);

  const isFeedData =
    url.pathname.includes("/data/feeds.json") ||
    url.pathname.includes("/data/feed.xml");

  // Always fetch fresh feed content first
  if (isFeedData) {
    event.respondWith(
      fetch(event.request)
        .then((response) => {
          if (response.ok) {
            const clone = response.clone();

            caches.open(CACHE_NAME).then((cache) => {
              cache.put(event.request, clone);
            });
          }

          return response;
        })
        .catch(() => caches.match(event.request))
    );

    return;
  }

  // Cache-first strategy for static site assets
  event.respondWith(
    caches.match(event.request).then((cached) => {
      if (cached) {
        return cached;
      }

      return fetch(event.request)
        .then((response) => {
          if (
            response.ok &&
            url.origin === self.location.origin
          ) {
            const clone = response.clone();

            caches.open(CACHE_NAME).then((cache) => {
              cache.put(event.request, clone);
            });
          }

          return response;
        })
        .catch(() => {
          // Optional offline fallback later
          return caches.match("/index.html");
        });
    })
  );
});