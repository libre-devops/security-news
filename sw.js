"use strict";

// ---------------------------------------------------------------------------
// Cache config
// ---------------------------------------------------------------------------
const CACHE_NAME = "securitynews-v6";

// Maximum age to retain a cached feed response (24 hours).
// Feed entries older than this are evicted on activate.
const FEED_MAX_AGE_MS = 86_400_000;

const STATIC_ASSETS = [
  "/",
  "/index.html",
  "/css/styles.css",
  "/js/app.js",
  "/sw.js",
  "/manifest.json",
  "/favicon.ico",
  "/security-libre-devops-white.png",
  "/icons/icon-192.png",
  "/icons/icon-512.png",
];

const FEED_PATHS = new Set(["/data/feeds.json", "/data/feed.xml"]);

// ---------------------------------------------------------------------------
// Install — pre-cache static assets, then activate immediately
// ---------------------------------------------------------------------------
self.addEventListener("install", (event) => {
  event.waitUntil(
    caches
      .open(CACHE_NAME)
      .then((cache) =>
        Promise.allSettled(STATIC_ASSETS.map((asset) => cache.add(asset)))
      )
      .then(() => self.skipWaiting())
  );
});

// ---------------------------------------------------------------------------
// Activate — evict old caches and stale feed entries
// ---------------------------------------------------------------------------
self.addEventListener("activate", (event) => {
  event.waitUntil(
    Promise.all([
      // Delete any cache belonging to a previous version of this SW.
      caches
        .keys()
        .then((keys) =>
          Promise.all(
            keys
              .filter((key) => key !== CACHE_NAME)
              .map((key) => caches.delete(key))
          )
        ),

      caches.open(CACHE_NAME).then(async (cache) => {
        const requests = await cache.keys();
        const cutoff   = Date.now() - FEED_MAX_AGE_MS;

        await Promise.all(
          requests
            .filter((req) => {
              const path = new URL(req.url).pathname;
              return FEED_PATHS.has(path);
            })
            .map(async (req) => {
              const res  = await cache.match(req);
              const date = new Date(res?.headers.get("date") || 0).getTime();
              if (date < cutoff) {
                return cache.delete(req);
              }
            })
        );
      }),
    ]).then(() => self.clients.claim())
  );
});

// ---------------------------------------------------------------------------
// Fetch — route requests to the appropriate strategy
// ---------------------------------------------------------------------------
self.addEventListener("fetch", (event) => {
  // Only handle GET — let everything else pass through untouched.
  if (event.request.method !== "GET") {
    return;
  }

  const url = new URL(event.request.url);

  // Only intercept same-origin requests.
  if (url.origin !== self.location.origin) {
    return;
  }

  if (FEED_PATHS.has(url.pathname)) {
    event.respondWith(fetchFeed(url));
  } else {
    event.respondWith(fetchStatic(event.request, url));
  }
});

// ---------------------------------------------------------------------------
// Strategy: network-first for feed data
// ---------------------------------------------------------------------------
async function fetchFeed(url) {
  try {
    const response = await fetch(url.pathname, { cache: "no-store" });

    if (response && response.ok) {
      const contentType = response.headers.get("content-type") || "";
      const isExpectedType =
        (url.pathname.endsWith(".json") && contentType.includes("application/json")) ||
        (url.pathname.endsWith(".xml")  && (contentType.includes("xml") || contentType.includes("text/plain")));

      if (isExpectedType) {
        const clone = response.clone();
        caches
          .open(CACHE_NAME)
          .then((cache) => cache.put(url.pathname, clone))
          .catch((err) => console.warn("[SW] Feed cache write failed:", err));
      } else {
        console.warn("[SW] Feed response had unexpected Content-Type — not caching:", contentType);
      }
    }

    return response;
  } catch {
    // Network failed — serve stale cached copy if available.
    const cached = await caches.match(url.pathname);
    return cached || Response.error();
  }
}

// ---------------------------------------------------------------------------
// Strategy: cache-first for static assets
// ---------------------------------------------------------------------------
async function fetchStatic(request, url) {
  const cached = await caches.match(url.pathname);
  if (cached) {
    return cached;
  }

  try {
    const response = await fetch(request);

    if (response && response.ok) {
      const clone = response.clone();
      caches
        .open(CACHE_NAME)
        .then((cache) => cache.put(url.pathname, clone))
        .catch((err) => console.warn("[SW] Static cache write failed:", err));
    }

    return response;
  } catch {
    const fallback = await caches.match("/index.html");
    return fallback || Response.error();
  }
}