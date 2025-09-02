const CACHE_NAME = 'ops-online-support-cache-v1';
const urlsToCache = [
  '/',
  '/index.html',
  '/contact-center.html',
  '/it-support.html',
  '/professional-services.html',
  '/css/style.css',
  '/css/utility.css',
  '/js/main.js',
  '/js/langtheme.js',
  '/js/theme-init.js',
  '/js/utils.js',
  '/js/search.js',
  '/js/search-index.json',
  '/js/antibot.js',
  '/fabs/js/cojoin.js',
  '/fabs/js/fab-handlers.js',
  '/fabs/js/chattia.js',
  '/cojoinlistener.js',
  '/manifest.json'
];

self.addEventListener('install', event => {
  event.waitUntil((async () => {
    const cache = await caches.open(CACHE_NAME);
    for (const url of urlsToCache) {
      try {
        const response = await fetch(url, { cache: 'no-cache' });
        if (response.ok) {
          await cache.put(url, response);
        } else {
          console.warn('SW install: skipping', url, response.status);
        }
      } catch (err) {
        console.warn('SW install: failed to cache', url, err);
      }
    }
  })());
});

self.addEventListener('fetch', event => {
  event.respondWith(
    caches.match(event.request)
      .then(response => {
        if (response) {
          return response;
        }
        return fetch(event.request);
      })
  );
});

self.addEventListener('activate', event => {
  const cacheWhitelist = [CACHE_NAME];
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.map(cacheName => {
          if (cacheWhitelist.indexOf(cacheName) === -1) {
            return caches.delete(cacheName);
          }
        })
      );
    })
  );
});
