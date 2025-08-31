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
  '/manifest.json',
  'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css'
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        console.log('Opened cache');
        return cache.addAll(urlsToCache);
      })
  );
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
