// The service worker. It exists to receive push and for nothing else.
//
// docs/adr/0002 is the decision and bin/check enforces it: there is
// deliberately NO fetch event listener here and nothing touches the Cache
// Storage API. A service worker only intercepts a request if it registers for
// the fetch event, so with none, every page load and every asset goes to the
// network exactly as it did before this file existed.
//
// That is what keeps a stale asset IMPOSSIBLE rather than merely unlikely,
// which is the property #3's diagnosis relied on: a CSS fix went up and was
// simply there, with no round spent asking whether the phone was showing the
// old stylesheet.
//
// Keep this file short enough to read in one sitting. A service worker
// outlives the page that installed it and cannot easily be inspected by the
// person running it, so it is the wrong place for anything clever.

self.addEventListener('push', (event) => {
  // A push with no payload is still worth showing. The send path encrypts a
  // body, but a delivery that loses it should degrade to "something happened,
  // go and look" rather than to silence.
  let title = 'Retro';
  let body = 'A game server changed state.';
  let tag = 'retro';
  if (event.data) {
    try {
      const d = event.data.json();
      if (d.title) { title = d.title; }
      if (d.body) { body = d.body; }
      // Same tag replaces an earlier notification instead of stacking. A
      // server that flaps should not leave forty entries on the lock screen.
      if (d.tag) { tag = d.tag; }
    } catch (e) {
      body = event.data.text() || body;
    }
  }
  event.waitUntil(self.registration.showNotification(title, {
    body: body,
    tag: tag,
    icon: '/pwa/icon-192.png',
    badge: '/pwa/icon-192.png',
  }));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  // Focus the app if it is already open rather than opening a second copy.
  event.waitUntil((async () => {
    const all = await self.clients.matchAll({
      type: 'window', includeUncontrolled: true,
    });
    for (const c of all) {
      if ('focus' in c) { return c.focus(); }
    }
    if (self.clients.openWindow) { return self.clients.openWindow('/'); }
  })());
});

// Take over as soon as installed rather than waiting for every tab to close.
// Nothing here serves content, so there is no old-version-still-serving
// hazard to be careful about -- the only thing being replaced is which copy
// of this file handles the next push.
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));
