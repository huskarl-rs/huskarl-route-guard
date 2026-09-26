const express = require('express');

const profile = process.env.ROUTING_PROFILE;
if (!['Default', 'Sensitive', 'Insensitive'].includes(profile)) {
  throw new Error(`Unknown routing profile: ${profile}`);
}

const app = express();
const router = profile === 'Default' ? express.Router() : express.Router({
  caseSensitive: profile === 'Sensitive',
  strict: true,
});

// Explicitly accept both trailing-slash spellings for these exception routes.
router.get(['/exact.txt', '/exact.txt/'], (_request, response) => {
  response.set('X-Route-ID', 'exact').type('text/plain').send('exact');
});
router.get(['/foo/:segment/bar', '/foo/:segment/bar/'], (_request, response) => {
  response.set('X-Route-ID', 'parameterized').type('text/plain').send('parameterized');
});

// These are route IDs. The harness independently assigns policies to each ID.
// Express uses registration order, so register the specific child first.
for (const [prefix, routeId] of [
  ['/files/private', 'private'],
  ['/files', 'files'],
  ['/admin', 'admin'],
]) {
  router.get([prefix, `${prefix}/`, `${prefix}/*rest`], (_request, response) => {
    response.set('X-Route-ID', routeId).type('text/plain').send(routeId);
  });
}
// POST intentionally falls through the GET-only private child to its parent.
router.post(['/files', '/files/', '/files/*rest'], (_request, response) => {
  response.set('X-Route-ID', 'files').type('text/plain').send('files');
});
router.use((_request, response) => response.set('X-Route-ID', 'public').type('text/plain').send('public'));
app.use(router);
app.use((error, _request, response, _next) => {
  // Preserve the router's rejection status for malformed escaped captures.
  response.status(error.status || 500).type('text/plain').send('rejected');
});
app.listen(8080, '0.0.0.0', () => {
  console.log(`Express ${require('express/package.json').version}; ${profile}; Node ${process.version}`);
});
