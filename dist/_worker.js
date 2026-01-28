// Cloudflare Pages proxy worker for beaconwarden.pages.dev
//
// Purpose:
// - Provide a stable Pages origin (beaconwarden.pages.dev)
// - Proxy API routes to the backend Worker via a service binding named `BACKEND`
// - Optionally serve static assets for non-API routes
//
// This file is intentionally dependency-free.

function isApiPath(pathname) {
  return (
    pathname === '/api' ||
    pathname.startsWith('/api/') ||
    pathname === '/v1' ||
    pathname.startsWith('/v1/') ||
    pathname === '/identity' ||
    pathname.startsWith('/identity/') ||
    pathname === '/icons' ||
    pathname.startsWith('/icons/') ||
    pathname === '/attachments' ||
    pathname.startsWith('/attachments/') ||
    pathname === '/sends' ||
    pathname.startsWith('/sends/') ||
    pathname === '/admin' ||
    pathname.startsWith('/admin/') ||
    pathname === '/.well-known' ||
    pathname.startsWith('/.well-known/')
  );
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    const backend = env?.BACKEND;
    if (!backend || typeof backend.fetch !== 'function') {
      return new Response('Missing BACKEND service binding', { status: 500 });
    }

    // Proxy API routes to the backend Worker.
    if (isApiPath(path)) {
      return backend.fetch(request);
    }

    // Prefer serving static assets if available.
    const assets = env?.ASSETS;
    if (assets && typeof assets.fetch === 'function') {
      const assetResp = await assets.fetch(request);
      // If the asset exists, return it; otherwise fall back to backend.
      if (assetResp && assetResp.status !== 404) {
        return assetResp;
      }
    }

    // Fallback: proxy everything else (useful during early migration).
    return backend.fetch(request);
  }
};
