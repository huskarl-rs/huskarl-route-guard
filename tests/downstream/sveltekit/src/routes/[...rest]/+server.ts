// Stable route IDs; the harness owns their policy mapping.
export const GET = () => new Response('public', { headers: { 'X-Route-ID': 'public' } });
