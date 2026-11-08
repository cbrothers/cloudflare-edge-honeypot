# cloudflare-edge-honeypot

Shared Cloudflare Workers and Cloudflare Pages edge honeypot, scanner trap, 24-hour KV IP ban (`env.SECURITY_BANS`), owner override (`STUDIO_OVERRIDE_KEY`), `/__health` endpoint, and staging `noindex` middleware.

## Installation

Add to `package.json`:

```json
{
  "dependencies": {
    "cloudflare-edge-honeypot": "github:cbrothers/cloudflare-edge-honeypot#main"
  }
}
```

## Usage (Cloudflare Pages `functions/_middleware.js`)

```javascript
import { createEdgeHoneypotMiddleware } from 'cloudflare-edge-honeypot';

export const { onRequest } = createEdgeHoneypotMiddleware({
    apexHostname: 'brothersblues.com',
    wwwHostname: 'www.brothersblues.com',
    overrideCookieName: '__bb_studio_override',
    tokenPrefix: 'bb_ovr'
});
```

## Testing

```powershell
npm test
```
