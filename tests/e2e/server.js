// Servidor estático mínimo para los tests en navegador. Solo escucha en 127.0.0.1 y nunca sale de `root`.
// Con `tls` ({ key, cert }) sirve por HTTPS (tests/e2e/tls.js genera un certificado efímero): WebKit aplica
// `upgrade-insecure-requests` también a 127.0.0.1, así que por HTTP no carga ni un script de la página.
import { createServer as createHttpServer } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const TYPES = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png',
  '.ico': 'image/x-icon', '.webmanifest': 'application/manifest+json', '.eml': 'message/rfc822', '.txt': 'text/plain; charset=utf-8',
};

/** @returns {Promise<{url: string, close: () => Promise<void>}>} */
export function serve(root = fileURLToPath(new URL('../../', import.meta.url)), { tls = null } = {}) {
  const base = normalize(root.endsWith(sep) ? root : root + sep);
  const handler = async (req, res) => {
    const path = decodeURIComponent(new URL(req.url, 'http://x').pathname);
    const file = normalize(join(base, path.endsWith('/') ? `${path}index.html` : path));
    if (!file.startsWith(base)) return res.writeHead(403).end();
    try {
      const body = await readFile(file);
      res.writeHead(200, { 'content-type': TYPES[extname(file)] ?? 'application/octet-stream', 'cache-control': 'no-store' }).end(body);
    } catch {
      res.writeHead(404).end();
    }
  };
  const server = tls ? createHttpsServer(tls, handler) : createHttpServer(handler);
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({
    url: `${tls ? 'https' : 'http'}://127.0.0.1:${server.address().port}`,
    close: () => new Promise((done) => server.close(() => done())),
  })));
}
