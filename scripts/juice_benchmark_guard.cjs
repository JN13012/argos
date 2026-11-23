/* Evaluator-only preload for a trusted local Juice Shop instance.
 * NODE_OPTIONS=--require=/absolute/path/to/this/file
 * No answers, response bodies, query strings or credentials in the journal.
 */
'use strict';
const fs = require('node:fs');
const http = require('node:http');
const net = require('node:net');
const path = require('node:path');

const config = JSON.parse(fs.readFileSync(process.env.ARGOS_BENCHMARK_CONFIG, 'utf8'));
const exclusions = config.scope.excluded_paths.map(p => p.toLowerCase().replace(/\/$/, ''));
if (!exclusions.length) throw new Error('Benchmark exclusions required');
const log = fs.openSync(process.env.ARGOS_BENCHMARK_ACCESS_LOG, 'wx', 0o600);

function classify(raw) {
  // Parse paths without WHATWG's normalization erasing encoded dot segments.
  if (!raw.startsWith('/') || raw.startsWith('//')) throw new Error('Origin form required');
  let value = raw.split(/[?#]/, 1)[0];
  for (let n = 0; n < 3; n++) value = decodeURIComponent(value);
  if (/[\x00-\x1f\x7f%]/.test(value)) throw new Error('Ambiguous encoding');
  value = path.posix.normalize(value.replace(/\\/g, '/').split('/').map(p => p.split(';')[0]).join('/')).toLowerCase();
  return {path: value, forbidden: exclusions.some(p => value === p || value.startsWith(p + '/'))};
}

const listen = net.Server.prototype.listen;
net.Server.prototype.listen = function (...args) {
  if (typeof args[0] === 'number' || (typeof args[0] === 'string' && /^\d+$/.test(args[0]))) {
    const callback = args.find(a => typeof a === 'function');
    return listen.call(this, {port: Number(args[0]), host: '127.0.0.1'}, callback);
  }
  if (args[0] && typeof args[0] === 'object' && 'port' in args[0]) {
    args[0] = {...args[0], host: '127.0.0.1'};
    return listen.apply(this, args);
  }
  throw new Error('Benchmark requires an explicit numeric loopback TCP port');
};

const emit = http.Server.prototype.emit;
http.Server.prototype.emit = function (event, ...args) {
  if (event !== 'request' && event !== 'upgrade') return emit.call(this, event, ...args);
  const [req, reply] = args;
  let decision;
  try { decision = classify(req.url); }
  catch { decision = {path: '[invalid]', forbidden: true}; }
  const blocked = decision.forbidden || event === 'upgrade';
  // Log synchronously before forwarding; journal failure prevents dispatch.
  fs.writeSync(log, JSON.stringify({at: new Date().toISOString(), method:req.method,
    path:decision.path, action:blocked ? 'blocked' : 'forwarded',
    forbidden:decision.forbidden, transport:event}) + '\n');
  if (blocked) {
    if (event === 'upgrade') reply.end('HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n');
    else { reply.writeHead(404, {'Content-Type':'text/plain', 'Cache-Control':'no-store'}); reply.end('Not found'); }
    return true;
  }
  return emit.call(this, event, ...args);
};
