const child = require('child_process');
const fs = require('fs');
const http = require('http');
const http2 = require('http2');
const path = require('path');
const url = require('url');
const log = require('@vladmandic/pilogger');
const config = require('../config.json');
const db = require('./db');
const { parseCookies, verifyToken, signToken, setAuthCookie, clearAuthCookie } = require('./auth');

// app configuration
// you can provide your server key and certificate or use provided self-signed ones
// self-signed certificate generated using:
// openssl req -x509 -newkey rsa:4096 -nodes -keyout https.key -out https.crt -days 365 -subj "/C=US/ST=Florida/L=Miami/O=@vladmandic"
// client app does not work without secure server since browsers enforce https for webcam access
const options = {
  key: fs.readFileSync('server/https.key'),
  cert: fs.readFileSync('server/https.crt'),
  defaultFolder: 'client',
  defaultFile: 'index.html',
  httpPort: config.server.httpPort,
  httpsPort: config.server.httpsPort,
};

// just some predefined mime types
const mime = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpg',
  '.gif': 'image/gif',
  '.ico': 'image/x-icon',
  '.svg': 'image/svg+xml',
  '.wav': 'audio/wav',
  '.mp4': 'video/mp4',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.ttf': 'font/ttf',
  '.wasm': 'application/wasm',
  '.m3u8': 'application/x-mpegURL',
  '.ts': 'video/MP2T',
  '.mpd': 'application/dash+xml',
};

function handle(uri) {
  const url = uri.split(/[?#]/)[0];
  const result = { ok: false, stat: {}, file: '' };
  const checkFile = (f) => {
    result.file = f;
    if (fs.existsSync(f)) {
      result.stat = fs.statSync(f);
      if (result.stat.isFile()) {
        result.ok = true;
        return true;
      }
    }
    return false;
  };
  const checkFolder = (f) => {
    result.file = f;
    if (fs.existsSync(f)) {
      result.stat = fs.statSync(f);
      if (result.stat.isDirectory()) {
        result.ok = true;
        return true;
      }
    }
    return false;
  };
  return new Promise((resolve) => {
    if (checkFile(path.join(process.cwd(), url))) resolve(result);
    else if (checkFile(path.join(process.cwd(), url, options.defaultFile))) resolve(result);
    else if (checkFile(path.join(process.cwd(), options.defaultFolder, url))) resolve(result);
    else if (checkFile(path.join(process.cwd(), options.defaultFolder, url, options.defaultFile))) resolve(result);
    else if (checkFolder(path.join(process.cwd(), url))) resolve(result);
    else if (checkFolder(path.join(process.cwd(), options.defaultFolder, url))) resolve(result);
    else resolve(result);
  });
}

// process http requests
async function httpRequest(req, res) {
  const parsed = url.parse(req.url, true);
  const pathname = parsed.pathname || '/';
  const cookies = parseCookies(req);
  const token = cookies.auth;
  const user = token ? verifyToken(token) : null;

  // API: login
  if (req.method === 'POST' && pathname === '/api/login') return handleLogin(req, res);
  if (req.method === 'POST' && pathname === '/api/logout') {
    clearAuthCookie(res);
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify({ ok: true }));
    return undefined;
  }
  // Dynamic config.json from DB
  if (req.method === 'GET' && pathname === '/config.json') return handleDynamicConfig(req, res);
  // Proxy to stream server, protected
  if (pathname.startsWith('/stream/')) return proxyToStream(req, res, user);

  // Block access to app pages if not authenticated, allow login page and assets
  const isHTML = pathname === '/' || pathname.endsWith('.html') || pathname === '';
  const isLoginPage = pathname === '/login.html';
  if (!user && isHTML && !isLoginPage) {
    // serve login.html
    const loginFile = path.join(process.cwd(), options.defaultFolder, 'login.html');
    if (fs.existsSync(loginFile)) {
      const data = fs.readFileSync(loginFile);
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache' });
      res.end(data);
      return undefined;
    }
  }

  handle(decodeURI(req.url)).then((result) => {
    // get original ip of requestor, regardless if it's behind proxy or not
    const forwarded = (req.headers['forwarded'] || '').match(/for="\[(.*)\]:/);
    const ip = (Array.isArray(forwarded) ? forwarded[1] : null) || req.headers['x-forwarded-for'] || req.ip || req.socket.remoteAddress;
    if (!result || !result.ok || !result.stat) {
      res.writeHead(404, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end('Error 404: Not Found\n', 'utf-8');
      log.warn(`${req.method}/${req.httpVersion}`, res.statusCode, decodeURI(req.url), ip);
    } else {
      if (result?.stat?.isFile()) {
        const ext = String(path.extname(result.file)).toLowerCase();
        const contentType = mime[ext] || 'application/octet-stream';
        res.writeHead(200, {
          'Content-Language': 'en', 'Content-Type': contentType, 'Cache-Control': 'no-cache', 'X-Content-Type-Options': 'nosniff', 'Access-Control-Allow-Origin': '*',
        });
        if (!req.headers.range) {
          const stream = fs.createReadStream(result.file);
          stream.pipe(res); // don't compress data
          log.data(`${req.method}/${req.httpVersion}`, 'full', res.statusCode, contentType, result.stat.size, req.url, ip);
        } else {
          const range = req.headers.range.split('=')[1].split('-');
          const start = parseInt(range[0] || 0);
          const end = parseInt(range[1] || 0);
          if (end - start > 0) {
            const buffer = Buffer.alloc(end - start);
            const fd = fs.openSync(result.file, 'r');
            fs.readSync(fd, buffer, 0, end - start, start);
            fs.closeSync(fd);
            res.write(buffer);
            log.data(`${req.method}/${req.httpVersion}`, 'range', res.statusCode, contentType, start, end, end - start, req.url, ip);
          } else {
            const stream = fs.createReadStream(result.file);
            stream.pipe(res);
            log.data(`${req.method}/${req.httpVersion}`, 'full', res.statusCode, contentType, 0, 0, result.stat.size, req.url, ip);
          }
        }
      }
      if (result?.stat?.isDirectory()) {
        res.writeHead(200, {
          'Content-Language': 'en',
          'Content-Type': 'application/json; charset=utf-8',
          'Cache-Control': 'no-cache',
          'X-Content-Type-Options': 'nosniff',
          // 'Content-Security-Policy': "media-src 'self' http: https: data:",
          // 'Access-Control-Allow-Origin': '*',
        });
        let dir = fs.readdirSync(result.file);
        dir = dir.map((f) => path.join(decodeURI(req.url), f));
        res.end(JSON.stringify(dir), 'utf-8');
        log.data(`${req.method}/${req.httpVersion}`, res.statusCode, 'directory/json', result.stat.size, req.url, ip);
      }
    }
  });
}

async function startStreamServer() {
  const streamServer = child.spawn('stream/stream');
  streamServer.stdout.on('data', (data) => log.data('stream:', data?.toString().replace(/[\r\n]+/gm, '')));
  streamServer.stderr.on('data', (data) => log.data('stream:', data?.toString().replace(/[\r\n]+/gm, '')));
  streamServer.on('close', (data) => log.data('stream closed:', data?.toString()));
}

// --- helpers & api ---
async function handleLogin(req, res) {
  let body = '';
  req.on('data', (chunk) => { body += chunk; });
  req.on('end', async () => {
    try {
      const params = new url.URLSearchParams(body);
      const username = params.get('username') || '';
      const password = params.get('password') || '';
      const record = await db.getUserByUsername(username);
      if (!record) return sendJSON(res, 401, { ok: false, error: 'invalid credentials' });
      const ok = await require('./auth').checkPassword(password, record.password_hash);
      if (!ok) return sendJSON(res, 401, { ok: false, error: 'invalid credentials' });
      const token = signToken({ uid: record.id, username: record.username });
      setAuthCookie(res, token, !!options.httpsPort);
      return sendJSON(res, 200, { ok: true });
    } catch (e) {
      return sendJSON(res, 500, { ok: false, error: e?.message || 'error' });
    }
  });
}

async function handleDynamicConfig(req, res) {
  try {
    const serverCfg = await db.getServerConfig();
    const streams = await db.getStreamsMap();
    const json = {
      streamServer: '',
      server: {
        httpPort: serverCfg?.http_port || options.httpPort,
        httpsPort: serverCfg?.https_port || options.httpsPort,
        encoderPort: serverCfg?.encoder_port || config.server.encoderPort,
        encoderBase: '', // same-origin proxy
        iceServers: serverCfg?.ice_servers || config.server.iceServers,
        webrtcMinPort: serverCfg?.webrtc_min_port || config.server.webrtcMinPort,
        webrtcMaxPort: serverCfg?.webrtc_max_port || config.server.webrtcMaxPort,
        retryConnectSec: serverCfg?.retry_connect_sec || config.server.retryConnectSec,
        startStreamServer: !!serverCfg?.start_stream_server,
      },
      streams,
      client: config.client || { debug: true },
    };
    sendJSON(res, 200, json);
  } catch (e) {
    sendJSON(res, 500, { ok: false, error: e?.message || 'error' });
  }
}

function sendJSON(res, status, obj) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-cache' });
  res.end(JSON.stringify(obj));
}

async function proxyToStream(req, res, user) {
  if (!user) {
    sendJSON(res, 401, { ok: false, error: 'unauthorized' });
    return;
  }
  let targetPort = 8002;
  try {
    const serverCfg = await db.getServerConfig();
    const enc = serverCfg?.encoder_port || config.server.encoderPort || ':8002';
    targetPort = parseInt(String(enc).replace(':', ''), 10);
  } catch { /* ignore and use default */ }
  const opts = url.parse(`http://127.0.0.1:${targetPort}${req.url}`);
  opts.method = req.method;
  opts.headers = { ...req.headers };
  // remove hop-by-hop headers
  delete opts.headers.host; delete opts.headers.connection; delete opts.headers['content-length'];
  const proxied = http.request(opts, (pres) => {
    res.writeHead(pres.statusCode || 502, pres.headers);
    pres.pipe(res);
  });
  proxied.on('error', (err) => {
    sendJSON(res, 502, { ok: false, error: err?.message || 'proxy error' });
  });
  req.pipe(proxied);
}

// app main entry point
async function main() {
  log.header();
  process.chdir(path.join(__dirname, '..'));
  try {
    await db.init();
    log.state('db initialized');
  } catch (e) {
    log.error('db init failed:', e?.message || e);
  }
  if (options.httpPort && options.httpPort > 0) {
    // @ts-ignore // ignore invalid options
    const server1 = http.createServer(options, httpRequest);
    server1.on('listening', () => log.state('http server listening:', options.httpPort));
    server1.on('error', (err) => log.error('http server:', err.message || err));
    server1.listen(options.httpPort);
  }
  if (options.httpsPort && options.httpsPort > 0) {
    // @ts-ignore // ignore invalid options
    const server2 = http2.createSecureServer(options, httpRequest);
    server2.on('listening', () => log.state('http2 server listening:', options.httpsPort));
    server2.on('error', (err) => log.error('http2 server:', err.message || err));
    server2.listen(options.httpsPort);
  }
  if (config.server.startStreamServer) startStreamServer();
}

main();
