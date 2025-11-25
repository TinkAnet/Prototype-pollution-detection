const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');

const DB_PATH = path.join(__dirname, 'db.json');
const PUBLIC_DIR = __dirname;

function deepMerge(target, source) {
  if (typeof source !== 'object' || source === null) return target;
  for (const key of Object.keys(source)) {
    const srcVal = source[key];
    if (srcVal === null) {
      delete target[key];
    } else if (typeof srcVal === 'object' && !Array.isArray(srcVal)) {
      target[key] = deepMerge(target[key] || {}, srcVal);
    } else {
      target[key] = srcVal;
    }
  }
  return target;
}

const server = http.createServer((req, res) => {
  const parsed = url.parse(req.url, true);

  // API endpoints
  if (req.method === 'GET' && parsed.pathname === '/api/db') {
    fs.readFile(DB_PATH, 'utf8', (err, data) => {
      if (err) {
        res.statusCode = 500;
        return res.end(JSON.stringify({ error: 'Failed to read db' }));
      }
      res.setHeader('Content-Type', 'application/json');
      res.end(data);
    });
    return;
  }

  if (req.method === 'PATCH' && parsed.pathname === '/api/db') {
    let body = '';
    req.on('data', chunk => (body += chunk));
    req.on('end', () => {
      try {
        const patch = JSON.parse(body || '{}');
        fs.readFile(DB_PATH, 'utf8', (err, data) => {
          if (err) {
            res.statusCode = 500;
            return res.end(JSON.stringify({ error: 'Failed to read db' }));
          }
          let json = {};
          try { json = JSON.parse(data); } catch {}
          deepMerge(json, patch);
          fs.writeFile(DB_PATH, JSON.stringify(json, null, 2), 'utf8', err2 => {
            if (err2) {
              res.statusCode = 500;
              return res.end(JSON.stringify({ error: 'Failed to write db' }));
            }
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({ status: 'ok' }));
          });
        });
      } catch (e) {
        res.statusCode = 400;
        res.end(JSON.stringify({ error: 'Invalid JSON' }));
      }
    });
    return;
  }

  // Static files
  if (req.method === 'GET') {
    let filePath = path.join(PUBLIC_DIR, parsed.pathname === '/' ? 'index.html' : parsed.pathname);
    fs.readFile(filePath, (err, data) => {
      if (err) {
        res.statusCode = 404;
        return res.end('Not found');
      }
      const ext = path.extname(filePath).toLowerCase();
      const map = {
        '.html': 'text/html',
        '.js': 'application/javascript',
        '.css': 'text/css',
        '.json': 'application/json'
      };
      res.setHeader('Content-Type', map[ext] || 'text/plain');
      res.end(data);
    });
    return;
  }

  res.statusCode = 404;
  res.end('Not found');
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});

