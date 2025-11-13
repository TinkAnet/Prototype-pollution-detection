/**
 * MAIN: Server that connects source to sink
 * Demonstrates server-side prototype pollution
 */

const http = require('http');
const url = require('url');
const { parseRequestBody, parseQueryParams, parseHeaderConfig } = require('./source');
const { deepMerge, extend, mergeConfig } = require('./sink');

const server = http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url, true);
    
    // Default configuration
    let config = {
        debug: false,
        logLevel: 'info'
    };
    
    // SOURCE: Parse data from different sources
    let userConfig = null;
    
    // Source 1: From query parameters
    userConfig = parseQueryParams(req.url);  // SOURCE
    
    // Source 2: From request body
    let body = '';
    req.on('data', chunk => {
        body += chunk.toString();
    });
    
    req.on('end', () => {
        if (body) {
            userConfig = parseRequestBody(body);  // SOURCE
        }
        
        // Source 3: From headers
        const headerConfig = parseHeaderConfig(req.headers);  // SOURCE
        
        // SINK: Merge user config into default config
        if (userConfig) {
            deepMerge(config, userConfig);  // SINK: Receives data from source
        }
        
        if (headerConfig) {
            extend(config, headerConfig);  // SINK: Receives data from source
        }
        
        // Another sink
        const additionalConfig = { timeout: 5000 };
        mergeConfig(config, additionalConfig);  // SINK
        
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(config));
    });
});

const PORT = 3000;
server.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log('Test with: curl -X POST http://localhost:3000 -H "Content-Type: application/json" -d \'{"__proto__":{"polluted":"yes"}}\'');
});

