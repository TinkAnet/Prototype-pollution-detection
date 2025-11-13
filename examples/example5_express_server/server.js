/**
 * MAIN: Express server connecting sources to sinks
 */

const express = require('express');
const bodyParser = require('body-parser');
const { getBodyConfig, getQueryConfig, getHeaderConfig, getCookieConfig } = require('./source');
const { deepMerge, extend, mergeConfig } = require('./sink');

const app = express();

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Default configuration
const defaultConfig = {
    debug: false,
    logLevel: 'info',
    timeout: 3000
};

// Route that demonstrates source-to-sink flow
app.post('/api/config', (req, res) => {
    var config = Object.assign({}, defaultConfig);
    
    // SOURCE: Get config from request body
    var bodyConfig = getBodyConfig(req);  // SOURCE
    
    // SOURCE: Get config from query parameters
    var queryConfig = getQueryConfig(req);  // SOURCE
    
    // SOURCE: Get config from headers
    var headerConfig = getHeaderConfig(req);  // SOURCE
    
    // SOURCE: Get config from cookies
    var cookieConfig = getCookieConfig(req);  // SOURCE
    
    // SINK: Merge all configs (receives data from sources)
    if (bodyConfig) {
        deepMerge(config, bodyConfig);  // SINK: Receives from source
    }
    
    if (queryConfig) {
        extend(config, queryConfig);  // SINK: Receives from source
    }
    
    if (headerConfig) {
        mergeConfig(config, headerConfig);  // SINK: Receives from source
    }
    
    if (cookieConfig) {
        deepMerge(config, cookieConfig);  // SINK: Receives from source
    }
    
    res.json(config);
});

// Another route
app.get('/api/merge', (req, res) => {
    var baseConfig = { api: 'v1' };
    
    // SOURCE: Query params
    var userConfig = getQueryConfig(req);  // SOURCE
    
    if (userConfig) {
        // SINK: Merge user config
        extend(baseConfig, userConfig);  // SINK: Receives from source
    }
    
    res.json(baseConfig);
});

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Express server running on http://localhost:${PORT}`);
    console.log('Test with:');
    console.log('  curl -X POST http://localhost:3000/api/config -H "Content-Type: application/json" -d \'{"__proto__":{"polluted":"yes"}}\'');
    console.log('  curl "http://localhost:3000/api/merge?config=%7B%22__proto__%22%3A%7B%22polluted%22%3A%22yes%22%7D%7D"');
});

