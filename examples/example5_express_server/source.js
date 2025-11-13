/**
 * SOURCE: Express.js request data sources
 */

// Source 1: Request body (JSON)
function getBodyConfig(req) {
    if (req.body && typeof req.body === 'object') {
        return req.body;  // SOURCE: Already parsed JSON from body-parser
    }
    return null;
}

// Source 2: Query parameters (JSON.parse)
function getQueryConfig(req) {
    var configParam = req.query.config;
    if (configParam) {
        return JSON.parse(decodeURIComponent(configParam));  // SOURCE: JSON.parse
    }
    return null;
}

// Source 3: Headers (JSON.parse)
function getHeaderConfig(req) {
    var configHeader = req.headers['x-config'];
    if (configHeader) {
        return JSON.parse(configHeader);  // SOURCE: JSON.parse
    }
    return null;
}

// Source 4: Cookies (JSON.parse)
function getCookieConfig(req) {
    var configCookie = req.cookies && req.cookies.config;
    if (configCookie) {
        return JSON.parse(decodeURIComponent(configCookie));  // SOURCE: JSON.parse
    }
    return null;
}

module.exports = {
    getBodyConfig,
    getQueryConfig,
    getHeaderConfig,
    getCookieConfig
};

