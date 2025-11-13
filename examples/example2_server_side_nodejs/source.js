/**
 * SOURCE: Server-side data sources
 * Node.js example with JSON.parse from HTTP requests
 */

const http = require('http');
const url = require('url');

// Source 1: JSON.parse from request body
function parseRequestBody(body) {
    try {
        return JSON.parse(body);  // SOURCE: JSON.parse from user input
    } catch (e) {
        return null;
    }
}

// Source 2: JSON.parse from query parameters
function parseQueryParams(queryString) {
    const params = new URLSearchParams(queryString);
    const configParam = params.get('config');
    if (configParam) {
        return JSON.parse(decodeURIComponent(configParam));  // SOURCE: JSON.parse
    }
    return null;
}

// Source 3: JSON.parse from headers
function parseHeaderConfig(headers) {
    const configHeader = headers['x-config'];
    if (configHeader) {
        return JSON.parse(configHeader);  // SOURCE: JSON.parse
    }
    return null;
}

module.exports = {
    parseRequestBody,
    parseQueryParams,
    parseHeaderConfig
};

